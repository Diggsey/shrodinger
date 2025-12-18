# Shrodinger - Encrypted Filesystem Driver

## Project Overview

Shrodinger is an encrypted filesystem driver for Windows that creates virtual encrypted drives using the WinFSP (Windows File System Proxy) framework. The name is a reference to Schrödinger's cat - the encrypted data exists in a superposed state where it's both there and hidden until you provide the correct decryption key.

**Core Capabilities:**
- Creates encrypted virtual filesystems that mount as Windows drives
- Uses AES-256-GCM authenticated encryption with Argon2 password hashing
- Supports dual-password schemes for hidden partitions (steganographic storage)
- Provides complete VFS implementation with standard file/directory operations
- Native Windows integration via WinFSP framework

## Architecture

### Three-Layer Design

```
┌─────────────────────────────────────┐
│   WinFSP Integration Layer          │  fs/encryptedfs.rs, fs/context.rs
│   (Windows Kernel Bridge)           │  fs/file.rs
├─────────────────────────────────────┤
│   Virtual Filesystem Layer          │  vfs.rs
│   (Files, Directories, Metadata)    │
├─────────────────────────────────────┤
│   Block Device Layer                │  block.rs
│   (AES-256-GCM Encryption)          │
└─────────────────────────────────────┘
```

**Layer 1: Block Device** (`block.rs`)
- Manages 4KB encrypted blocks with AES-256-GCM
- Block format: 12-byte nonce + encrypted data + 16-byte authentication tag
- Usable space per block: 4068 bytes (4096 - 28 bytes overhead)
- Argon2 password hashing for key derivation
- Dual-sided allocation for steganographic dual-password support

**Layer 2: Virtual Filesystem** (`vfs.rs`)
- Implements filesystem semantics (files, directories, metadata)
- BSON-serialized metadata stored at block 0
- Tracks file/directory items with flags, sizes, and block allocations
- Free space management using range sets
- Dynamic metadata resizing with block relocation

**Layer 3: WinFSP Integration** (`fs/` module)
- Bridges VFS to Windows kernel via WinFSP API
- Implements `FileSystemContext` trait for filesystem operations
- Handles file handles and directory enumeration
- Provides POSIX-like operations over Windows API

## Key Files

### Core Implementation

| File | Responsibility |
|------|----------------|
| `src/main.rs` | Entry point; CLI argument parsing (debug flags, volume prefix, backing file, mountpoint) |
| `src/service.rs` | Service lifecycle management; default mountpoint (`~\Secrets`) and backing file setup |
| `src/block.rs` | `EncryptedBlockDevice` - low-level block encryption/decryption with AES-256-GCM |
| `src/vfs.rs` | `Vfs` - virtual filesystem with metadata management and file I/O operations |

### WinFSP Integration

| File | Responsibility |
|------|----------------|
| `src/fs/encryptedfs.rs` | `EncryptedFilesystem` - high-level wrapper for creating and mounting the filesystem |
| `src/fs/context.rs` | `EncryptedContext` - implements WinFSP's `FileSystemContext` trait for all filesystem operations |
| `src/fs/file.rs` | `EncryptedFile` - represents open files/directories with directory buffer support |

### Build Configuration

| File | Responsibility |
|------|----------------|
| `build.rs` | Links WinFSP libraries with delay-load capability for Windows |
| `Cargo.toml` | Package manifest with dependencies and build settings |

## Technology Stack

**Language:** Rust (Edition 2024)

**Key Dependencies:**
- `winfsp = "0.12"` - Windows File System Proxy framework
- `aes-gcm = "0.10"` - AES-256-GCM authenticated encryption
- `argon2 = "0.5"` - Memory-hard password hashing
- `bson = "3"` - Binary serialization for metadata
- `windows = "0.62"` - Windows API bindings
- `clap = "4.5.4"` - CLI argument parsing
- `anyhow = "1.0"` - Error handling
- `serde = "1.0"` - Serialization framework

## Building and Running

### Prerequisites
- Windows operating system
- Rust toolchain (edition 2024)
- WinFSP installed on the system

### Build
```bash
cargo build --release
```

### Run
```bash
# Default usage (mounts at ~\Secrets with backing file ~\Secrets.shrodinger)
cargo run --release

# Custom mountpoint and backing file
cargo run --release -- --mountpoint "Z:" --backing-file "encrypted.dat"

# With debug logging
cargo run --release -- --debug
```

## Implementation Details

### Block Device Format

**File Prefix:** `SHRODINGER_V1` (12 bytes)

**Block Structure (4096 bytes):**
```
┌──────────────┬────────────────────────┬──────────────────┐
│ Nonce        │ Encrypted Data         │ Auth Tag         │
│ (12 bytes)   │ (4068 bytes)           │ (16 bytes)       │
└──────────────┴────────────────────────┴──────────────────┘
```

**Key Derivation:**
- Algorithm: Argon2
- Password → 256-bit encryption key
- Per-block random nonces for encryption

### Filesystem Metadata

**Storage:** Block 0 (BSON-serialized)

**Structure:**
```rust
pub struct Vfs {
    items: Vec<VfsItem>,           // File/directory entries
    next_file_index: u64,          // Next unique file ID
    free_ranges: Vec<Range<u64>>,  // Available block ranges
}

pub struct VfsItem {
    file_index: u64,               // Unique identifier
    flags: VfsItemFlags,           // File vs Directory
    name: String,                  // Filename
    size: u64,                     // Size in bytes
    blocks: Vec<u64>,              // Allocated block numbers
    parent_index: Option<u64>,     // Parent directory
}
```

### Dual-Password Scheme

The block device supports dual-sided allocation:
- **Side A:** Standard allocation from the beginning
- **Side B:** Hidden allocation from the end
- Different passwords reveal different filesystem views
- Enables steganographic hidden partitions

## Security Considerations

### Encryption
- **Cipher:** AES-256-GCM (authenticated encryption)
- **Key Derivation:** Argon2 (memory-hard, GPU-resistant)
- **Nonces:** Random per-block, never reused
- **Authentication:** GCM authentication tag prevents tampering

### Threat Model
- Protects data at rest on disk
- Prevents unauthorized access without password
- Authentication prevents modification detection
- Dual-password scheme provides plausible deniability

### Limitations
- No protection while mounted (filesystem is accessible)
- Password must be kept secure (no key recovery)
- Metadata stored in cleartext at block 0 (structure visible but content encrypted)
- Relies on WinFSP security model

## Common Operations

### Creating a New Filesystem
First run automatically initializes a new encrypted filesystem and prompts for password.

### Mounting Existing Filesystem
Subsequent runs mount the existing backing file and prompt for password to unlock.

### File Operations
Standard Windows file operations work on the mounted drive:
- Create/delete files and directories
- Read/write file contents
- Rename/move files
- List directory contents

### Unmounting
Stop the service (Ctrl+C) to unmount and lock the filesystem.

## Development Notes

### Error Handling
- Uses `anyhow::Result` for general errors
- Uses `thiserror` for custom error types
- WinFSP errors mapped to appropriate Windows error codes

### Windows Integration
- Wide strings (UTF-16) used for Windows API compatibility
- File times in Windows FILETIME format (100ns intervals since 1601)
- Security descriptor support for file permissions
- Volume information (serial number, label, etc.)

### Debugging
- `--debug` flag enables detailed WinFSP logging
- `FileSystemHost::set_debug(true)` for verbose operation tracing
- Stdout logging for service lifecycle events

## Future Considerations

- Consider encrypting metadata at block 0
- Add support for file compression
- Implement file-level deduplication
- Add integrity checking/repair functionality
- Consider multi-threaded I/O optimization
- Add proper service installation for Windows services
