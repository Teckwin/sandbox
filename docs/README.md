# AI Sandbox - Cross-platform AI Tool Sandbox Security

A Rust crate providing cross-platform sandbox isolation for AI agent tools.

## Features

- **Multi-platform sandboxing**:
  - Linux: Bubblewrap + Seccomp + Landlock
  - macOS: Seatbelt (sandbox-exec)
  - Windows: Restricted Token
  - FreeBSD: Capsicum
  - OpenBSD: pledge
  
- **Process hardening**: Pre-main() security hardening
- **Execution policy engine**: Rule-based command execution control
- **Network policy**: Fine-grained network access control
- **Filesystem policy**: Read-only, workspace-only, or full access

## Platform Support

| Platform | Sandbox Type | Status |
|----------|--------------|--------|
| Linux | Bubblewrap/Seccomp/Landlock | ✅ |
| macOS | Seatbelt (sandbox-exec) | ✅ |
| Windows | Restricted Token | ✅ |
| FreeBSD | Capsicum | ✅ |
| OpenBSD | pledge | ✅ |

## Installation

```toml
# Cargo.toml
[dependencies]
ai-sandbox = "0.1.5"
```

## Quick Start

```rust
use ai_sandbox::{SandboxManager, SandboxPolicy, SandboxCommand};
use std::collections::HashMap;
use std::ffi::OsString;
use std::path::PathBuf;

// Create sandbox manager - automatically detects platform
let manager = SandboxManager::new();

// Define your command
let command = SandboxCommand {
    program: OsString::from("ls"),
    args: vec!["-la".to_string()],
    cwd: PathBuf::from("/tmp"),
    env: HashMap::new(),
};

// Define sandbox policy (default: DangerFullAccess - no sandbox)
let policy = SandboxPolicy::default();

// Create sandboxed execution request
let request = manager.create_exec_request(command, policy).unwrap();
```

## Testing

```bash
# Run all tests
cargo test

# Run with coverage
cargo test -- --nocov

# Build release version
cargo build --release

# Run demo example
cargo run --example demo
```

## Core API

### SandboxManager

The main entry point for creating sandboxed execution requests.

```rust
use ai_sandbox::{SandboxManager, SandboxPolicy, SandboxCommand};
use std::collections::HashMap;
use std::ffi::OsString;
use std::path::PathBuf;

let manager = SandboxManager::new();

let command = SandboxCommand {
    program: OsString::from("ls"),
    args: vec!["-la".to_string()],
    cwd: PathBuf::from("/tmp"),
    env: HashMap::new(),
};

// Use default policy (DangerFullAccess)
let request = manager.create_exec_request(command, SandboxPolicy::default()).unwrap();
```

### SandboxPolicy

Defines the sandboxing level and access controls.

```rust
use ai_sandbox::{SandboxPolicy, FileSystemSandboxPolicy, NetworkSandboxPolicy};
use std::path::PathBuf;

// Read-only sandbox - no file writes, no network
let policy = SandboxPolicy::ReadOnly {
    file_system: FileSystemSandboxPolicy::ReadOnly,
    network_access: NetworkSandboxPolicy::NoAccess,
};

// Workspace write - allow writes to specific directories
let policy = SandboxPolicy::WorkspaceWrite {
    writable_roots: vec![PathBuf::from("/tmp"), PathBuf::from("/home/user/workspace")],
    network_access: NetworkSandboxPolicy::Localhost,
};

// External sandbox - use platform's default sandbox
let policy = SandboxPolicy::ExternalSandbox {
    network_access: NetworkSandboxPolicy::FullAccess,
};

// Danger full access - no sandboxing (default)
let policy = SandboxPolicy::DangerFullAccess;
```

### Platform Detection

```rust
use ai_sandbox::{get_platform_sandbox, SandboxType};

// Get available sandbox type for current platform
let sandbox = get_platform_sandbox(false);  // false = don't enable Windows sandbox
match sandbox {
    Some(SandboxType::LinuxSeccomp) => println!("Using Linux Seccomp/Bubblewrap"),
    Some(SandboxType::MacosSeatbelt) => println!("Using macOS Seatbelt"),
    Some(SandboxType::WindowsRestrictedToken) => println!("Using Windows Restricted Token"),
    Some(SandboxType::FreeBSDCapsicum) => println!("Using FreeBSD Capsicum"),
    Some(SandboxType::OpenBSDPledge) => println!("Using OpenBSD pledge"),
    Some(SandboxType::None) | None => println!("No sandbox available"),
}
```

## Advanced Usage

### Execution Policy Engine

Control which commands can be executed based on prefix matching.

```rust
use ai_sandbox::{Policy, Decision, PrefixRule, RuleType};

let mut policy = Policy::new();

// Add prefix rules to deny dangerous commands
policy.add_prefix_rule(&["rm".to_string()], Decision::Deny, Some("Removing files is not allowed".to_string())).unwrap();
policy.add_prefix_rule(&["mkfs".to_string()], Decision::Deny, Some("Filesystem modification is not allowed".to_string())).unwrap();
policy.add_prefix_rule(&["dd".to_string()], Decision::Deny, Some("Raw disk access is not allowed".to_string())).unwrap();

// Check a command
let full_command = vec!["rm".to_string(), "-rf".to_string(), "/".to_string()];
if let Some(m) = policy.check(&full_command) {
    if m.decision == Decision::Deny {
        println!("Command denied: {:?}", m.justification);
    }
}
```

### Process Hardening

Apply security hardening at program startup.

```rust
use ai_sandbox::pre_main_hardening;

fn main() {
    // Apply process hardening before main logic
    pre_main_hardening();
    
    // Your application code here
}
```

### Platform-Specific APIs

#### Linux Landlock

```rust
use ai_sandbox::{is_landlock_available, get_landlock_version};

// Check Landlock support
if is_landlock_available() {
    let version = get_landlock_version().unwrap_or(0);
    println!("Landlock version: {}", version);
}
```

#### macOS Seatbelt

```rust
use ai_sandbox::sandboxing::seatbelt::{create_seatbelt_policy, proxy_loopback_ports_from_env};
use std::collections::HashMap;

// Create Seatbelt policy string
let policy = create_seatbelt_policy(&sandbox_policy);
println!("Seatbelt policy:\n{}", policy);

// Get proxy ports from environment
let mut env = HashMap::new();
env.insert("HTTP_PROXY".to_string(), "http://localhost:8080".to_string());
let ports = proxy_loopback_ports_from_env(&env);
```

## Platform-Specific Notes

### Linux

Requires bubblewrap (`bwrap`) installed on the system. On Ubuntu/Debian:

```bash
apt install bubblewrap
```

Landlock requires Linux kernel 5.13 or later.

### macOS

Uses the native `sandbox-exec` command (available in `/usr/bin/sandbox-exec`).

### Windows

Uses Windows Restricted Token API. Requires Windows 10 version 1709 or later.

### FreeBSD

Uses Capsicum framework for capability-mode sandboxing.

### OpenBSD

Uses the `pledge()` system call for system call filtering.

## License

MIT