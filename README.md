AI Sandbox - Cross-platform AI Tool Sandbox Security
=====================================================

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
ai-sandbox = "0.1.3"
```

## Testing

```bash
# Run the test script
./test.sh

# Or run manually:
# Check compilation
cargo check

# Run all tests
cargo test

# Run demo example
cargo run --example demo

# Build release version
cargo build --release
```

## Creating Your Own Sandbox Application

### Step 1: Add Dependency

```toml
# Cargo.toml
[dependencies]
ai-sandbox = "0.1.3"
```

### Step 2: Basic Usage Example

Create a file `examples/sandbox_app.rs`:

```rust
use ai_sandbox::{
    SandboxManager, 
    SandboxPolicy, 
    SandboxCommand,
    FileSystemSandboxPolicy,
    NetworkSandboxPolicy,
    get_platform_sandbox,
};
use std::ffi::OsString;
use std::collections::HashMap;
use std::path::PathBuf;
use std::process::{Command, Stdio};

fn main() {
    // Check platform support
    let sandbox_type = get_platform_sandbox(false);
    println!("Using sandbox type: {:?}", sandbox_type);
    
    // Create sandbox manager
    let manager = SandboxManager::new();
    
    // Define your policy
    let policy = SandboxPolicy::ReadOnly {
        file_system: FileSystemSandboxPolicy::ReadOnly,
        network_access: NetworkSandboxPolicy::NoAccess,
    };
    
    // Create command to sandbox
    let command = SandboxCommand {
        program: OsString::from("ls"),
        args: vec!["-la".to_string(), "/etc".to_string()],
        cwd: PathBuf::from("/tmp"),
        env: HashMap::new(),
    };
    
    // Transform command for sandbox execution
    match manager.create_exec_request(command, policy) {
        Ok(request) => {
            println!("Sandbox policy applied: {:?}", request.sandbox_policy);
            println!("Command: {:?}", request.command);
            
            // Execute the sandboxed command
            // In production, use request.command with proper execution
        }
        Err(e) => {
            eprintln!("Sandbox error: {}", e);
        }
    }
}
```

### Step 3: Run Your Example

```bash
cargo run --example sandbox_app
```

## Advanced Usage

### Custom Sandbox Policy

```rust
use ai_sandbox::{SandboxPolicy, NetworkSandboxPolicy};
use std::path::PathBuf;

// Only allow writing to specific directories
let policy = SandboxPolicy::WorkspaceWrite {
    writable_roots: vec![
        PathBuf::from("/tmp"),
        PathBuf::from("/home/user/workspace"),
    ],
    network_access: NetworkSandboxPolicy::Localhost,  // Only localhost
};
```

### Execution Policy (Command Allow/Deny)

```rust
use ai_sandbox::{Policy, Decision};

let mut exec_policy = Policy::new();

// Deny dangerous commands
exec_policy.add_prefix_rule(
    &["rm".to_string(), "-rf".to_string()],
    Decision::Deny,
    Some("Deleting files recursively is not allowed".to_string()),
).unwrap();

// Deny network downloads
exec_policy.add_prefix_rule(
    &["curl".to_string()],
    Decision::Deny,
    Some("Network downloads are restricted".to_string()),
).unwrap();

exec_policy.add_prefix_rule(
    &["wget".to_string()],
    Decision::Deny,
    Some("Network downloads are restricted".to_string()),
).unwrap();

// Allow read-only commands
exec_policy.add_prefix_rule(
    &["ls".to_string()],
    Decision::Allow,
    None,
).unwrap();

exec_policy.add_prefix_rule(
    &["cat".to_string()],
    Decision::Allow,
    None,
).unwrap();

// Check a command
let result = exec_policy.check(&["rm".to_string(), "-rf".to_string(), "/".to_string()]);
match result {
    Some(m) => {
        if m.decision == Decision::Deny {
            println!("Command denied: {}", m.justification.as_deref().unwrap_or("No reason"));
        }
    }
    None => println!("Command allowed (no matching rule)"),
}
```

### Process Hardening

```rust
use ai_sandbox::process_hardening::pre_main_hardening;

// Call at program startup (before main)
fn init() {
    pre_main_hardening();
}

// Or use constructor crate for automatic calling
// Add to Cargo.toml: ctor = "0.2"
#[cfg_attr(not(test), ctor::ctor)]
fn init() {
    pre_main_hardening();
}
```

### Platform-Specific Features

#### Linux with Bubblewrap

```rust
use ai_sandbox::linux_sandbox::{find_system_bwrap_in_path, system_bwrap_warning};

// Check if bubblewrap is available
if let Some(warning) = system_bwrap_warning() {
    eprintln!("Warning: {}", warning);
}

// Get bwrap path
let bwrap_path = find_system_bwrap_in_path();
```

#### Linux with Landlock

```rust
use ai_sandbox::linux_sandbox::landlock::{is_landlock_available, get_landlock_version};

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

## Complete AI Agent Example

```rust
use ai_sandbox::{
    SandboxManager, SandboxPolicy, SandboxCommand, SandboxType,
    FileSystemSandboxPolicy, NetworkSandboxPolicy, Policy, Decision,
};
use std::collections::HashMap;
use std::ffi::OsString;
use std::path::PathBuf;
use std::process::Command;

struct AgentSandbox {
    manager: SandboxManager,
    exec_policy: Policy,
}

impl AgentSandbox {
    fn new() -> Self {
        let mut exec_policy = Policy::new();
        
        // Configure execution policy
        exec_policy.add_prefix_rule(&["rm".to_string()], Decision::Deny, None).unwrap();
        exec_policy.add_prefix_rule(&["mkfs".to_string()], Decision::Deny, None).unwrap();
        exec_policy.add_prefix_rule(&["dd".to_string()], Decision::Deny, None).unwrap();
        
        Self {
            manager: SandboxManager::new(),
            exec_policy,
        }
    }
    
    fn execute(&self, program: &str, args: Vec<String>, cwd: PathBuf) -> Result<(), String> {
        let command = SandboxCommand {
            program: OsString::from(program),
            args,
            cwd: cwd.clone(),
            env: HashMap::new(),
        };
        
        // Check execution policy first
        let mut full_command = vec![program.to_string()];
        full_command.extend(command.args.clone());
        
        if let Some(m) = self.exec_policy.check(&full_command) {
            if m.decision == Decision::Deny {
                return Err(format!("Command denied: {:?}", m.justification));
            }
        }
        
        // Create sandboxed request
        let policy = SandboxPolicy::WorkspaceWrite {
            writable_roots: vec![cwd],
            network_access: NetworkSandboxPolicy::Localhost,
        };
        
        let request = self.manager
            .create_exec_request(command, policy)
            .map_err(|e| e.to_string())?;
        
        println!("Executing: {:?}", request.command);
        Ok(())
    }
}

fn main() {
    let sandbox = AgentSandbox::new();
    
    // This should be allowed
    sandbox.execute("ls", vec!["-la".to_string()], PathBuf::from("/tmp")).unwrap();
    
    // This should be denied by policy
    let result = sandbox.execute("rm", vec!["-rf".to_string(), "/".to_string()], PathBuf::from("/tmp"));
    assert!(result.is_err());
}
```

## Platform-Specific Notes

### Linux
Requires bubblewrap (`bwrap`) installed on the system. On Ubuntu/Debian:
```bash
apt install bubblewrap
```

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