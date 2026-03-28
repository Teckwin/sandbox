# AI Sandbox

Cross-platform sandbox security implementation for AI tools.

## Project Structure

```
ai-sandbox/
├── src/
│   ├── lib.rs                    # Main library entry
│   ├── bin/
│   │   └── sandbox-exec.rs       # CLI executable
│   ├── sandboxing/
│   │   ├── mod.rs                # Sandbox manager & policies
│   │   └── seatbelt.rs           # macOS Seatbelt implementation
│   ├── linux_sandbox/
│   │   ├── mod.rs                # Linux sandbox module
│   │   ├── bwrap.rs              # Bubblewrap integration
│   │   ├── landlock.rs           # Landlock implementation
│   │   └── bsd.rs                # FreeBSD/OpenBSD implementation
│   ├── windows_sandbox/
│   │   └── mod.rs                # Windows Restricted Token
│   ├── process_hardening/
│   │   └── mod.rs                # Process hardening
│   └── execpolicy/
│       └── mod.rs                # Execution policy engine
├── Cargo.toml
├── README.md
└── LICENSE
```

## Supported Platforms

| Platform | Sandbox Type | File |
|----------|--------------|------|
| Linux | Bubblewrap + Seccomp + Landlock | `linux_sandbox/` |
| macOS | Seatbelt (sandbox-exec) | `sandboxing/seatbelt.rs` |
| Windows | Restricted Token | `windows_sandbox/` |
| FreeBSD | Capsicum | `linux_sandbox/bsd.rs` |
| OpenBSD | pledge | `linux_sandbox/bsd.rs` |

## Key Modules

### SandboxManager
- Cross-platform sandbox abstraction
- Policy-based command transformation

### SandboxPolicy
- `DangerFullAccess` - No restrictions
- `ReadOnly` - Read-only filesystem and network
- `WorkspaceWrite` - Specific writable paths
- `ExternalSandbox` - External sandbox coordination

### Process Hardening
- Pre-main() hardening for all platforms
- Disables core dumps, ptrace attach
- Removes dangerous env vars (LD_*, DYLD_*)

### Execution Policy
- Prefix-based rule matching
- Network access control
- Command allow/deny/prompt decisions