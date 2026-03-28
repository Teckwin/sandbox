//! Sandbox Execution Binary
//!
//! A command-line tool for executing commands in a sandbox.

use std::collections::HashMap;
use std::ffi::OsString;
use std::path::PathBuf;
use std::process;

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 {
        eprintln!("Usage: sandbox-exec <policy> <command> [args...]");
        eprintln!("Policies: none, readonly, workspace");
        process::exit(1);
    }

    let policy = &args[1];
    let command = &args[2..];

    if command.is_empty() {
        eprintln!("Error: No command provided");
        process::exit(1);
    }

    // Use the sandbox library
    use ai_sandbox::{
        FileSystemSandboxPolicy, NetworkSandboxPolicy, SandboxCommand, SandboxManager,
        SandboxPolicy,
    };

    let sandbox_policy = match policy.as_str() {
        "none" => SandboxPolicy::DangerFullAccess,
        "readonly" => SandboxPolicy::ReadOnly {
            file_system: FileSystemSandboxPolicy::ReadOnly,
            network_access: NetworkSandboxPolicy::NoAccess,
        },
        "workspace" => SandboxPolicy::WorkspaceWrite {
            writable_roots: vec![PathBuf::from(".")],
            network_access: NetworkSandboxPolicy::Localhost,
        },
        _ => {
            eprintln!("Unknown policy: {}", policy);
            process::exit(1);
        }
    };

    let cmd = SandboxCommand {
        program: OsString::from(&command[0]),
        args: command[1..].to_vec(),
        cwd: std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
        env: HashMap::new(),
    };

    let manager = SandboxManager::new();

    match manager.create_exec_request(cmd, sandbox_policy) {
        Ok(_request) => {
            println!("Sandbox policy applied: {}", policy);
            // In a full implementation, this would actually execute the command
            // with the sandboxed arguments
            process::exit(0);
        }
        Err(e) => {
            eprintln!("Error creating sandbox request: {}", e);
            process::exit(1);
        }
    }
}
