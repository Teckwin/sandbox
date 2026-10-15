//! Sandbox Execution Binary
//!
//! A command-line tool for executing commands in a sandbox.

use std::collections::HashMap;
use std::ffi::OsString;
use std::path::PathBuf;
use std::process;
use std::time::Duration;

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args
        .get(1)
        .is_some_and(|argument| argument == "--mxc-config")
    {
        process::exit(run_mxc_config(&args));
    }

    if args.len() < 2 {
        eprintln!("Usage: sandbox-exec <policy> <command> [args...]");
        eprintln!("   or: sandbox-exec --mxc-config <file.json> -- <command> [args...]");
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
        "none" => {
            eprintln!("Error: policy 'none' is not permitted by sandbox-exec");
            process::exit(1);
        }
        "readonly" => SandboxPolicy::ReadOnly {
            file_system: FileSystemSandboxPolicy::ReadOnly,
            network_access: NetworkSandboxPolicy::NoAccess,
        },
        "workspace" => {
            let root = current_dir_or_fallback(std::env::current_dir());
            SandboxPolicy::WorkspaceWrite {
                writable_roots: vec![root],
                network_access: NetworkSandboxPolicy::NoAccess,
            }
        }
        _ => {
            eprintln!("Unknown policy: {}", policy);
            process::exit(1);
        }
    };

    let cmd = SandboxCommand {
        program: OsString::from(&command[0]),
        args: command[1..].to_vec(),
        cwd: current_dir_or_fallback(std::env::current_dir()),
        env: HashMap::new(),
    };

    let manager = SandboxManager::new();

    match manager.create_exec_request(cmd, sandbox_policy) {
        Ok(request) => match request.wait() {
            Ok(status) => process::exit(status.code().unwrap_or(1)),
            Err(e) => {
                eprintln!("Error executing sandboxed command: {}", e);
                process::exit(1);
            }
        },
        Err(e) => {
            eprintln!("Error creating sandbox request: {}", e);
            process::exit(1);
        }
    }
}

fn run_mxc_config(args: &[String]) -> i32 {
    use ai_sandbox::{SandboxCommand, SandboxManager};

    let Some(config_path) = args.get(2) else {
        eprintln!("Usage: sandbox-exec --mxc-config <file.json> -- <command> [args...]");
        return 1;
    };
    if args.get(3).map(String::as_str) != Some("--") {
        eprintln!("Error: --mxc-config requires '--' before the command");
        return 1;
    }
    let command_args = &args[4..];
    if command_args.is_empty() {
        eprintln!("Error: No command provided");
        return 1;
    }

    let config_json = match std::fs::read_to_string(config_path) {
        Ok(config) => config,
        Err(error) => {
            eprintln!("Error reading MXC config: {error}");
            return 1;
        }
    };
    let command = SandboxCommand {
        program: OsString::from(&command_args[0]),
        args: command_args[1..].to_vec(),
        cwd: current_dir_or_fallback(std::env::current_dir()),
        env: HashMap::new(),
    };
    let request =
        match SandboxManager::new().create_exec_request_from_mxc_json(command, &config_json) {
            Ok(request) => request,
            Err(error) => {
                eprintln!("Error creating sandbox request from MXC config: {error}");
                return 1;
            }
        };

    match request.run(Duration::MAX) {
        Ok(status) => status.code().unwrap_or(1),
        Err(error) => {
            eprintln!("Error executing MXC-configured sandbox request: {error}");
            1
        }
    }
}

fn current_dir_or_fallback(current_dir: std::io::Result<PathBuf>) -> PathBuf {
    current_dir.unwrap_or_else(|_| PathBuf::from("."))
}

#[cfg(test)]
mod tests {
    use super::current_dir_or_fallback;
    use std::path::PathBuf;

    #[test]
    fn current_directory_resolution_uses_fallback_only_on_error() {
        let current = PathBuf::from("/workspace");
        assert_eq!(current_dir_or_fallback(Ok(current.clone())), current);
        assert_eq!(
            current_dir_or_fallback(Err(std::io::Error::other("cwd unavailable"))),
            PathBuf::from(".")
        );
    }
}
