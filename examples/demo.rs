#![allow(unused_variables)]
// This file is intentionally not fully warning-free for demonstration purposes

use ai_sandbox::{
    get_platform_sandbox, Decision, FileSystemSandboxPolicy, NetworkSandboxPolicy, Policy,
    SandboxCommand, SandboxManager, SandboxPolicy,
};
use std::collections::HashMap;
use std::ffi::OsString;
use std::path::PathBuf;

fn main() {
    println!("=== AI Sandbox Demo ===\n");

    // 1. Check platform support
    println!("1. Platform Detection:");
    let sandbox_type = get_platform_sandbox(false);
    println!("   Detected sandbox type: {:?}", sandbox_type);
    println!();

    // 2. Basic sandbox usage
    println!("2. Basic Sandbox Request:");
    let manager = SandboxManager::new();

    let command = SandboxCommand {
        program: OsString::from("ls"),
        args: vec!["-la".to_string()],
        cwd: PathBuf::from("/tmp"),
        env: HashMap::new(),
    };

    let policy = SandboxPolicy::ReadOnly {
        file_system: FileSystemSandboxPolicy::ReadOnly,
        network_access: NetworkSandboxPolicy::NoAccess,
    };

    match manager.create_exec_request(command, policy) {
        Ok(request) => {
            println!("   Command: {:?}", request.command);
            println!("   Working dir: {:?}", request.cwd);
            println!("   Sandbox type: {:?}", request.sandbox);
        }
        Err(e) => {
            println!("   Error: {}", e);
        }
    }
    println!();

    // 3. Workspace write policy
    println!("3. Workspace Write Policy:");
    let command = SandboxCommand {
        program: OsString::from("touch"),
        args: vec!["test.txt".to_string()],
        cwd: PathBuf::from("/tmp"),
        env: HashMap::new(),
    };

    let policy = SandboxPolicy::WorkspaceWrite {
        writable_roots: vec![PathBuf::from("/tmp")],
        network_access: NetworkSandboxPolicy::Localhost,
    };

    match manager.create_exec_request(command, policy) {
        Ok(request) => {
            println!("   Writable roots: /tmp");
            println!("   Network: localhost only");
        }
        Err(e) => {
            println!("   Error: {}", e);
        }
    }
    println!();

    // 4. Execution policy (command allow/deny)
    println!("4. Execution Policy (Command Filtering):");
    let mut exec_policy = Policy::new();

    // Add some rules
    exec_policy
        .add_prefix_rule(
            &["rm".to_string()],
            Decision::Deny,
            Some("Dangerous: rm command".to_string()),
        )
        .unwrap();

    exec_policy
        .add_prefix_rule(
            &["curl".to_string()],
            Decision::Deny,
            Some("Network access restricted".to_string()),
        )
        .unwrap();

    exec_policy
        .add_prefix_rule(&["ls".to_string()], Decision::Allow, None)
        .unwrap();

    // Test commands
    let test_commands = vec![
        vec!["ls".to_string(), "-la".to_string()],
        vec!["rm".to_string(), "-rf".to_string()],
        vec!["curl".to_string(), "http://example.com".to_string()],
    ];

    for cmd in test_commands {
        let result = exec_policy.check(&cmd);
        match result {
            Some(m) => {
                println!("   {:?} -> {:?}", cmd, m.decision);
                if let Some(justification) = &m.justification {
                    println!("      Reason: {}", justification);
                }
            }
            None => {
                println!("   {:?} -> Allowed (no matching rule)", cmd);
            }
        }
    }
    println!();

    // 5. Get allowed prefixes
    println!("5. Allowed Command Prefixes:");
    let prefixes = exec_policy.get_allowed_prefixes();
    for prefix in prefixes {
        println!("   {:?}", prefix);
    }
    println!();

    println!("=== Demo Complete ===");
}
