//! Comprehensive functional tests for sandbox security features
//!
//! Tests cover:
//! 1. Workspace directory read/write operations
//! 2. Directory bypass attempt blocking
//! 3. Dangerous command blacklist (git, file operations)
//! 4. Configurable whitelist/blacklist/greylist system

use ai_sandbox::{Decision, Policy};

fn main() {
    println!("=== AI Sandbox Functional Tests ===\n");

    // Test 1: Workspace directory operations
    test_workspace_read_write();

    // Test 2: Directory bypass attempts
    test_directory_bypass_blocking();

    // Test 3: Dangerous command blacklist
    test_dangerous_command_blacklist();

    // Test 4: Whitelist/Blacklist/Greylist system
    test_command_rule_system();

    // Test 5: Default dangerous command blacklist
    test_default_dangerous_commands();

    println!("\n=== All Functional Tests Passed! ===");
}

/// Test 1: Workspace directory read/write operations
fn test_workspace_read_write() {
    println!("Test 1: Workspace Directory Read/Write Operations");

    // Create a policy with default (allow) mode
    let mut policy = Policy::new();
    policy
        .add_prefix_rule(&["ls".to_string()], Decision::Allow, None)
        .unwrap();
    policy
        .add_prefix_rule(&["cat".to_string()], Decision::Allow, None)
        .unwrap();
    policy
        .add_prefix_rule(&["touch".to_string()], Decision::Allow, None)
        .unwrap();
    policy
        .add_prefix_rule(&["echo".to_string()], Decision::Allow, None)
        .unwrap();
    policy
        .add_prefix_rule(&["mkdir".to_string()], Decision::Allow, None)
        .unwrap();

    // Test: Normal file operations in workspace should be allowed
    let tests = vec![
        vec!["ls".to_string(), "-la".to_string()],
        vec!["cat".to_string(), "file.txt".to_string()],
        vec!["touch".to_string(), "newfile.txt".to_string()],
        vec!["echo".to_string(), "hello".to_string()],
        vec!["mkdir".to_string(), "newdir".to_string()],
    ];

    for cmd in &tests {
        let result = policy.check_with_cwd(cmd, Some("/tmp"));
        match result {
            Some(m) => {
                if m.decision == Decision::Allow {
                    println!("  ✓ {:?} -> Allowed (workspace operation)", cmd);
                } else {
                    panic!("  ✗ {:?} should be allowed in workspace!", cmd);
                }
            }
            None => {
                // No matching rule, depends on default decision
                println!("  ✓ {:?} -> Allowed (default)", cmd);
            }
        }
    }

    println!("  PASSED: Workspace operations allowed\n");
}

/// Test 2: Block directory bypass attempts
fn test_directory_bypass_blocking() {
    println!("Test 2: Directory Bypass Attempt Blocking");

    let policy = Policy::new();

    // Test: Bypass attempts using absolute paths
    let bypass_tests = vec![
        // Absolute path to sensitive location
        (
            vec!["cat".to_string(), "/etc/passwd".to_string()],
            Some("/tmp"),
            true,
        ),
        (
            vec!["ls".to_string(), "/var/log".to_string()],
            Some("/tmp"),
            true,
        ),
        (
            vec!["cat".to_string(), "/root/.ssh/id_rsa".to_string()],
            Some("/tmp"),
            true,
        ),
        // Relative path bypass using ..
        (
            vec!["ls".to_string(), "../..".to_string()],
            Some("/tmp"),
            true,
        ),
        (
            vec!["cat".to_string(), "../../etc/passwd".to_string()],
            Some("/tmp"),
            true,
        ),
        // Normal operations should be allowed
        (
            vec!["ls".to_string(), "file.txt".to_string()],
            Some("/tmp"),
            false,
        ),
        (
            vec!["cat".to_string(), "data.json".to_string()],
            Some("/tmp"),
            false,
        ),
        (
            vec!["touch".to_string(), "test.txt".to_string()],
            Some("/tmp"),
            false,
        ),
    ];

    for (cmd, cwd, should_block) in &bypass_tests {
        let result = policy.check_with_cwd(cmd, *cwd);
        let is_blocked = result
            .as_ref()
            .map(|m| {
                m.decision == Decision::Deny
                    && m.justification
                        .as_ref()
                        .map(|j| j.contains("bypass"))
                        .unwrap_or(false)
            })
            .unwrap_or(false);

        if *should_block {
            if is_blocked {
                println!(
                    "  ✓ {:?} with cwd {:?} -> Blocked (bypass detected)",
                    cmd, cwd
                );
            } else {
                panic!(
                    "  ✗ {:?} with cwd {:?} should be blocked as bypass attempt!",
                    cmd, cwd
                );
            }
        } else {
            if !is_blocked {
                println!(
                    "  ✓ {:?} with cwd {:?} -> Allowed (normal operation)",
                    cmd, cwd
                );
            } else {
                panic!(
                    "  ✗ {:?} with cwd {:?} should be allowed as normal operation!",
                    cmd, cwd
                );
            }
        }
    }

    println!("  PASSED: Directory bypass attempts blocked\n");
}

/// Test 3: Dangerous command blacklist (git, file operations)
fn test_dangerous_command_blacklist() {
    println!("Test 3: Dangerous Command Blacklist");

    // Create blacklist policy
    let mut policy = Policy::new_blacklist();

    // File destruction commands
    let dangerous_files = vec!["rm", "rmdir", "shred", "dd", "mkfs", "format"];
    for cmd in &dangerous_files {
        policy
            .add_prefix_rule(
                &[cmd.to_string()],
                Decision::Deny,
                Some(format!("Dangerous: {}", cmd)),
            )
            .unwrap();
    }

    // Git commands (require confirmation)
    policy
        .add_prefix_rule(
            &["git".to_string()],
            Decision::Prompt,
            Some("Git needs confirmation".to_string()),
        )
        .unwrap();

    // Test file destruction commands
    let file_tests = vec![
        vec!["rm".to_string(), "-rf".to_string(), "/".to_string()],
        vec!["rmdir".to_string(), "somedir".to_string()],
        vec!["shred".to_string(), "-u".to_string(), "file".to_string()],
        vec![
            "dd".to_string(),
            "if=/dev/zero".to_string(),
            "of=/dev/sda".to_string(),
        ],
        vec!["mkfs".to_string(), "-t".to_string(), "ext4".to_string()],
    ];

    for cmd in &file_tests {
        let result = policy.check(cmd);
        match result {
            Some(m) => {
                if m.decision == Decision::Deny {
                    println!("  ✓ {:?} -> Denied (dangerous file operation)", cmd);
                } else {
                    panic!("  ✗ {:?} should be denied!", cmd);
                }
            }
            None => panic!("  ✗ {:?} should have matching rule!", cmd),
        }
    }

    // Test git commands
    let git_tests = vec![
        vec!["git".to_string(), "status".to_string()],
        vec!["git".to_string(), "restore".to_string()],
        vec!["git".to_string(), "rm".to_string()],
        vec!["git".to_string(), "reset".to_string(), "--hard".to_string()],
        vec!["git".to_string(), "clean".to_string(), "-fd".to_string()],
    ];

    for cmd in &git_tests {
        let result = policy.check(cmd);
        match result {
            Some(m) => {
                if m.decision == Decision::Prompt {
                    println!("  ✓ {:?} -> Prompt (git command)", cmd);
                } else {
                    panic!("  ✗ {:?} should require prompt for git!", cmd);
                }
            }
            None => panic!("  ✗ {:?} should have matching rule!", cmd),
        }
    }

    println!("  PASSED: Dangerous commands properly handled\n");
}

/// Test 4: Whitelist/Blacklist/Greylist system
fn test_command_rule_system() {
    println!("Test 4: Whitelist/Blacklist/Greylist System");

    // Test whitelist mode
    let mut whitelist_policy = Policy::new_whitelist();
    whitelist_policy
        .add_prefix_rule(&["ls".to_string()], Decision::Allow, None)
        .unwrap();
    whitelist_policy
        .add_prefix_rule(&["cat".to_string()], Decision::Allow, None)
        .unwrap();

    // In whitelist mode, only allowed commands work
    let whitelist_tests = vec![
        (vec!["ls".to_string()], Decision::Allow),
        (vec!["cat".to_string(), "file".to_string()], Decision::Allow),
        (vec!["rm".to_string()], Decision::Deny), // Not in whitelist
        (vec!["curl".to_string()], Decision::Deny), // Not in whitelist
    ];

    println!("  Whitelist Mode:");
    for (cmd, expected) in &whitelist_tests {
        let result = whitelist_policy.check(cmd);
        let decision = result
            .as_ref()
            .map(|m| m.decision)
            .unwrap_or(Decision::Allow);
        if decision == *expected {
            println!("    ✓ {:?} -> {:?}", cmd, decision);
        } else {
            panic!(
                "    ✗ {:?} expected {:?} but got {:?}",
                cmd, expected, decision
            );
        }
    }

    // Test greylist (prompt) mode
    let mut greylist_policy = Policy::new();
    greylist_policy
        .add_prefix_rule(
            &["git".to_string()],
            Decision::Prompt,
            Some("Git needs confirmation".to_string()),
        )
        .unwrap();

    let greylist_tests = vec![vec!["git".to_string(), "status".to_string()]];

    for cmd in &greylist_tests {
        let result = greylist_policy.check(cmd);
        match result {
            Some(m) => {
                if m.decision == Decision::Prompt {
                    println!("    ✓ {:?} -> Prompt (greylist)", cmd);
                }
            }
            None => panic!("    ✗ {:?} should prompt!", cmd),
        }
    }

    println!("  PASSED: Whitelist/Blacklist/Greylist system works\n");
}

/// Test 5: Default dangerous command blacklist
fn test_default_dangerous_commands() {
    println!("Test 5: Default Dangerous Command Blacklist");

    // Create policy with defaults
    let policy = Policy::new_with_defaults();

    // Test various dangerous command categories
    let tests = vec![
        // File destruction
        (vec!["rm".to_string(), "-rf".to_string()], Decision::Deny),
        (
            vec![
                "dd".to_string(),
                "if=/dev/zero".to_string(),
                "of=/dev/sda".to_string(),
            ],
            Decision::Deny,
        ),
        // System modification (should be denied)
        (
            vec![
                "chmod".to_string(),
                "777".to_string(),
                "/some/path".to_string(),
            ],
            Decision::Deny,
        ),
        (
            vec![
                "chown".to_string(),
                "root".to_string(),
                "/some/path".to_string(),
            ],
            Decision::Deny,
        ),
        // Network (should be denied)
        (
            vec!["curl".to_string(), "http://evil.com".to_string()],
            Decision::Deny,
        ),
        (
            vec!["wget".to_string(), "http://evil.com".to_string()],
            Decision::Deny,
        ),
        // Shell escape (should prompt)
        (vec!["bash".to_string()], Decision::Prompt),
        (
            vec![
                "python".to_string(),
                "-c".to_string(),
                "import os".to_string(),
            ],
            Decision::Prompt,
        ),
        (vec!["vim".to_string()], Decision::Prompt),
        // Git (should prompt)
        (
            vec!["git".to_string(), "restore".to_string()],
            Decision::Prompt,
        ),
        (vec!["git".to_string(), "rm".to_string()], Decision::Prompt),
        // Safe commands (should be allowed by default)
        (vec!["ls".to_string()], Decision::Allow),
        (vec!["pwd".to_string()], Decision::Allow),
    ];

    let mut passed = 0;
    let mut failed = 0;

    for (cmd, expected) in &tests {
        let result = policy.check(cmd);
        let decision = result
            .as_ref()
            .map(|m| m.decision)
            .unwrap_or(Decision::Allow);

        if decision == *expected {
            println!("  ✓ {:?} -> {:?}", cmd, decision);
            passed += 1;
        } else {
            println!(
                "  ✗ {:?} expected {:?} but got {:?}",
                cmd, expected, decision
            );
            failed += 1;
        }
    }

    if failed > 0 {
        panic!(
            "  FAILED: {} tests failed out of {}",
            failed,
            passed + failed
        );
    }

    println!("  PASSED: {} tests passed\n", passed);
}
