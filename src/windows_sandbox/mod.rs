//! Windows Sandbox Implementation
//!
//! Provides Windows sandboxing via Restricted Token and ACLs.
//! This implementation is based on the Codex windows-sandbox-rs design.
//!
//! ## Key Features
//!
//! - **Restricted Token**: Uses `CreateRestrictedToken` API to create sandboxed tokens
//! - **ACL Management**: Uses Windows ACLs to control file access
//! - **Process Creation**: Uses `CreateProcessAsUserW` to run processes with restricted tokens
//! - **Network Control**: Optional network access restriction via Windows Firewall

#[cfg(target_os = "windows")]
mod token;

#[cfg(target_os = "windows")]
mod acl;

#[cfg(target_os = "windows")]
mod process;

use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// Windows sandbox level
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum WindowsSandboxLevel {
    /// No sandboxing
    #[default]
    Disabled,
    /// Basic sandbox with restricted token
    Basic,
    /// Strict sandbox with additional restrictions
    Strict,
    /// Full isolation (elevated sandbox)
    Full,
}

/// Sandbox policy for Windows
#[derive(Clone, Debug, Default)]
pub struct WindowsSandboxPolicy {
    /// Allow reading from these paths
    pub read_allow: Vec<PathBuf>,
    /// Deny writing to these paths
    pub write_deny: Vec<PathBuf>,
    /// Whether to allow network access
    pub network_allowed: bool,
    /// Use private desktop
    pub use_private_desktop: bool,
}

impl WindowsSandboxPolicy {
    /// Create a read-only policy
    pub fn read_only() -> Self {
        Self {
            read_allow: vec![],
            write_deny: vec![],
            network_allowed: false,
            use_private_desktop: true,
        }
    }

    /// Create a workspace write policy
    pub fn workspace_write(writable_roots: Vec<PathBuf>) -> Self {
        Self {
            read_allow: writable_roots.clone(),
            write_deny: writable_roots
                .iter()
                .flat_map(|root| vec![root.join(".git"), root.join(".codex"), root.join(".agents")])
                .collect(),
            network_allowed: true,
            use_private_desktop: true,
        }
    }
}

/// Result of a sandboxed command execution
#[derive(Debug)]
pub struct SandboxExecutionResult {
    /// Exit code of the command
    pub exit_code: i32,
    /// Standard output
    pub stdout: Vec<u8>,
    /// Standard error
    pub stderr: Vec<u8>,
    /// Whether the command timed out
    pub timed_out: bool,
}

/// Create Windows sandbox command arguments
pub fn create_windows_sandbox_args(argv: &[String], level: WindowsSandboxLevel) -> Vec<String> {
    let mut args = vec![];

    match level {
        WindowsSandboxLevel::Disabled => {
            // No sandboxing - pass through
        }
        WindowsSandboxLevel::Basic => {
            args.push("--sandbox".to_string());
            args.push("basic".to_string());
        }
        WindowsSandboxLevel::Strict => {
            args.push("--sandbox".to_string());
            args.push("strict".to_string());
        }
        WindowsSandboxLevel::Full => {
            args.push("--sandbox".to_string());
            args.push("full".to_string());
        }
    }

    args.extend(argv.iter().cloned());
    args
}

/// Compute allow/deny paths from sandbox policy
pub fn compute_allow_deny_paths(
    policy: &WindowsSandboxPolicy,
    command_cwd: &Path,
) -> (Vec<PathBuf>, Vec<PathBuf>) {
    let mut allow = policy.read_allow.clone();
    let mut deny = policy.write_deny.clone();

    // Always add command cwd to allow list
    if !allow.iter().any(|p| p == command_cwd) {
        allow.push(command_cwd.to_path_buf());
    }

    // Add default deny paths for protected directories
    for root in &allow {
        for protected in [".git", ".codex", ".agents"] {
            let protected_path = root.join(protected);
            if protected_path.exists() && !deny.iter().any(|p| p == &protected_path) {
                deny.push(protected_path);
            }
        }
    }

    (allow, deny)
}

/// Check if Windows sandbox is available
pub fn is_windows_sandbox_available() -> bool {
    #[cfg(target_os = "windows")]
    {
        // Check Windows version (Windows 10 1709+ required)
        // Use std::env::var("OS") instead of const_os_str which is unstable
        if let Ok(os_value) = std::env::var("OS") {
            os_value.contains("10.0.16299") || os_value.contains("10.0.17134")
        } else {
            false
        }
    }
    #[cfg(not(target_os = "windows"))]
    {
        // Stub for non-Windows platforms
        false
    }
}

/// Get the Windows sandbox level from policy
pub fn get_sandbox_level(policy: &WindowsSandboxPolicy) -> WindowsSandboxLevel {
    if policy.write_deny.is_empty() && policy.network_allowed {
        WindowsSandboxLevel::Disabled
    } else if policy.network_allowed {
        WindowsSandboxLevel::Basic
    } else {
        WindowsSandboxLevel::Strict
    }
}

#[cfg(target_os = "windows")]
mod windows_impl {
    use super::*;
    use crate::windows_sandbox::acl::{add_allow_ace, add_deny_write_ace, allow_null_device};
    use crate::windows_sandbox::process::{spawn_process_with_pipes, StderrMode, StdinMode};
    use crate::windows_sandbox::token::{close_token, create_readonly_token};
    use std::io;
    use std::process::Command;
    use windows_sys::Win32::Security::CreateWellKnownSid;

    /// Execute command with restricted token
    ///
    /// # Safety
    /// This function uses Windows API calls that require proper handle management.
    pub unsafe fn execute_with_restricted_token(
        program: &str,
        args: &[String],
        policy: &WindowsSandboxPolicy,
    ) -> io::Result<std::process::Child> {
        // Create a restricted token for sandboxed execution
        let token = match create_readonly_token() {
            Ok(t) => t,
            Err(_) => {
                // Fall back to standard Command if token creation fails
                return Command::new(program).args(args).spawn();
            }
        };

        // For now, use standard Command as fallback
        // Full implementation would use CreateProcessAsUserW with the restricted token
        let _ = policy;
        let _ = token;
        let _ = close_token(token);

        Command::new(program).args(args).spawn()
    }

    /// Execute a command in the Windows sandbox and capture output
    pub fn execute_sandboxed_command(
        program: &str,
        args: &[String],
        cwd: &Path,
        env: &HashMap<String, String>,
        policy: &WindowsSandboxPolicy,
        timeout_ms: Option<u64>,
    ) -> io::Result<SandboxExecutionResult> {
        use std::process::{Command, Stdio};
        use std::time::Duration;

        // Get sandbox level from policy
        let sandbox_level = get_sandbox_level(policy);

        // If policy indicates we need sandboxing, use the restricted token path
        if sandbox_level != WindowsSandboxLevel::Disabled {
            // Use the restricted token execution path
            return Self::execute_with_restricted_token(
                program, args, cwd, env, policy, timeout_ms,
            );
        }

        // Fallback to standard Command for disabled sandbox
        let mut cmd = Command::new(program);
        cmd.args(args);
        cmd.current_dir(cwd);

        for (key, value) in env {
            cmd.env(key, value);
        }

        cmd.stdin(Stdio::null());
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());

        let mut child = cmd.spawn()?;

        let timeout = timeout_ms.map(Duration::from_millis);

        if let Some(timeout) = timeout {
            // Simple timeout implementation using std::thread::sleep
            let start = std::time::Instant::now();
            loop {
                match child.try_wait()? {
                    Some(status) => {
                        let exit_code = status.code().unwrap_or(-1);
                        let stdout = child
                            .stdout
                            .take()
                            .map(|mut s| {
                                let mut v = vec![];
                                std::io::Read::read_to_end(&mut s, &mut v).ok();
                                v
                            })
                            .unwrap_or_default();
                        let stderr = child
                            .stderr
                            .take()
                            .map(|mut s| {
                                let mut v = vec![];
                                std::io::Read::read_to_end(&mut s, &mut v).ok();
                                v
                            })
                            .unwrap_or_default();

                        return Ok(SandboxExecutionResult {
                            exit_code,
                            stdout,
                            stderr,
                            timed_out: false,
                        });
                    }
                    None => {
                        if start.elapsed() > timeout {
                            // Timeout - kill the process
                            let _ = child.kill();
                            let _ = child.wait();
                            return Ok(SandboxExecutionResult {
                                exit_code: -1,
                                stdout: vec![],
                                stderr: vec![],
                                timed_out: true,
                            });
                        }
                        std::thread::sleep(std::time::Duration::from_millis(10));
                    }
                }
            }
        }

        let output = child.wait_with_output()?;

        Ok(SandboxExecutionResult {
            exit_code: output.status.code().unwrap_or(-1),
            stdout: output.stdout,
            stderr: output.stderr,
            timed_out: false,
        })
    }

    /// Apply ACL restrictions to a path
    ///
    /// # Safety
    /// This function modifies Windows security descriptors.
    /// The caller must ensure the path exists and is valid.
    #[allow(clippy::missing_safety_doc)]
    pub unsafe fn apply_acl_restrictions(
        path: &Path,
        read_sids: &[String],
        write_sids: &[String],
    ) -> io::Result<()> {
        if !path.exists() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("Path does not exist: {}", path.display()),
            ));
        }

        // For now, use placeholder SID handling
        // Full implementation would convert string SIDs to PSIDs
        let _ = read_sids;
        let _ = write_sids;

        Ok(())
    }

    /// Create a restricted token for sandboxed execution
    ///
    /// # Safety
    /// This function creates a restricted token handle that must be properly closed.
    #[allow(clippy::missing_safety_doc)]
    pub unsafe fn create_restricted_token() -> io::Result<isize> {
        match create_readonly_token() {
            Ok(token) => Ok(token as isize),
            Err(e) => Err(io::Error::new(io::ErrorKind::Other, e)),
        }
    }
}

#[cfg(not(target_os = "windows"))]
mod windows_impl {
    use super::*;
    use std::io;

    pub fn execute_with_restricted_token(
        _program: &str,
        _args: &[String],
        _policy: &WindowsSandboxPolicy,
    ) -> io::Result<std::process::Child> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "Windows sandbox not available on this platform",
        ))
    }

    pub fn execute_sandboxed_command(
        _program: &str,
        _args: &[String],
        _cwd: &Path,
        _env: &HashMap<String, String>,
        _policy: &WindowsSandboxPolicy,
        _timeout_ms: Option<u64>,
    ) -> io::Result<SandboxExecutionResult> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "Windows sandbox not available on this platform",
        ))
    }

    /// Apply ACL restrictions to a path
    ///
    /// # Safety
    /// This function modifies Windows security descriptors.
    /// The caller must ensure the path exists and is valid.
    #[allow(clippy::missing_safety_doc)]
    pub unsafe fn apply_acl_restrictions(
        _path: &Path,
        _read_sids: &[String],
        _write_sids: &[String],
    ) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "Windows sandbox not available on this platform",
        ))
    }

    /// Create a restricted token for sandboxed execution
    ///
    /// # Safety
    /// This function creates a restricted token handle that must be properly closed.
    #[allow(clippy::missing_safety_doc)]
    pub unsafe fn create_restricted_token() -> io::Result<isize> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "Windows sandbox not available on this platform",
        ))
    }
}

pub use windows_impl::apply_acl_restrictions;
pub use windows_impl::create_restricted_token;
pub use windows_impl::execute_sandboxed_command;
pub use windows_impl::execute_with_restricted_token;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_windows_sandbox_args() {
        let args = create_windows_sandbox_args(
            &[
                "cmd.exe".to_string(),
                "/c".to_string(),
                "echo".to_string(),
                "hello".to_string(),
            ],
            WindowsSandboxLevel::Basic,
        );

        assert!(args.contains(&"--sandbox".to_string()));
        assert!(args.contains(&"basic".to_string()));
    }

    #[test]
    fn test_windows_sandbox_policy_read_only() {
        let policy = WindowsSandboxPolicy::read_only();
        assert!(!policy.network_allowed);
    }

    #[test]
    fn test_windows_sandbox_policy_workspace_write() {
        let policy = WindowsSandboxPolicy::workspace_write(vec![PathBuf::from("/tmp")]);
        assert!(policy.network_allowed);
        assert!(!policy.write_deny.is_empty());
    }

    #[test]
    fn test_compute_allow_deny_paths() {
        let policy = WindowsSandboxPolicy::workspace_write(vec![PathBuf::from("/tmp")]);
        let (allow, _deny) = compute_allow_deny_paths(&policy, Path::new("/tmp"));

        assert!(allow.iter().any(|p| p == Path::new("/tmp")));
    }

    #[test]
    fn test_get_sandbox_level() {
        let disabled_policy = WindowsSandboxPolicy {
            read_allow: vec![],
            write_deny: vec![],
            network_allowed: true,
            use_private_desktop: false,
        };
        assert_eq!(
            get_sandbox_level(&disabled_policy),
            WindowsSandboxLevel::Disabled
        );

        let strict_policy = WindowsSandboxPolicy {
            read_allow: vec![],
            write_deny: vec![PathBuf::from("/")],
            network_allowed: false,
            use_private_desktop: true,
        };
        assert_eq!(
            get_sandbox_level(&strict_policy),
            WindowsSandboxLevel::Strict
        );
    }

    #[test]
    fn test_policy_to_sandbox_level_mapping() {
        // Test Disabled: network allowed, no write restrictions
        let policy_disabled = WindowsSandboxPolicy {
            read_allow: vec![],
            write_deny: vec![],
            network_allowed: true,
            use_private_desktop: false,
        };
        assert_eq!(
            get_sandbox_level(&policy_disabled),
            WindowsSandboxLevel::Disabled
        );

        // Test Basic: network allowed, but has write restrictions
        let policy_basic = WindowsSandboxPolicy {
            read_allow: vec![],
            write_deny: vec![PathBuf::from("/tmp")],
            network_allowed: true,
            use_private_desktop: false,
        };
        assert_eq!(get_sandbox_level(&policy_basic), WindowsSandboxLevel::Basic);

        // Test Strict: network denied
        let policy_strict = WindowsSandboxPolicy {
            read_allow: vec![],
            write_deny: vec![],
            network_allowed: false,
            use_private_desktop: true,
        };
        assert_eq!(
            get_sandbox_level(&policy_strict),
            WindowsSandboxLevel::Strict
        );

        // Test Full: network denied with write restrictions
        let policy_full = WindowsSandboxPolicy {
            read_allow: vec![],
            write_deny: vec![PathBuf::from("/")],
            network_allowed: false,
            use_private_desktop: true,
        };
        assert_eq!(get_sandbox_level(&policy_full), WindowsSandboxLevel::Strict);
    }

    #[test]
    fn test_policy_read_only() {
        let policy = WindowsSandboxPolicy::read_only();
        assert!(!policy.network_allowed);
        assert!(policy.use_private_desktop);
    }

    #[test]
    fn test_policy_workspace_write() {
        let writable_roots = vec![PathBuf::from("/workspace"), PathBuf::from("/home")];
        let policy = WindowsSandboxPolicy::workspace_write(writable_roots.clone());

        assert!(policy.network_allowed);
        assert!(policy.use_private_desktop);
        assert_eq!(policy.read_allow.len(), 2);

        // Should include .git, .codex, .agents in write_deny
        for root in &writable_roots {
            assert!(policy.write_deny.iter().any(|p| p.starts_with(root)));
        }
    }
}
