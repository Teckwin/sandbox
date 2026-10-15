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

#[cfg(any(target_os = "windows", test))]
fn quote_windows_arg(arg: &str) -> String {
    let mut quoted = String::with_capacity(arg.len() + 2);
    quoted.push('"');
    let mut backslashes = 0;

    for character in arg.chars() {
        match character {
            '\\' => backslashes += 1,
            '"' => {
                quoted.extend(std::iter::repeat('\\').take(backslashes * 2 + 1));
                quoted.push('"');
                backslashes = 0;
            }
            _ => {
                quoted.extend(std::iter::repeat('\\').take(backslashes));
                quoted.push(character);
                backslashes = 0;
            }
        }
    }

    quoted.extend(std::iter::repeat('\\').take(backslashes * 2));
    quoted.push('"');
    quoted
}

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

impl WindowsSandboxLevel {
    /// Convert sandbox level to string
    pub fn as_str(&self) -> &'static str {
        match self {
            WindowsSandboxLevel::Disabled => "disabled",
            WindowsSandboxLevel::Basic => "basic",
            WindowsSandboxLevel::Strict => "strict",
            WindowsSandboxLevel::Full => "full",
        }
    }
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
    // Full: maximum restrictions - no write access to root (/) and no network
    if !policy.write_deny.is_empty() && !policy.network_allowed {
        // Check if write is denied for root or system directories
        let has_root_deny = policy
            .write_deny
            .iter()
            .any(|p| p.as_os_str() == "/" || p.to_string_lossy() == "/");
        if has_root_deny {
            return WindowsSandboxLevel::Full;
        }
    }

    if policy.read_allow.is_empty() && policy.write_deny.is_empty() && policy.network_allowed {
        WindowsSandboxLevel::Disabled
    } else if policy.network_allowed {
        WindowsSandboxLevel::Basic
    } else {
        WindowsSandboxLevel::Strict
    }
}

#[cfg(any(target_os = "windows", test))]
fn with_windows_process_adapter<T>(
    policy: &WindowsSandboxPolicy,
    execute: impl FnOnce(bool) -> std::io::Result<T>,
) -> std::io::Result<T> {
    execute(get_sandbox_level(policy) != WindowsSandboxLevel::Disabled)
}

#[cfg(test)]
mod portable_adapter_tests {
    use super::*;
    use std::cell::Cell;
    use std::io;

    struct MockWindowsProcessAdapter {
        restricted_selected: Cell<Option<bool>>,
    }

    impl MockWindowsProcessAdapter {
        fn execute(&self, policy: &WindowsSandboxPolicy) -> io::Result<()> {
            with_windows_process_adapter(policy, |restricted| {
                self.restricted_selected.set(Some(restricted));
                if restricted {
                    Err(io::Error::new(
                        io::ErrorKind::Unsupported,
                        "mock restricted process launcher unavailable",
                    ))
                } else {
                    Ok(())
                }
            })
        }
    }

    #[test]
    fn protected_policy_does_not_fall_back_to_unrestricted_process() {
        let adapter = MockWindowsProcessAdapter {
            restricted_selected: Cell::new(None),
        };

        let result = adapter.execute(&WindowsSandboxPolicy::read_only());

        assert_eq!(adapter.restricted_selected.get(), Some(true));
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::Unsupported);
    }

    #[test]
    fn full_access_policy_selects_only_the_unrestricted_process() {
        let adapter = MockWindowsProcessAdapter {
            restricted_selected: Cell::new(None),
        };
        let policy = WindowsSandboxPolicy {
            read_allow: Vec::new(),
            write_deny: Vec::new(),
            network_allowed: true,
            use_private_desktop: false,
        };

        adapter.execute(&policy).unwrap();

        assert_eq!(adapter.restricted_selected.get(), Some(false));
    }

    #[test]
    fn read_allow_policy_never_selects_the_unrestricted_process() {
        let adapter = MockWindowsProcessAdapter {
            restricted_selected: Cell::new(None),
        };
        let policy = WindowsSandboxPolicy {
            read_allow: vec![PathBuf::from("/workspace")],
            write_deny: Vec::new(),
            network_allowed: true,
            use_private_desktop: false,
        };

        let result = adapter.execute(&policy);

        assert_eq!(adapter.restricted_selected.get(), Some(true));
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::Unsupported);
    }
}

#[cfg(target_os = "windows")]
mod windows_impl {
    use super::*;
    #[allow(unused_imports)]
    use crate::windows_sandbox::acl::{add_allow_ace, add_deny_write_ace, allow_null_device};
    #[allow(unused_imports)]
    use crate::windows_sandbox::process::{
        spawn_process_with_pipes, PipeSpawnHandles, StderrMode, StdinMode,
    };
    use crate::windows_sandbox::token::{close_token, create_readonly_token};
    use std::io;
    use std::io::Read;
    use std::os::windows::io::{FromRawHandle, RawHandle};
    #[allow(unused_imports)]
    use windows_sys::Win32::Security::CreateWellKnownSid;
    #[allow(unused_imports)]
    use windows_sys::Win32::Security::TOKEN_ADJUST_DEFAULT;
    #[allow(unused_imports)]
    use windows_sys::Win32::Security::TOKEN_ADJUST_SESSIONID;
    use windows_sys::Win32::System::Threading::{TerminateProcess, WaitForSingleObject, INFINITE};
    use windows_sys::Win32::{
        Foundation::{CloseHandle, WAIT_OBJECT_0, WAIT_TIMEOUT},
        System::Threading::PROCESS_INFORMATION,
    };

    /// Execute command with restricted token
    ///
    /// # Safety
    /// This function uses Windows API calls that require proper handle management.
    pub unsafe fn execute_with_restricted_token(
        program: &str,
        args: &[String],
        policy: &WindowsSandboxPolicy,
    ) -> io::Result<()> {
        execute_sandboxed_command(
            program,
            args,
            &std::env::current_dir()?,
            &HashMap::new(),
            policy,
            None,
        )
        .map(|_| ())
    }

    fn read_pipe(handle: usize) -> io::Result<Vec<u8>> {
        let mut file = unsafe {
            std::fs::File::from_raw_handle(
                handle as windows_sys::Win32::Foundation::HANDLE as RawHandle,
            )
        };
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)?;
        Ok(bytes)
    }

    unsafe fn close_spawn_handles(handles: &PipeSpawnHandles) {
        let _ = CloseHandle(handles.process.hProcess);
        let _ = CloseHandle(handles.stdout_read);
        if let Some(handle) = handles.stderr_read {
            let _ = CloseHandle(handle);
        }
        if let Some(handle) = handles.stdin_write {
            let _ = CloseHandle(handle);
        }
    }

    unsafe fn spawn_restricted_process(
        program: &str,
        args: &[String],
        cwd: &Path,
        env: &HashMap<String, String>,
        policy: &WindowsSandboxPolicy,
    ) -> io::Result<crate::windows_sandbox::process::PipeSpawnHandles> {
        if !policy.network_allowed {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "Windows network isolation is unavailable; refusing protected execution",
            ));
        }
        if !policy.read_allow.is_empty() || !policy.write_deny.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "Windows filesystem ACL enforcement is unavailable for this policy",
            ));
        }

        let token = create_readonly_token().map_err(io::Error::other)?;
        let mut argv = Vec::with_capacity(args.len() + 1);
        argv.push(program.to_string());
        argv.extend(args.iter().cloned());
        let result = spawn_process_with_pipes(
            token,
            &argv,
            cwd,
            env,
            StdinMode::Closed,
            StderrMode::Separate,
            policy.use_private_desktop,
        )
        .map_err(io::Error::other);
        let _ = close_token(token);
        result
    }

    unsafe fn wait_for_restricted_process(
        process: PROCESS_INFORMATION,
        timeout_ms: Option<u64>,
        stdout_thread: std::thread::JoinHandle<io::Result<Vec<u8>>>,
        stderr_thread: std::thread::JoinHandle<io::Result<Vec<u8>>>,
    ) -> io::Result<SandboxExecutionResult> {
        let wait_ms = match timeout_ms {
            Some(value) if value < u32::MAX as u64 => value as u32,
            Some(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "Windows wait timeout is too large",
                ))
            }
            None => INFINITE,
        };
        let wait_result = WaitForSingleObject(process.hProcess, wait_ms);
        let mut timed_out = false;
        if wait_result != WAIT_OBJECT_0 {
            if timeout_ms.is_some() && wait_result == WAIT_TIMEOUT {
                timed_out = true;
                if TerminateProcess(process.hProcess, 1) == 0 {
                    let error = io::Error::last_os_error();
                    let _ = CloseHandle(process.hProcess);
                    return Err(error);
                }
                let _ = WaitForSingleObject(process.hProcess, INFINITE);
            } else {
                let error = io::Error::last_os_error();
                let _ = CloseHandle(process.hProcess);
                return Err(error);
            }
        }

        let stdout = match stdout_thread.join() {
            Ok(result) => result?,
            Err(_) => {
                let _ = CloseHandle(process.hProcess);
                let _ = stderr_thread.join();
                return Err(io::Error::other("stdout reader thread panicked"));
            }
        };
        let stderr = match stderr_thread.join() {
            Ok(result) => result?,
            Err(_) => {
                let _ = CloseHandle(process.hProcess);
                return Err(io::Error::other("stderr reader thread panicked"));
            }
        };
        let mut exit_code = 1u32;
        if !timed_out {
            let mut code = 0u32;
            if windows_sys::Win32::System::Threading::GetExitCodeProcess(
                process.hProcess,
                &mut code,
            ) == 0
            {
                let error = io::Error::last_os_error();
                let _ = CloseHandle(process.hProcess);
                return Err(error);
            }
            exit_code = code;
        }
        let _ = CloseHandle(process.hProcess);
        Ok(SandboxExecutionResult {
            exit_code: if timed_out { -1 } else { exit_code as i32 },
            stdout,
            stderr,
            timed_out,
        })
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

        with_windows_process_adapter(policy, |restricted| {
            // A protected policy uses only the restricted-token process creator.
            // Failure is returned; the original command is never run.
            if restricted {
                let handles = unsafe { spawn_restricted_process(program, args, cwd, env, policy) }?;
                if handles.stderr_read.is_none() {
                    unsafe { close_spawn_handles(&handles) };
                    return Err(io::Error::other(
                        "restricted process returned no stderr pipe",
                    ));
                }
                let process = handles.process;
                let stdout_handle = handles.stdout_read;
                let stderr_handle = handles.stderr_read.expect("checked above");
                let stdout_handle = stdout_handle as usize;
                let stderr_handle = stderr_handle as usize;
                let stdout_thread = std::thread::spawn(move || read_pipe(stdout_handle));
                let stderr_thread = std::thread::spawn(move || read_pipe(stderr_handle));
                return unsafe {
                    wait_for_restricted_process(process, timeout_ms, stdout_thread, stderr_thread)
                };
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

        if read_sids.is_empty() && write_sids.is_empty() {
            return Ok(());
        }
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "string SID to ACL enforcement is not implemented",
        ))
    }

    /// Create a restricted token for sandboxed execution
    ///
    /// # Safety
    /// This function creates a restricted token handle that must be properly closed.
    #[allow(clippy::missing_safety_doc, clippy::io_other_error)]
    pub unsafe fn create_restricted_token() -> io::Result<isize> {
        match create_readonly_token() {
            Ok(token) => Ok(token as isize),
            Err(e) => Err(io::Error::other(e)),
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
    ) -> io::Result<()> {
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

// Note: The following imports are for future Windows implementation
// They are marked as allowed because they will be used when the actual
// Windows implementation is connected to this module
#[allow(unused_imports)]
#[cfg(target_os = "windows")]
use self::acl::{add_allow_ace, add_deny_write_ace, allow_null_device};
#[allow(unused_imports)]
#[cfg(target_os = "windows")]
use self::process::{spawn_process_with_pipes, StderrMode, StdinMode};
#[allow(unused_imports)]
#[cfg(target_os = "windows")]
use self::token::{close_token, create_readonly_token};

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn windows_argument_quoting_preserves_backslashes_and_quotes() {
        assert_eq!(quote_windows_arg(""), "\"\"");
        assert_eq!(quote_windows_arg("simple"), "\"simple\"");
        assert_eq!(quote_windows_arg("with space"), "\"with space\"");
        assert_eq!(quote_windows_arg("with\\\"quote"), "\"with\\\\\\\"quote\"");
        assert_eq!(
            quote_windows_arg("trailing space\\"),
            "\"trailing space\\\\\""
        );
    }

    #[test]
    fn test_windows_sandbox_level_default() {
        let level = WindowsSandboxLevel::default();
        assert_eq!(level, WindowsSandboxLevel::Disabled);
    }

    #[test]
    fn test_windows_sandbox_level_variants() {
        assert_eq!(WindowsSandboxLevel::Disabled.as_str(), "disabled");
        assert_eq!(WindowsSandboxLevel::Basic.as_str(), "basic");
        assert_eq!(WindowsSandboxLevel::Strict.as_str(), "strict");
        assert_eq!(WindowsSandboxLevel::Full.as_str(), "full");
    }

    #[test]
    fn test_windows_sandbox_policy_default() {
        let policy = WindowsSandboxPolicy::default();
        // On Windows, default policy should have specific defaults
        // The actual default values are implementation details
        // Just verify the struct can be created and has expected structure
        assert!(policy.read_allow.is_empty());
        assert!(policy.write_deny.is_empty());
        // Note: network_allowed defaults to true for full access
        // and use_private_desktop defaults to false
    }

    #[test]
    fn test_create_windows_sandbox_args_disabled() {
        let argv = vec![
            "cmd".to_string(),
            "/c".to_string(),
            "echo".to_string(),
            "hello".to_string(),
        ];
        let args = create_windows_sandbox_args(&argv, WindowsSandboxLevel::Disabled);
        assert_eq!(args, argv);
    }

    #[test]
    fn test_create_windows_sandbox_args_basic() {
        let argv = vec![
            "cmd".to_string(),
            "/c".to_string(),
            "echo".to_string(),
            "hello".to_string(),
        ];
        let args = create_windows_sandbox_args(&argv, WindowsSandboxLevel::Basic);
        assert!(args.contains(&"--sandbox".to_string()));
        assert!(args.contains(&"basic".to_string()));
    }

    #[test]
    fn test_create_windows_sandbox_args_strict() {
        let argv = vec!["cmd".to_string(), "/c".to_string(), "echo".to_string()];
        let args = create_windows_sandbox_args(&argv, WindowsSandboxLevel::Strict);
        assert!(args.contains(&"--sandbox".to_string()));
        assert!(args.contains(&"strict".to_string()));
    }

    #[test]
    fn test_create_windows_sandbox_args_full() {
        let argv = vec!["cmd".to_string(), "/c".to_string(), "echo".to_string()];
        let args = create_windows_sandbox_args(&argv, WindowsSandboxLevel::Full);
        assert!(args.contains(&"--sandbox".to_string()));
        assert!(args.contains(&"full".to_string()));
    }

    #[test]
    fn test_is_windows_sandbox_available() {
        // On non-Windows platforms, this should return false
        // Just call the function to ensure it compiles and returns a boolean
        let _result = is_windows_sandbox_available();
        #[cfg(not(target_os = "windows"))]
        assert!(!_result);
    }

    #[test]
    fn test_network_policy_to_sandbox_level() {
        // Test network allowed maps to less restrictive level
        let policy_network = WindowsSandboxPolicy {
            read_allow: vec![],
            write_deny: vec![],
            network_allowed: true,
            use_private_desktop: false,
        };
        let level = get_sandbox_level(&policy_network);
        // With network allowed but no other restrictions, should be Disabled
        assert_eq!(level, WindowsSandboxLevel::Disabled);

        // Test network denied maps to more restrictive level
        let policy_no_network = WindowsSandboxPolicy {
            read_allow: vec![],
            write_deny: vec![],
            network_allowed: false,
            use_private_desktop: true,
        };
        let level_no_net = get_sandbox_level(&policy_no_network);
        assert!(matches!(
            level_no_net,
            WindowsSandboxLevel::Strict | WindowsSandboxLevel::Full
        ));
    }

    #[test]
    fn test_compute_allow_deny_paths_with_multiple_roots() {
        let policy = WindowsSandboxPolicy::workspace_write(vec![
            PathBuf::from("C:\\workspace"),
            PathBuf::from("D:\\data"),
        ]);
        let (allow, _deny) = compute_allow_deny_paths(&policy, Path::new("C:\\workspace"));

        assert_eq!(allow.len(), 2);
        assert!(allow
            .iter()
            .any(|p| p.to_string_lossy().contains("workspace")));
        assert!(allow.iter().any(|p| p.to_string_lossy().contains("data")));
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

        let (allow_with_cwd, _) = compute_allow_deny_paths(&policy, Path::new("/workspace"));
        assert!(allow_with_cwd.iter().any(|path| path == Path::new("/tmp")));
        assert_eq!(
            allow_with_cwd
                .iter()
                .filter(|path| *path == Path::new("/workspace"))
                .count(),
            1
        );
    }

    #[test]
    fn compute_allow_deny_paths_adds_existing_protected_paths_once() {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("ai-sandbox-windows-paths-{suffix}"));
        std::fs::create_dir_all(root.join(".git")).unwrap();
        std::fs::create_dir_all(root.join(".codex")).unwrap();
        std::fs::create_dir_all(root.join(".agents")).unwrap();

        let git_path = root.join(".git");
        let policy = WindowsSandboxPolicy {
            read_allow: vec![root.clone()],
            write_deny: vec![git_path.clone()],
            network_allowed: false,
            use_private_desktop: true,
        };
        let (allow, deny) = compute_allow_deny_paths(&policy, &root);

        assert_eq!(allow, vec![root.clone()]);
        assert_eq!(deny.len(), 3);
        assert!(deny.contains(&git_path));
        assert!(deny.contains(&root.join(".codex")));
        assert!(deny.contains(&root.join(".agents")));

        std::fs::remove_dir_all(root).unwrap();
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

        // Test Strict: network denied but no root write deny
        let strict_policy = WindowsSandboxPolicy {
            read_allow: vec![],
            write_deny: vec![PathBuf::from("/some/path")], // Not root
            network_allowed: false,
            use_private_desktop: true,
        };
        assert_eq!(
            get_sandbox_level(&strict_policy),
            WindowsSandboxLevel::Strict
        );

        // Test Full: network denied with root write deny
        let full_policy = WindowsSandboxPolicy {
            read_allow: vec![],
            write_deny: vec![PathBuf::from("/")],
            network_allowed: false,
            use_private_desktop: true,
        };
        assert_eq!(get_sandbox_level(&full_policy), WindowsSandboxLevel::Full);
    }

    #[test]
    fn test_get_sandbox_level_full_with_multiple_denies() {
        // Test Full: with multiple write denies including root
        let policy = WindowsSandboxPolicy {
            read_allow: vec![],
            write_deny: vec![PathBuf::from("/tmp"), PathBuf::from("/")],
            network_allowed: false,
            use_private_desktop: true,
        };
        assert_eq!(get_sandbox_level(&policy), WindowsSandboxLevel::Full);
    }

    #[test]
    fn test_get_sandbox_level_basic_without_root_deny() {
        // Test Basic: network allowed, write deny but not root
        let policy = WindowsSandboxPolicy {
            read_allow: vec![],
            write_deny: vec![PathBuf::from("/tmp"), PathBuf::from("/home")],
            network_allowed: true,
            use_private_desktop: false,
        };
        assert_eq!(get_sandbox_level(&policy), WindowsSandboxLevel::Basic);
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

        // Test Full: network denied with write restrictions to root
        let policy_full = WindowsSandboxPolicy {
            read_allow: vec![],
            write_deny: vec![PathBuf::from("/")],
            network_allowed: false,
            use_private_desktop: true,
        };
        assert_eq!(get_sandbox_level(&policy_full), WindowsSandboxLevel::Full);
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

#[cfg(all(test, target_os = "windows"))]
mod native_windows_tests {
    use super::*;
    use std::io;

    #[test]
    fn restricted_token_process_launches_native_command() {
        let program = PathBuf::from(std::env::var_os("SystemRoot").unwrap())
            .join("System32")
            .join("cmd.exe");
        let result = unsafe {
            execute_with_restricted_token(
                &program.to_string_lossy(),
                &["/c".into(), "exit 0".into()],
                &WindowsSandboxPolicy::default(),
            )
        };

        assert!(result.is_ok(), "restricted-token launch failed: {result:?}");
    }

    #[test]
    fn unsupported_protected_policies_fail_closed_before_launch() {
        let cwd = std::env::current_dir().unwrap();
        let command = PathBuf::from(std::env::var_os("SystemRoot").unwrap())
            .join("System32")
            .join("missing-sandbox-command.exe");
        let policies = [
            WindowsSandboxPolicy {
                read_allow: vec![cwd.clone()],
                write_deny: Vec::new(),
                network_allowed: true,
                use_private_desktop: false,
            },
            WindowsSandboxPolicy {
                read_allow: Vec::new(),
                write_deny: Vec::new(),
                network_allowed: false,
                use_private_desktop: false,
            },
        ];

        for policy in policies {
            let result = execute_sandboxed_command(
                &command.to_string_lossy(),
                &[],
                &cwd,
                &HashMap::new(),
                &policy,
                None,
            );
            assert_eq!(result.unwrap_err().kind(), io::ErrorKind::Unsupported);
        }
    }

    #[test]
    fn native_acl_entrypoint_reports_unimplemented_enforcement() {
        let root =
            std::env::temp_dir().join(format!("ai-sandbox-windows-acl-{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        let result = unsafe { apply_acl_restrictions(&root, &["S-1-1-0".into()], &[]) };
        std::fs::remove_dir_all(root).unwrap();

        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::Unsupported);
    }
}
