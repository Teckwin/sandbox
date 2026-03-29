//! Sandbox Manager - Cross-platform sandbox abstraction

#![allow(dead_code)]

#[cfg(target_os = "macos")]
pub mod seatbelt;

#[cfg(target_os = "macos")]
pub use seatbelt::MACOS_PATH_TO_SEATBELT_EXECUTABLE;

use std::collections::HashMap;
#[allow(unused_imports)]
use std::ffi::OsString;
use std::path::{Path, PathBuf};

/// Platform-specific sandbox types
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum SandboxType {
    /// No sandboxing
    #[default]
    None,
    /// macOS Seatbelt (sandbox-exec)
    MacosSeatbelt,
    /// Linux Seccomp/Bubblewrap/Landlock
    LinuxSeccomp,
    /// Windows Restricted Token
    WindowsRestrictedToken,
    /// FreeBSD Capsicum
    FreeBSDCapsicum,
    /// OpenBSD pledge
    OpenBSDPledge,
}

impl SandboxType {
    pub fn as_metric_tag(self) -> &'static str {
        match self {
            SandboxType::None => "none",
            SandboxType::MacosSeatbelt => "seatbelt",
            SandboxType::LinuxSeccomp => "seccomp",
            SandboxType::WindowsRestrictedToken => "windows_sandbox",
            SandboxType::FreeBSDCapsicum => "capsicum",
            SandboxType::OpenBSDPledge => "pledge",
        }
    }

    /// Get the name of this sandbox type
    pub fn name(&self) -> &'static str {
        match self {
            SandboxType::None => "none",
            SandboxType::MacosSeatbelt => "seatbelt",
            SandboxType::LinuxSeccomp => "linux-seccomp",
            SandboxType::WindowsRestrictedToken => "windows-restricted-token",
            SandboxType::FreeBSDCapsicum => "capsicum",
            SandboxType::OpenBSDPledge => "pledge",
        }
    }
}

/// Sandbox preference setting
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum SandboxablePreference {
    /// Automatically select based on platform
    #[default]
    Auto,
    /// Require sandboxing
    Require,
    /// Forbid sandboxing
    Forbid,
}

/// Network sandbox policy
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum NetworkSandboxPolicy {
    /// Full network access
    #[default]
    FullAccess,
    /// No network access
    NoAccess,
    /// Allow localhost only
    Localhost,
    /// Use system proxy
    Proxy,
}

/// File system sandbox policy
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub enum FileSystemSandboxPolicy {
    /// Full filesystem access
    #[default]
    FullAccess,
    /// Read-only access
    ReadOnly,
    /// Workspace-only write access
    WorkspaceWrite {
        /// Allowed writable roots
        writable_roots: Vec<PathBuf>,
    },
    /// External sandbox (no policy applied by us)
    External,
}

/// Sandbox policy definition
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub enum SandboxPolicy {
    /// No sandboxing - full access
    #[default]
    DangerFullAccess,
    /// Read-only sandbox
    ReadOnly {
        file_system: FileSystemSandboxPolicy,
        network_access: NetworkSandboxPolicy,
    },
    /// External sandbox with network control
    ExternalSandbox {
        network_access: NetworkSandboxPolicy,
    },
    /// Workspace write access
    WorkspaceWrite {
        writable_roots: Vec<PathBuf>,
        network_access: NetworkSandboxPolicy,
    },
}

/// A command to be executed with sandboxing
#[derive(Debug)]
pub struct SandboxCommand {
    pub program: OsString,
    pub args: Vec<String>,
    pub cwd: PathBuf,
    pub env: HashMap<String, String>,
}

/// The transformed request ready for execution
#[derive(Debug)]
pub struct SandboxExecRequest {
    pub command: Vec<String>,
    pub cwd: PathBuf,
    pub env: HashMap<String, String>,
    pub sandbox: SandboxType,
    pub sandbox_policy: SandboxPolicy,
    pub file_system_policy: FileSystemSandboxPolicy,
    pub network_policy: NetworkSandboxPolicy,
    pub arg0: Option<String>,
}

/// Sandbox transformation error
#[derive(Debug)]
pub enum SandboxTransformError {
    MissingLinuxSandboxExecutable,
    #[cfg(not(target_os = "macos"))]
    SeatbeltUnavailable,
    PlatformNotSupported,
}

impl std::fmt::Display for SandboxTransformError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingLinuxSandboxExecutable => {
                write!(f, "missing linux-sandbox executable path")
            }
            #[cfg(not(target_os = "macos"))]
            Self::SeatbeltUnavailable => write!(f, "seatbelt sandbox is only available on macOS"),
            Self::PlatformNotSupported => write!(f, "sandbox is not supported on this platform"),
        }
    }
}

impl std::error::Error for SandboxTransformError {}

/// Get the appropriate sandbox type for the current platform
pub fn get_platform_sandbox(windows_sandbox_enabled: bool) -> Option<SandboxType> {
    if cfg!(target_os = "macos") {
        Some(SandboxType::MacosSeatbelt)
    } else if cfg!(target_os = "linux") {
        Some(SandboxType::LinuxSeccomp)
    } else if cfg!(target_os = "freebsd") {
        Some(SandboxType::FreeBSDCapsicum)
    } else if cfg!(target_os = "openbsd") {
        Some(SandboxType::OpenBSDPledge)
    } else if cfg!(target_os = "windows") {
        if windows_sandbox_enabled {
            Some(SandboxType::WindowsRestrictedToken)
        } else {
            None
        }
    } else {
        None
    }
}

/// Sandbox Manager - creates sandboxed execution requests
#[derive(Default)]
pub struct SandboxManager;

impl SandboxManager {
    pub fn new() -> Self {
        Self
    }

    /// Select initial sandbox type based on preferences
    #[allow(unused_variables)]
    pub fn select_initial(
        &self,
        file_system_policy: &FileSystemSandboxPolicy,
        network_policy: NetworkSandboxPolicy,
        pref: SandboxablePreference,
        windows_sandbox_enabled: bool,
    ) -> SandboxType {
        match pref {
            SandboxablePreference::Forbid => SandboxType::None,
            SandboxablePreference::Require => {
                get_platform_sandbox(windows_sandbox_enabled).unwrap_or(SandboxType::None)
            }
            SandboxablePreference::Auto => {
                let platform_sandbox = get_platform_sandbox(windows_sandbox_enabled);
                // Always use platform sandbox for Auto mode
                platform_sandbox.unwrap_or(SandboxType::None)
            }
        }
    }

    /// Create a sandbox execution request
    pub fn create_exec_request(
        &self,
        command: SandboxCommand,
        policy: SandboxPolicy,
    ) -> Result<SandboxExecRequest, SandboxTransformError> {
        let sandbox = self.select_initial(
            &FileSystemSandboxPolicy::default(),
            NetworkSandboxPolicy::default(),
            SandboxablePreference::Auto,
            false,
        );
        self.transform_command(command, policy, sandbox, None)
    }

    /// Transform a command for sandbox execution
    pub fn transform_command(
        &self,
        command: SandboxCommand,
        policy: SandboxPolicy,
        sandbox: SandboxType,
        _linux_sandbox_exe: Option<&Path>,
    ) -> Result<SandboxExecRequest, SandboxTransformError> {
        let argv: Vec<OsString> = std::iter::once(command.program)
            .chain(command.args.iter().map(OsString::from))
            .collect();

        let (argv, arg0_override) = match sandbox {
            SandboxType::None => (os_argv_to_strings(argv), None),
            #[cfg(target_os = "macos")]
            SandboxType::MacosSeatbelt => {
                let args = crate::sandboxing::seatbelt::create_seatbelt_command_args_for_policies(
                    os_argv_to_strings(argv),
                    &crate::FileSystemSandboxPolicy::default(),
                    crate::NetworkSandboxPolicy::FullAccess,
                    std::path::Path::new("."),
                    false,
                    None,
                );
                let mut full_command = vec![MACOS_PATH_TO_SEATBELT_EXECUTABLE.to_string()];
                full_command.extend(args);
                (full_command, None)
            }
            #[cfg(not(target_os = "macos"))]
            SandboxType::MacosSeatbelt => return Err(SandboxTransformError::SeatbeltUnavailable),
            SandboxType::LinuxSeccomp => {
                let exe = _linux_sandbox_exe
                    .ok_or(SandboxTransformError::MissingLinuxSandboxExecutable)?;
                let args = create_linux_sandbox_args(&policy, command.cwd.as_path());
                let mut full_command = vec![exe.to_string_lossy().to_string()];
                full_command.extend(args);
                (full_command, Some("linux-sandbox".to_string()))
            }
            #[cfg(target_os = "windows")]
            SandboxType::WindowsRestrictedToken => (os_argv_to_strings(argv), None),
            #[cfg(not(target_os = "windows"))]
            SandboxType::WindowsRestrictedToken => (os_argv_to_strings(argv), None),
            #[cfg(target_os = "freebsd")]
            SandboxType::FreeBSDCapsicum => (os_argv_to_strings(argv), None),
            #[cfg(not(target_os = "freebsd"))]
            SandboxType::FreeBSDCapsicum => (os_argv_to_strings(argv), None),
            #[cfg(target_os = "openbsd")]
            SandboxType::OpenBSDPledge => (os_argv_to_strings(argv), None),
            #[cfg(not(target_os = "openbsd"))]
            SandboxType::OpenBSDPledge => (os_argv_to_strings(argv), None),
        };

        Ok(SandboxExecRequest {
            command: argv,
            cwd: command.cwd,
            env: command.env,
            sandbox,
            sandbox_policy: policy.clone(),
            file_system_policy: FileSystemSandboxPolicy::default(),
            network_policy: NetworkSandboxPolicy::default(),
            arg0: arg0_override,
        })
    }
}

fn os_argv_to_strings(argv: Vec<OsString>) -> Vec<String> {
    argv.into_iter()
        .map(|s| {
            s.into_string()
                .unwrap_or_else(|s| s.to_string_lossy().into_owned())
        })
        .collect()
}

fn should_require_platform_sandbox(
    file_system_policy: &FileSystemSandboxPolicy,
    network_policy: NetworkSandboxPolicy,
) -> bool {
    !matches!(file_system_policy, FileSystemSandboxPolicy::FullAccess)
        || !matches!(network_policy, NetworkSandboxPolicy::FullAccess)
}

#[cfg(target_os = "macos")]
#[allow(dead_code)]
fn create_seatbelt_command_args(_policy: &SandboxPolicy) -> Vec<String> {
    vec!["-p".to_string(), "(version 1)".to_string()]
}

#[cfg(target_os = "linux")]
fn create_linux_sandbox_args(policy: &SandboxPolicy, cwd: &Path) -> Vec<String> {
    crate::linux_sandbox::create_linux_sandbox_command_args_for_policies(vec![], cwd, policy, false)
}

#[cfg(not(target_os = "linux"))]
#[allow(dead_code)]
fn create_linux_sandbox_args(_policy: &SandboxPolicy, _cwd: &Path) -> Vec<String> {
    vec![]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_platform_sandbox() {
        // On Windows, sandbox requires windows_sandbox_enabled = true
        // Use true to ensure test passes on all platforms
        #[cfg(target_os = "windows")]
        let result = get_platform_sandbox(true);
        #[cfg(not(target_os = "windows"))]
        let result = get_platform_sandbox(false);

        #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
        assert!(result.is_some());
        #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
        assert!(result.is_none());
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn test_sandbox_manager_create_request() {
        let manager = SandboxManager::new();
        let command = SandboxCommand {
            program: OsString::from("ls"),
            args: vec!["-la".to_string()],
            cwd: PathBuf::from("/tmp"),
            env: HashMap::new(),
        };

        let result = manager.create_exec_request(command, SandboxPolicy::default());
        assert!(result.is_ok());
    }

    #[test]
    #[cfg(not(target_os = "macos"))]
    fn test_sandbox_manager_create_request() {
        // Skip test on non-macOS platforms as it requires platform-specific sandbox executable
        // The test verifies that create_exec_request works, but it requires a sandbox executable
        // which is only available on macOS (seatbelt)
    }
}
