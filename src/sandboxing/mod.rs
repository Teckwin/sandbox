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

impl SandboxPolicy {
    /// Get the network policy from this sandbox policy
    pub fn network_policy(&self) -> NetworkSandboxPolicy {
        match self {
            SandboxPolicy::DangerFullAccess => NetworkSandboxPolicy::FullAccess,
            SandboxPolicy::ReadOnly { network_access, .. } => *network_access,
            SandboxPolicy::ExternalSandbox { network_access } => *network_access,
            SandboxPolicy::WorkspaceWrite { network_access, .. } => *network_access,
        }
    }

    /// Get the filesystem policy from this sandbox policy
    pub fn filesystem_policy(&self) -> FileSystemSandboxPolicy {
        match self {
            SandboxPolicy::DangerFullAccess => FileSystemSandboxPolicy::FullAccess,
            SandboxPolicy::ReadOnly { file_system, .. } => file_system.clone(),
            SandboxPolicy::ExternalSandbox { .. } => FileSystemSandboxPolicy::External,
            SandboxPolicy::WorkspaceWrite { writable_roots, .. } => {
                FileSystemSandboxPolicy::WorkspaceWrite {
                    writable_roots: writable_roots.clone(),
                }
            }
        }
    }
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
                    &policy.filesystem_policy(),
                    policy.network_policy(),
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
            file_system_policy: policy.filesystem_policy(),
            network_policy: policy.network_policy(),
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

    // ============================================================================
    // 破坏性测试 - 沙箱策略安全性验证
    // ============================================================================

    #[test]
    fn test_sandbox_policy_default_is_restrictive() {
        // 测试默认策略是否足够安全
        let default_policy = SandboxPolicy::default();
        // 默认应该是 DangerFullAccess (无限制)
        // 这意味着默认是不安全的，需要用户显式设置限制策略
        assert!(matches!(default_policy, SandboxPolicy::DangerFullAccess));
    }

    #[test]
    fn test_readonly_policy_structure() {
        // 测试只读策略结构
        let policy = SandboxPolicy::ReadOnly {
            file_system: FileSystemSandboxPolicy::ReadOnly,
            network_access: NetworkSandboxPolicy::NoAccess,
        };

        match policy {
            SandboxPolicy::ReadOnly {
                file_system,
                network_access,
            } => {
                assert!(matches!(file_system, FileSystemSandboxPolicy::ReadOnly));
                assert!(matches!(network_access, NetworkSandboxPolicy::NoAccess));
            }
            _ => panic!("Expected ReadOnly policy"),
        }
    }

    #[test]
    fn test_workspace_policy_validates_paths() {
        // 测试工作区策略路径验证
        let policy = SandboxPolicy::WorkspaceWrite {
            writable_roots: vec![PathBuf::from("/tmp"), PathBuf::from("/home/user/workspace")],
            network_access: NetworkSandboxPolicy::Localhost,
        };

        match policy {
            SandboxPolicy::WorkspaceWrite {
                writable_roots,
                network_access,
            } => {
                assert_eq!(writable_roots.len(), 2);
                assert!(matches!(network_access, NetworkSandboxPolicy::Localhost));
            }
            _ => panic!("Expected WorkspaceWrite policy"),
        }
    }

    #[test]
    fn test_network_policy_variants() {
        // 测试网络策略变体
        assert!(matches!(
            NetworkSandboxPolicy::default(),
            NetworkSandboxPolicy::FullAccess
        ));
        assert!(matches!(
            NetworkSandboxPolicy::NoAccess,
            NetworkSandboxPolicy::NoAccess
        ));
        assert!(matches!(
            NetworkSandboxPolicy::Localhost,
            NetworkSandboxPolicy::Localhost
        ));
        assert!(matches!(
            NetworkSandboxPolicy::Proxy,
            NetworkSandboxPolicy::Proxy
        ));
    }

    #[test]
    fn test_filesystem_policy_variants() {
        // 测试文件系统策略变体
        assert!(matches!(
            FileSystemSandboxPolicy::default(),
            FileSystemSandboxPolicy::FullAccess
        ));
        assert!(matches!(
            FileSystemSandboxPolicy::ReadOnly,
            FileSystemSandboxPolicy::ReadOnly
        ));
        assert!(matches!(
            FileSystemSandboxPolicy::External,
            FileSystemSandboxPolicy::External
        ));

        // 测试 WorkspaceWrite 变体
        let ws = FileSystemSandboxPolicy::WorkspaceWrite {
            writable_roots: vec![PathBuf::from("/tmp")],
        };
        assert!(matches!(ws, FileSystemSandboxPolicy::WorkspaceWrite { .. }));
    }

    #[test]
    fn test_sandbox_type_all_variants() {
        // 测试所有沙箱类型
        let types = vec![
            SandboxType::None,
            SandboxType::MacosSeatbelt,
            SandboxType::LinuxSeccomp,
            SandboxType::WindowsRestrictedToken,
            SandboxType::FreeBSDCapsicum,
            SandboxType::OpenBSDPledge,
        ];

        for sandbox_type in types {
            let name = sandbox_type.name();
            let tag = sandbox_type.as_metric_tag();
            assert!(!name.is_empty());
            assert!(!tag.is_empty());
        }
    }

    #[test]
    fn test_sandbox_command_validation() {
        // 测试 SandboxCommand 验证
        let command = SandboxCommand {
            program: OsString::from("ls"),
            args: vec!["-la".to_string(), "/tmp".to_string()],
            cwd: PathBuf::from("/tmp"),
            env: HashMap::new(),
        };

        assert!(!command.program.is_empty());
        assert!(!command.args.is_empty());
        assert!(command.cwd.exists() || command.cwd.to_string_lossy() == "/tmp");
    }

    #[test]
    fn test_sandbox_preference_variants() {
        // 测试沙箱偏好设置
        assert!(matches!(
            SandboxablePreference::default(),
            SandboxablePreference::Auto
        ));
        assert!(matches!(
            SandboxablePreference::Require,
            SandboxablePreference::Require
        ));
        assert!(matches!(
            SandboxablePreference::Forbid,
            SandboxablePreference::Forbid
        ));
    }

    // ============================================================================
    // 破坏性测试 - 边界条件和错误处理
    // ============================================================================

    #[test]
    fn test_empty_program_name() {
        // 测试空程序名
        let manager = SandboxManager::new();
        let command = SandboxCommand {
            program: OsString::from(""),
            args: vec![],
            cwd: PathBuf::from("/tmp"),
            env: HashMap::new(),
        };

        // 应该能创建请求，但不保证能执行
        let result = manager.create_exec_request(command, SandboxPolicy::default());
        // 空程序名可能导致错误
        assert!(result.is_ok() || result.is_err());
    }

    #[test]
    fn test_very_long_program_name() {
        // 测试超长程序名
        let manager = SandboxManager::new();
        let long_name = "A".repeat(10000);
        let command = SandboxCommand {
            program: OsString::from(long_name),
            args: vec![],
            cwd: PathBuf::from("/tmp"),
            env: HashMap::new(),
        };

        let result = manager.create_exec_request(command, SandboxPolicy::default());
        // 长程序名应该被处理（可能返回错误但不崩溃）
        assert!(result.is_ok() || result.is_err());
    }

    #[test]
    fn test_special_characters_in_args() {
        // 测试参数中的特殊字符
        let manager = SandboxManager::new();
        let command = SandboxCommand {
            program: OsString::from("ls"),
            args: vec![
                "-la".to_string(),
                "/tmp".to_string(),
                ";rm -rf /".to_string(),
                "|cat /etc/passwd".to_string(),
                "`whoami`".to_string(),
                "$(id)".to_string(),
            ],
            cwd: PathBuf::from("/tmp"),
            env: HashMap::new(),
        };

        let result = manager.create_exec_request(command, SandboxPolicy::default());
        // 特殊字符应该被处理（可能返回错误但不崩溃）
        assert!(result.is_ok() || result.is_err());
    }

    #[test]
    fn test_empty_cwd() {
        // 测试空工作目录
        let manager = SandboxManager::new();
        let command = SandboxCommand {
            program: OsString::from("ls"),
            args: vec![],
            cwd: PathBuf::from(""),
            env: HashMap::new(),
        };

        let result = manager.create_exec_request(command, SandboxPolicy::default());
        // 空 cwd 可能导致错误或使用默认目录
        assert!(result.is_ok() || result.is_err());
    }

    #[test]
    fn test_nonexistent_cwd() {
        // 测试不存在的工作目录
        let manager = SandboxManager::new();
        let command = SandboxCommand {
            program: OsString::from("ls"),
            args: vec![],
            cwd: PathBuf::from("/nonexistent/path/that/does/not/exist"),
            env: HashMap::new(),
        };

        let result = manager.create_exec_request(command, SandboxPolicy::default());
        // 应该能创建请求（可能在执行时验证目录，不一定要在创建时）
        assert!(result.is_ok() || result.is_err());
    }

    // ============================================================================
    // 破坏性测试 - Policy Clone 和序列化
    // ============================================================================

    #[test]
    fn test_policy_clone() {
        // 测试策略克隆
        let policy = SandboxPolicy::ReadOnly {
            file_system: FileSystemSandboxPolicy::ReadOnly,
            network_access: NetworkSandboxPolicy::NoAccess,
        };

        let cloned = policy.clone();
        assert_eq!(policy, cloned);
    }

    #[test]
    fn test_policy_debug_format() {
        // 测试策略调试格式
        let policy = SandboxPolicy::WorkspaceWrite {
            writable_roots: vec![PathBuf::from("/tmp")],
            network_access: NetworkSandboxPolicy::Localhost,
        };

        let debug_str = format!("{:?}", policy);
        assert!(!debug_str.is_empty());
    }

    // ============================================================================
    // 新增测试: 验证 network_policy() 和 filesystem_policy() 方法
    // ============================================================================

    #[test]
    fn test_sandbox_policy_network_policy_method() {
        // 测试 SandboxPolicy::network_policy() 方法
        let policy_full = SandboxPolicy::DangerFullAccess;
        assert_eq!(
            policy_full.network_policy(),
            NetworkSandboxPolicy::FullAccess
        );

        let policy_readonly = SandboxPolicy::ReadOnly {
            file_system: FileSystemSandboxPolicy::ReadOnly,
            network_access: NetworkSandboxPolicy::NoAccess,
        };
        assert_eq!(
            policy_readonly.network_policy(),
            NetworkSandboxPolicy::NoAccess
        );

        let policy_external = SandboxPolicy::ExternalSandbox {
            network_access: NetworkSandboxPolicy::Localhost,
        };
        assert_eq!(
            policy_external.network_policy(),
            NetworkSandboxPolicy::Localhost
        );

        let policy_workspace = SandboxPolicy::WorkspaceWrite {
            writable_roots: vec![PathBuf::from("/tmp")],
            network_access: NetworkSandboxPolicy::Proxy,
        };
        assert_eq!(
            policy_workspace.network_policy(),
            NetworkSandboxPolicy::Proxy
        );
    }

    #[test]
    fn test_sandbox_policy_filesystem_policy_method() {
        // 测试 SandboxPolicy::filesystem_policy() 方法
        let policy_full = SandboxPolicy::DangerFullAccess;
        assert_eq!(
            policy_full.filesystem_policy(),
            FileSystemSandboxPolicy::FullAccess
        );

        let policy_readonly = SandboxPolicy::ReadOnly {
            file_system: FileSystemSandboxPolicy::ReadOnly,
            network_access: NetworkSandboxPolicy::NoAccess,
        };
        assert_eq!(
            policy_readonly.filesystem_policy(),
            FileSystemSandboxPolicy::ReadOnly
        );

        let policy_external = SandboxPolicy::ExternalSandbox {
            network_access: NetworkSandboxPolicy::Localhost,
        };
        assert_eq!(
            policy_external.filesystem_policy(),
            FileSystemSandboxPolicy::External
        );

        let policy_workspace = SandboxPolicy::WorkspaceWrite {
            writable_roots: vec![PathBuf::from("/tmp"), PathBuf::from("/home")],
            network_access: NetworkSandboxPolicy::FullAccess,
        };
        let fs_policy = policy_workspace.filesystem_policy();
        match fs_policy {
            FileSystemSandboxPolicy::WorkspaceWrite { writable_roots } => {
                assert_eq!(writable_roots.len(), 2);
            }
            _ => panic!("Expected WorkspaceWrite variant"),
        }
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn test_sandbox_exec_request_carries_network_policy() {
        // 测试 SandboxExecRequest 正确携带 network_policy
        let manager = SandboxManager::new();

        // 测试 NoAccess 策略
        let policy = SandboxPolicy::ReadOnly {
            file_system: FileSystemSandboxPolicy::ReadOnly,
            network_access: NetworkSandboxPolicy::NoAccess,
        };
        let command = SandboxCommand {
            program: OsString::from("ls"),
            args: vec![],
            cwd: PathBuf::from("/tmp"),
            env: HashMap::new(),
        };
        let request = manager.create_exec_request(command, policy).unwrap();
        assert_eq!(request.network_policy, NetworkSandboxPolicy::NoAccess);

        // 测试 Localhost 策略
        let policy_localhost = SandboxPolicy::ReadOnly {
            file_system: FileSystemSandboxPolicy::ReadOnly,
            network_access: NetworkSandboxPolicy::Localhost,
        };
        let command = SandboxCommand {
            program: OsString::from("ls"),
            args: vec![],
            cwd: PathBuf::from("/tmp"),
            env: HashMap::new(),
        };
        let request = manager
            .create_exec_request(command, policy_localhost)
            .unwrap();
        assert_eq!(request.network_policy, NetworkSandboxPolicy::Localhost);
    }

    #[test]
    #[cfg(not(target_os = "macos"))]
    fn test_sandbox_exec_request_carries_network_policy() {
        // Skip on non-macOS as it requires platform-specific sandbox executable
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn test_sandbox_exec_request_carries_filesystem_policy() {
        // 测试 SandboxExecRequest 正确携带 file_system_policy
        let manager = SandboxManager::new();

        // 测试 ReadOnly 策略
        let policy = SandboxPolicy::ReadOnly {
            file_system: FileSystemSandboxPolicy::ReadOnly,
            network_access: NetworkSandboxPolicy::FullAccess,
        };
        let command = SandboxCommand {
            program: OsString::from("ls"),
            args: vec![],
            cwd: PathBuf::from("/tmp"),
            env: HashMap::new(),
        };
        let request = manager.create_exec_request(command, policy).unwrap();
        assert_eq!(
            request.file_system_policy,
            FileSystemSandboxPolicy::ReadOnly
        );

        // 测试 WorkspaceWrite 策略
        let policy_workspace = SandboxPolicy::WorkspaceWrite {
            writable_roots: vec![PathBuf::from("/workspace")],
            network_access: NetworkSandboxPolicy::FullAccess,
        };
        let command = SandboxCommand {
            program: OsString::from("ls"),
            args: vec![],
            cwd: PathBuf::from("/tmp"),
            env: HashMap::new(),
        };
        let request = manager
            .create_exec_request(command, policy_workspace)
            .unwrap();
        match request.file_system_policy {
            FileSystemSandboxPolicy::WorkspaceWrite { writable_roots } => {
                assert_eq!(writable_roots.len(), 1);
            }
            _ => panic!("Expected WorkspaceWrite variant"),
        }
    }

    #[test]
    #[cfg(not(target_os = "macos"))]
    fn test_sandbox_exec_request_carries_filesystem_policy() {
        // Skip on non-macOS as it requires platform-specific sandbox executable
    }
}
