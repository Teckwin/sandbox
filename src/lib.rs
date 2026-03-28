//! AI Sandbox - Cross-platform AI tool sandbox security
//!
//! A comprehensive sandbox library supporting multiple platforms:
//! - Linux: Bubblewrap + Seccomp + Landlock
//! - macOS: Seatbelt (sandbox-exec)
//! - Windows: Restricted Token
//! - FreeBSD: Capsicum
//! - OpenBSD: pledge
//!
//! # Unified API
//!
//! This crate provides a unified API that works across all supported platforms.
//! Users do not need to write platform-specific code.
//!
//! ## Quick Start
//!
//! ```ignore
//! use ai_sandbox::{SandboxManager, SandboxPolicy, SandboxCommand};
//! use std::collections::HashMap;
//! use std::ffi::OsString;
//! use std::path::PathBuf;
//!
//! // Create sandbox manager - automatically detects platform
//! let manager = SandboxManager::new();
//!
//! // Define your command
//! let command = SandboxCommand {
//!     program: OsString::from("ls"),
//!     args: vec!["-la".to_string()],
//!     cwd: PathBuf::from("/tmp"),
//!     env: HashMap::new(),
//! };
//!
//! // Define sandbox policy
//! let policy = SandboxPolicy::default();
//!
//! // Create sandboxed execution request
//! let request = manager.create_exec_request(command, policy).unwrap();
//! ```

pub mod execpolicy;
pub mod linux_sandbox;
pub mod process_hardening;
pub mod sandboxing;
pub mod windows_sandbox;

// ============================================================================
// Core API - 这些是用户主要使用的接口
// ============================================================================

// 沙箱管理
pub use sandboxing::{
    get_platform_sandbox, FileSystemSandboxPolicy, NetworkSandboxPolicy, SandboxCommand,
    SandboxExecRequest, SandboxManager, SandboxPolicy, SandboxTransformError, SandboxType,
    SandboxablePreference,
};

// 进程加固
pub use process_hardening::pre_main_hardening;

// 执行策略
pub use execpolicy::{parse_policy, Decision, NetworkRule, Policy, PrefixRule, RuleMatch};

// ============================================================================
// Extended API - 高级用户可能需要的接口
// ============================================================================

// Linux 特定功能 - 所有平台都可调用，非 Linux 返回默认值
#[allow(unused_imports)]
pub use linux_sandbox::{
    create_linux_sandbox_command_args_for_policies, execute_with_capsicum, execute_with_pledge,
    find_system_bwrap_in_path, get_landlock_version, is_landlock_available, system_bwrap_warning,
    CapsicumLevel, PledgePromises,
};

// Windows 特定功能 - 所有平台都可调用，非 Windows 返回默认值
#[allow(unused_imports)]
pub use windows_sandbox::{
    create_windows_sandbox_args, is_windows_sandbox_available, WindowsSandboxLevel,
};

#[cfg(test)]
#[allow(unused_imports)]
mod tests {
    use crate::{get_platform_sandbox, SandboxCommand, SandboxManager, SandboxPolicy, SandboxType};
    use std::collections::HashMap;
    use std::ffi::OsString;
    use std::path::PathBuf;

    #[test]
    fn test_platform_detection() {
        let sandbox = get_platform_sandbox(false);
        #[cfg(any(
            target_os = "linux",
            target_os = "macos",
            target_os = "windows",
            target_os = "freebsd",
            target_os = "openbsd"
        ))]
        {
            assert!(sandbox.is_some());
        }
        #[cfg(not(any(
            target_os = "linux",
            target_os = "macos",
            target_os = "windows",
            target_os = "freebsd",
            target_os = "openbsd"
        )))]
        {
            assert!(sandbox.is_none());
        }
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

        let request = result.unwrap();
        assert!(!request.command.is_empty());
    }

    #[test]
    #[cfg(not(target_os = "macos"))]
    fn test_sandbox_manager_create_request() {
        // Skip test on non-macOS platforms as it requires platform-specific sandbox executable
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn test_readonly_policy() {
        let policy = SandboxPolicy::ReadOnly {
            file_system: crate::FileSystemSandboxPolicy::ReadOnly,
            network_access: crate::NetworkSandboxPolicy::NoAccess,
        };

        let manager = SandboxManager::new();
        let command = SandboxCommand {
            program: OsString::from("cat"),
            args: vec!["/etc/passwd".to_string()],
            cwd: PathBuf::from("/tmp"),
            env: HashMap::new(),
        };

        let result = manager.create_exec_request(command, policy);
        assert!(result.is_ok());
    }

    #[test]
    #[cfg(not(target_os = "macos"))]
    fn test_readonly_policy() {
        // Skip test on non-macOS platforms as it requires platform-specific sandbox executable
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn test_workspace_policy() {
        let policy = SandboxPolicy::WorkspaceWrite {
            writable_roots: vec![PathBuf::from("/tmp")],
            network_access: crate::NetworkSandboxPolicy::Localhost,
        };

        let manager = SandboxManager::new();
        let command = SandboxCommand {
            program: OsString::from("touch"),
            args: vec!["test.txt".to_string()],
            cwd: PathBuf::from("/tmp"),
            env: HashMap::new(),
        };

        let result = manager.create_exec_request(command, policy);
        assert!(result.is_ok());
    }

    #[test]
    #[cfg(not(target_os = "macos"))]
    fn test_workspace_policy() {
        // Skip test on non-macOS platforms as it requires platform-specific sandbox executable
    }

    #[test]
    fn test_sandbox_type_names() {
        assert_eq!(SandboxType::None.as_metric_tag(), "none");
        assert_eq!(SandboxType::MacosSeatbelt.as_metric_tag(), "seatbelt");
        assert_eq!(SandboxType::LinuxSeccomp.as_metric_tag(), "seccomp");
        assert_eq!(
            SandboxType::WindowsRestrictedToken.as_metric_tag(),
            "windows_sandbox"
        );
        assert_eq!(SandboxType::FreeBSDCapsicum.as_metric_tag(), "capsicum");
        assert_eq!(SandboxType::OpenBSDPledge.as_metric_tag(), "pledge");
    }
}
