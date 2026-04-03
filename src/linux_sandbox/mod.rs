//! Linux Sandbox Implementation
//!
//! Provides Linux sandboxing via bubblewrap, seccomp, and Landlock.

mod bsd;
mod landlock;

pub mod bwrap;

pub use bsd::{
    create_pledge_promises_from_policy, execute_with_capsicum, execute_with_pledge,
    is_capsicum_available, is_pledge_available, CapsicumLevel, PledgePromises,
};

pub use landlock::{
    create_linux_sandbox_command_args, create_readonly_ruleset, create_workspace_ruleset,
    get_landlock_version, is_landlock_available, landlock_access,
};

use crate::SandboxPolicy;
use std::path::PathBuf;

#[cfg(target_os = "linux")]
use which::which;

/// Find system bubblewrap in PATH
pub fn find_system_bwrap_in_path() -> Option<PathBuf> {
    #[cfg(target_os = "linux")]
    {
        which("bwrap").ok()
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}

/// Get warning message about system bwrap
pub fn system_bwrap_warning() -> Option<String> {
    if find_system_bwrap_in_path().is_none() {
        Some("bubblewrap not found in PATH. Install with: apt install bubblewrap".to_string())
    } else {
        None
    }
}

/// Linux sandbox argument builder
pub fn create_linux_sandbox_command_args_for_policies(
    argv: Vec<String>,
    cwd: &std::path::Path,
    policy: &SandboxPolicy,
    use_legacy_landlock: bool,
) -> Vec<String> {
    landlock::create_linux_sandbox_command_args(argv, cwd, policy, use_legacy_landlock)
}

/// Linux sandbox arg0 constant
pub const CODEX_LINUX_SANDBOX_ARG0: &str = "linux-sandbox";

/// Check if network should be allowed for proxy
pub fn allow_network_for_proxy(enforce_managed_network: bool) -> bool {
    enforce_managed_network
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{FileSystemSandboxPolicy, NetworkSandboxPolicy};

    #[test]
    fn test_create_linux_sandbox_args() {
        let policy = SandboxPolicy::ReadOnly {
            file_system: FileSystemSandboxPolicy::ReadOnly,
            network_access: NetworkSandboxPolicy::FullAccess,
        };

        let args = create_linux_sandbox_command_args_for_policies(
            vec!["ls".to_string(), "-la".to_string()],
            std::path::Path::new("/tmp"),
            &policy,
            false,
        );

        assert!(args.contains(&"--cwd".to_string()));
    }
}
