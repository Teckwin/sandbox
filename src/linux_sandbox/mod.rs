//! Linux Sandbox Implementation
//!
//! Provides Linux sandboxing via Bubblewrap. Landlock helpers are capability
//! metadata only and are not part of the active executor.

mod bsd;
mod landlock;

pub mod bwrap;

pub use bwrap::BwrapBuildError;

pub use bsd::{
    create_freebsd_sandbox_args, create_pledge_promises_from_policy, execute_with_capsicum,
    execute_with_pledge, is_capsicum_available, is_pledge_available, CapsicumLevel, PledgePromises,
};

pub use landlock::{
    create_readonly_ruleset, create_workspace_ruleset, get_landlock_version, is_landlock_available,
    landlock_access,
};

use crate::SandboxPolicy;
use std::path::PathBuf;
use std::process::{Command, Stdio};

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
    system_bwrap_warning_for(find_system_bwrap_in_path())
}

fn system_bwrap_warning_for(executable: Option<PathBuf>) -> Option<String> {
    if executable.is_none() {
        Some("bubblewrap not found in PATH. Install with: apt install bubblewrap".to_string())
    } else {
        None
    }
}

/// Verify that Bubblewrap can create the namespaces required by the executor.
pub fn ensure_bwrap_support() -> Result<(), String> {
    ensure_bwrap_support_with(Box::new(find_system_bwrap_in_path))
}

fn ensure_bwrap_support_with(find: Box<dyn FnOnce() -> Option<PathBuf>>) -> Result<(), String> {
    ensure_bwrap_support_with_args(find, bwrap::create_support_probe_args())
}

#[cfg(test)]
pub(crate) fn ensure_bwrap_procfs_support() -> Result<(), String> {
    ensure_bwrap_support_with_args(
        Box::new(find_system_bwrap_in_path),
        bwrap::create_support_probe_args_with_procfs(true),
    )
}

fn ensure_bwrap_support_with_args(
    find: Box<dyn FnOnce() -> Option<PathBuf>>,
    args: Vec<String>,
) -> Result<(), String> {
    let executable =
        find().ok_or_else(|| "bubblewrap executable was not found in PATH".to_string())?;
    let status = Command::new(&executable)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|error| format!("failed to probe bubblewrap: {error}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("bubblewrap capability probe exited with {status}"))
    }
}

#[cfg(all(test, unix))]
mod bwrap_support_tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn system_bwrap_warning_matches_injected_availability() {
        assert!(system_bwrap_warning_for(None)
            .unwrap()
            .contains("not found in PATH"));
        assert!(system_bwrap_warning_for(Some(PathBuf::from("/usr/bin/bwrap"))).is_none());
    }

    fn executable_script(body: &str) -> (PathBuf, PathBuf) {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory = std::env::temp_dir().join(format!("ai-sandbox-bwrap-probe-{suffix}"));
        std::fs::create_dir_all(&directory).unwrap();
        let path = directory.join("bwrap");
        std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
        let mut permissions = std::fs::metadata(&path).unwrap().permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&path, permissions).unwrap();
        (path, directory)
    }

    #[test]
    fn bwrap_support_probe_covers_missing_spawn_and_exit_statuses() {
        assert!(ensure_bwrap_support_with(Box::new(|| None))
            .unwrap_err()
            .contains("not found in PATH"));

        let missing = std::env::temp_dir().join("ai-sandbox-no-such-bwrap-executable");
        assert!(ensure_bwrap_support_with(Box::new(|| Some(missing)))
            .unwrap_err()
            .contains("failed to probe bubblewrap"));

        let (success, success_dir) = executable_script("exit 0");
        assert!(ensure_bwrap_support_with(Box::new(|| Some(success))).is_ok());

        let (failure, failure_dir) = executable_script("exit 7");
        assert!(ensure_bwrap_support_with(Box::new(|| Some(failure)))
            .unwrap_err()
            .contains("exited with exit status: 7"));

        std::fs::remove_dir_all(success_dir).unwrap();
        std::fs::remove_dir_all(failure_dir).unwrap();
    }
}

/// Linux sandbox argument builder
pub fn create_linux_sandbox_command_args_for_policies(
    argv: Vec<String>,
    cwd: &std::path::Path,
    policy: &SandboxPolicy,
    _use_legacy_landlock: bool,
) -> Result<Vec<String>, BwrapBuildError> {
    let env = [];
    match policy.filesystem_policy() {
        crate::FileSystemSandboxPolicy::FullAccess => {
            bwrap::create_full_access_bwrap_command(argv, cwd, &env, policy.network_policy())
        }
        crate::FileSystemSandboxPolicy::ReadOnly => {
            bwrap::create_readonly_bwrap_command(argv, cwd, &env, policy.network_policy())
        }
        crate::FileSystemSandboxPolicy::ReadOnlyWithRoots { read_only_roots } => {
            bwrap::create_readonly_bwrap_command_with_roots(
                argv,
                cwd,
                &read_only_roots,
                &env,
                policy.network_policy(),
            )
        }
        crate::FileSystemSandboxPolicy::WorkspaceWrite { writable_roots } => {
            bwrap::create_workspace_bwrap_command(
                argv,
                cwd,
                &writable_roots,
                &env,
                policy.network_policy(),
            )
        }
        crate::FileSystemSandboxPolicy::External => Err(
            BwrapBuildError::UnsupportedFilesystemPolicy("external filesystem sandbox"),
        ),
    }
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
        )
        .unwrap();

        assert!(args.contains(&"--chdir".to_string()));
    }

    #[test]
    fn policy_argument_builder_covers_every_filesystem_policy() {
        use std::time::{SystemTime, UNIX_EPOCH};

        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let base = std::env::temp_dir().join(format!("ai-sandbox-policy-map-{suffix}"));
        let cwd = base.join("workspace");
        let toolchain = base.join("toolchain");
        let writable = base.join("output");
        std::fs::create_dir_all(&cwd).unwrap();
        std::fs::create_dir_all(&toolchain).unwrap();
        std::fs::create_dir_all(&writable).unwrap();

        let policies = [
            SandboxPolicy::DangerFullAccess,
            SandboxPolicy::ReadOnly {
                file_system: FileSystemSandboxPolicy::ReadOnly,
                network_access: NetworkSandboxPolicy::NoAccess,
            },
            SandboxPolicy::ReadOnly {
                file_system: FileSystemSandboxPolicy::ReadOnlyWithRoots {
                    read_only_roots: vec![toolchain],
                },
                network_access: NetworkSandboxPolicy::NoAccess,
            },
            SandboxPolicy::WorkspaceWrite {
                writable_roots: vec![writable],
                network_access: NetworkSandboxPolicy::NoAccess,
            },
        ];
        for policy in policies {
            assert!(create_linux_sandbox_command_args_for_policies(
                vec!["true".into()],
                &cwd,
                &policy,
                false,
            )
            .is_ok());
        }
        assert!(matches!(
            create_linux_sandbox_command_args_for_policies(
                vec!["true".into()],
                &cwd,
                &SandboxPolicy::ExternalSandbox {
                    network_access: NetworkSandboxPolicy::NoAccess,
                },
                false,
            ),
            Err(BwrapBuildError::UnsupportedFilesystemPolicy(_))
        ));

        std::fs::remove_dir_all(base).unwrap();
    }
}
