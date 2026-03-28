//! Linux Landlock Implementation
//!
//! Provides Linux sandboxing via Landlock filesystem sandboxing.

#![allow(dead_code)]

use crate::SandboxPolicy;
use std::path::PathBuf;

/// Landlock ruleset attribute flags
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct LandlockRulesetAttr {
    pub handle_access_fs: u64,
}

/// Landlock access types
pub mod landlock_access {
    pub const EXECUTE: u64 = 1 << 0;
    pub const WRITE_FILE: u64 = 1 << 1;
    pub const READ_FILE: u64 = 1 << 2;
    pub const READ_DIR: u64 = 1 << 3;
    pub const REMOVE_DIR: u64 = 1 << 4;
    pub const REMOVE_FILE: u64 = 1 << 5;
    pub const CREATE_CHAR: u64 = 1 << 6;
    pub const CREATE_DIR: u64 = 1 << 7;
    pub const CREATE_REG: u64 = 1 << 8;
    pub const CREATE_FIFO: u64 = 1 << 9;
    pub const CREATE_SOCK: u64 = 1 << 10;

    /// All file-related accesses
    pub const ALL_FILE: u64 = WRITE_FILE
        | READ_FILE
        | READ_DIR
        | REMOVE_DIR
        | REMOVE_FILE
        | CREATE_CHAR
        | CREATE_DIR
        | CREATE_REG
        | CREATE_FIFO
        | CREATE_SOCK;

    /// Read-only access
    pub const READ_ONLY: u64 = READ_FILE | READ_DIR;
}

/// Check if Landlock is supported on this system
pub fn is_landlock_available() -> bool {
    #[cfg(target_os = "linux")]
    {
        std::path::Path::new("/proc/sys/kernel/landlock/version").exists()
    }
    #[cfg(not(target_os = "linux"))]
    {
        false
    }
}

/// Landlock path descriptor
#[derive(Debug)]
pub struct LandlockPathFd {
    path: PathBuf,
}

impl LandlockPathFd {
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }

    pub fn path(&self) -> &PathBuf {
        &self.path
    }
}

/// Create Landlock ruleset for read-only access
pub fn create_readonly_ruleset() -> Option<LandlockRulesetAttr> {
    if !is_landlock_available() {
        return None;
    }

    Some(LandlockRulesetAttr {
        handle_access_fs: landlock_access::READ_ONLY,
    })
}

/// Create Landlock ruleset for workspace access
pub fn create_workspace_ruleset(writable_roots: &[PathBuf]) -> Option<LandlockRulesetAttr> {
    if !is_landlock_available() {
        return None;
    }

    let mut access = landlock_access::READ_ONLY;

    for _root in writable_roots {
        access |= landlock_access::ALL_FILE;
    }

    Some(LandlockRulesetAttr {
        handle_access_fs: access,
    })
}

/// Get the Landlock ABI version
pub fn get_landlock_version() -> Option<u32> {
    #[cfg(target_os = "linux")]
    {
        std::fs::read_to_string("/proc/sys/kernel/landlock/version")
            .ok()
            .and_then(|v| v.trim().parse().ok())
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}

/// Linux sandbox argument builder with Landlock support
pub fn create_linux_sandbox_command_args(
    argv: Vec<String>,
    cwd: &std::path::Path,
    policy: &super::SandboxPolicy,
    use_landlock_fallback: bool,
) -> Vec<String> {
    let mut args = vec![];

    args.push("--cwd".to_string());
    args.push(cwd.to_string_lossy().to_string());

    let use_landlock = use_landlock_fallback && is_landlock_available();

    if use_landlock {
        args.push("--use-landlock".to_string());
    }

    match policy {
        SandboxPolicy::ReadOnly { .. } => {
            if use_landlock {
                args.push("--landlock-ro".to_string());
            } else {
                args.push("--ro-bind".to_string());
                args.push("/".to_string());
                args.push("/".to_string());
            }
        }
        SandboxPolicy::WorkspaceWrite { writable_roots, .. } => {
            if use_landlock {
                args.push("--landlock-rw".to_string());
                for root in writable_roots {
                    args.push("--landlock-allow-write".to_string());
                    args.push(root.to_string_lossy().to_string());
                }
            } else {
                for root in writable_roots {
                    args.push("--rw".to_string());
                    args.push(root.to_string_lossy().to_string());
                }
                args.push("--ro-bind".to_string());
                args.push("/".to_string());
                args.push("/".to_string());
            }
        }
        SandboxPolicy::DangerFullAccess => {
            if use_landlock {
                args.push("--no-sandbox".to_string());
            }
        }
        _ => {}
    }

    args.push("--".to_string());
    args.extend(argv);

    args
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_landlock_version() {
        let _ = get_landlock_version();
    }
}
