//! Linux Landlock capability metadata.
//!
//! Bubblewrap is the active Linux executor. These helpers only report kernel
//! capability metadata; they do not install Landlock rules or enforce policy.

#![allow(dead_code)]

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

/// Describe the access mask a future Landlock executor would need for reads.
pub fn create_readonly_ruleset() -> Option<LandlockRulesetAttr> {
    create_readonly_ruleset_with_availability(is_landlock_available())
}

fn create_readonly_ruleset_with_availability(available: bool) -> Option<LandlockRulesetAttr> {
    if !available {
        return None;
    }

    Some(LandlockRulesetAttr {
        handle_access_fs: landlock_access::READ_ONLY,
    })
}

pub fn create_workspace_ruleset(writable_roots: &[PathBuf]) -> Option<LandlockRulesetAttr> {
    create_workspace_ruleset_with_availability(writable_roots, is_landlock_available())
}

fn create_workspace_ruleset_with_availability(
    writable_roots: &[PathBuf],
    available: bool,
) -> Option<LandlockRulesetAttr> {
    if !available {
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

/// Get the Landlock ABI version.
pub fn get_landlock_version() -> Option<u32> {
    #[cfg(target_os = "linux")]
    {
        std::fs::read_to_string("/proc/sys/kernel/landlock/version")
            .ok()
            .and_then(|version| version.trim().parse().ok())
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_landlock_version() {
        let _ = get_landlock_version();
    }

    #[test]
    fn ruleset_descriptions_follow_kernel_availability_and_roots() {
        assert!(create_readonly_ruleset_with_availability(false).is_none());
        assert!(create_workspace_ruleset_with_availability(&[], false).is_none());

        let readonly = create_readonly_ruleset_with_availability(true).unwrap();
        assert_eq!(readonly.handle_access_fs, landlock_access::READ_ONLY);

        let workspace_readonly = create_workspace_ruleset_with_availability(&[], true).unwrap();
        assert_eq!(
            workspace_readonly.handle_access_fs,
            landlock_access::READ_ONLY
        );

        let writable =
            create_workspace_ruleset_with_availability(&[PathBuf::from("/workspace")], true)
                .unwrap();
        assert_eq!(
            writable.handle_access_fs,
            landlock_access::READ_ONLY | landlock_access::ALL_FILE
        );
    }
}
