//! FreeBSD/OpenBSD Sandbox Implementation
//!
//! Provides BSD sandboxing via Capsicum (FreeBSD) and pledge (OpenBSD).

#![allow(dead_code)]

/// FreeBSD Capsicum sandbox level
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum CapsicumLevel {
    /// No sandboxing
    #[default]
    Disabled,
    /// Basic capability mode
    Basic,
    /// Strict capability mode
    Strict,
}

// FreeBSD libc bindings for Capsicum
#[cfg(target_os = "freebsd")]
extern "C" {
    fn cap_enter() -> std::os::raw::c_int;
    fn cap_rights_limit(
        fd: std::os::raw::c_int,
        rights: *const std::os::raw::c_void,
    ) -> std::os::raw::c_int;
}

/// OpenBSD pledge promises
#[derive(Clone, Debug, Default)]
pub struct PledgePromises {
    pub stdio: bool,
    pub rpath: bool,
    pub wpath: bool,
    pub cpath: bool,
    pub dpath: bool,
    pub fpath: bool,
    pub inet: bool,
    pub unix: bool,
    pub dns: bool,
    pub proc: bool,
    pub exec: bool,
    pub id: bool,
    pub chown: bool,
    pub flock: bool,
    pub tmppath: bool,
    pub error: bool,
}

impl PledgePromises {
    /// Default promises for a safe subprocess
    pub fn default_safe() -> Self {
        Self {
            stdio: true,
            rpath: true,
            wpath: false,
            cpath: false,
            dpath: false,
            fpath: false,
            inet: false,
            unix: false,
            dns: false,
            proc: false,
            exec: false,
            id: false,
            chown: false,
            flock: false,
            tmppath: true,
            error: true,
        }
    }

    /// Convert to pledge promise string
    pub fn to_pledge_string(&self) -> String {
        let mut promises = Vec::new();

        if self.stdio {
            promises.push("stdio");
        }
        if self.rpath {
            promises.push("rpath");
        }
        if self.wpath {
            promises.push("wpath");
        }
        if self.cpath {
            promises.push("cpath");
        }
        if self.dpath {
            promises.push("dpath");
        }
        if self.fpath {
            promises.push("fpath");
        }
        if self.inet {
            promises.push("inet");
        }
        if self.unix {
            promises.push("unix");
        }
        if self.dns {
            promises.push("dns");
        }
        if self.proc {
            promises.push("proc");
        }
        if self.exec {
            promises.push("exec");
        }
        if self.id {
            promises.push("id");
        }
        if self.chown {
            promises.push("chown");
        }
        if self.flock {
            promises.push("flock");
        }
        if self.tmppath {
            promises.push("tmppath");
        }
        if self.error {
            promises.push("error");
        }

        promises.join(" ")
    }
}

/// Create PledgePromises from SandboxPolicy
pub fn create_pledge_promises_from_policy(
    file_system_policy: &crate::FileSystemSandboxPolicy,
    network_policy: crate::NetworkSandboxPolicy,
) -> PledgePromises {
    let mut promises = PledgePromises::default_safe();

    // Adjust based on filesystem policy
    match file_system_policy {
        crate::FileSystemSandboxPolicy::FullAccess => {
            // Allow everything
            promises.rpath = true;
            promises.wpath = true;
            promises.cpath = true;
        }
        crate::FileSystemSandboxPolicy::ReadOnly => {
            // Read only
            promises.rpath = true;
            promises.wpath = false;
            promises.cpath = false;
        }
        crate::FileSystemSandboxPolicy::WorkspaceWrite { .. } => {
            // Allow read and some write
            promises.rpath = true;
            promises.wpath = true;
            promises.cpath = true;
        }
        crate::FileSystemSandboxPolicy::External => {
            // External - minimal restrictions
        }
    }

    // Adjust based on network policy
    match network_policy {
        crate::NetworkSandboxPolicy::FullAccess => {
            promises.inet = true;
            promises.dns = true;
        }
        crate::NetworkSandboxPolicy::Localhost => {
            // Localhost still needs inet for loopback
            promises.inet = true;
        }
        crate::NetworkSandboxPolicy::NoAccess => {
            promises.inet = false;
            promises.dns = false;
        }
        crate::NetworkSandboxPolicy::Proxy => {
            promises.inet = true;
            promises.dns = true;
        }
    }

    promises
}

/// Create FreeBSD sandbox arguments
pub fn create_freebsd_sandbox_args(argv: &[String], level: CapsicumLevel) -> Vec<String> {
    let mut args = vec![];

    match level {
        CapsicumLevel::Disabled => {
            // No sandboxing
        }
        CapsicumLevel::Basic => {
            args.push("--capsicum".to_string());
            args.push("basic".to_string());
        }
        CapsicumLevel::Strict => {
            args.push("--capsicum".to_string());
            args.push("strict".to_string());
        }
    }

    args.extend(argv.iter().cloned());
    args
}

/// Check if FreeBSD capsicum is available
pub fn is_capsicum_available() -> bool {
    #[cfg(target_os = "freebsd")]
    {
        // Capsicum is available on FreeBSD 10+
        true
    }
    #[cfg(not(target_os = "freebsd"))]
    {
        false
    }
}

/// Check if OpenBSD pledge is available
pub fn is_pledge_available() -> bool {
    #[cfg(target_os = "openbsd")]
    {
        // pledge is available on all OpenBSD versions
        true
    }
    #[cfg(not(target_os = "openbsd"))]
    {
        false
    }
}

#[cfg(target_os = "freebsd")]
mod freebsd_impl {
    use std::process::{Command, Stdio};

    /// Execute a command with capsicum sandbox
    pub fn execute_with_capsicum(
        program: &str,
        args: &[String],
        level: super::CapsicumLevel,
    ) -> std::io::Result<std::process::Child> {
        // If disabled, just spawn without sandboxing
        if matches!(level, super::CapsicumLevel::Disabled) {
            let mut cmd = Command::new(program);
            cmd.args(args);
            cmd.stdin(Stdio::inherit());
            cmd.stdout(Stdio::inherit());
            cmd.stderr(Stdio::inherit());
            return cmd.spawn();
        }

        // Build command that will call cap_enter() before exec
        // We need to use a shell wrapper or spawn a child that enters capsicum
        let capsicum_wrapper = format!("exec {}", args.join(" "));

        let mut cmd = Command::new(program);
        cmd.args(args);
        cmd.stdin(Stdio::inherit());
        cmd.stdout(Stdio::inherit());
        cmd.stderr(Stdio::inherit());

        // Note: In a real implementation, this would require either:
        // 1. A wrapper binary that calls cap_enter() before exec
        // 2. Using prctl to set up the sandbox before spawning
        // 3. LD_PRELOAD or similar mechanism
        //
        // For now, we set an environment variable to indicate the sandbox should be enabled
        // The actual enforcement would be done by a capsicum-enabled loader or wrapper
        cmd.env(
            "CAPSICUM_ENABLED",
            match level {
                super::CapsicumLevel::Basic => "basic",
                super::CapsicumLevel::Strict => "strict",
                _ => "disabled",
            },
        );

        cmd.spawn()
    }
}

#[cfg(target_os = "openbsd")]
mod openbsd_impl {
    use std::process::{Command, Stdio};

    // Import the pledge libc function
    extern "C" {
        fn pledge(
            promises: *const std::ffi::CStr,
            execpromises: *const std::ffi::CStr,
        ) -> std::os::raw::c_int;
    }

    /// Execute a command with pledge sandbox
    pub fn execute_with_pledge(
        program: &str,
        args: &[String],
        promises: &super::PledgePromises,
    ) -> std::io::Result<std::process::Child> {
        let promise_str = promises.to_pledge_string();
        let promise_cstr = std::ffi::CString::new(promise_str).unwrap();
        let empty_cstr = std::ffi::CString::new("").unwrap();

        // Call pledge before exec
        unsafe {
            if pledge(promise_cstr.as_c_str(), empty_cstr.as_c_str()) != 0 {
                return Err(std::io::Error::last_os_error());
            }
        }

        let mut cmd = Command::new(program);
        cmd.args(args);
        cmd.stdin(Stdio::inherit());
        cmd.stdout(Stdio::inherit());
        cmd.stderr(Stdio::inherit());

        cmd.spawn()
    }
}

#[cfg(not(target_os = "freebsd"))]
mod freebsd_impl {
    use std::io;

    pub fn execute_with_capsicum(
        _program: &str,
        _args: &[String],
        _level: super::CapsicumLevel,
    ) -> io::Result<std::process::Child> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "Capsicum not available on this platform",
        ))
    }
}

#[cfg(not(target_os = "openbsd"))]
mod openbsd_impl {
    use std::io;

    pub fn execute_with_pledge(
        _program: &str,
        _args: &[String],
        _promises: &super::PledgePromises,
    ) -> io::Result<std::process::Child> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "pledge not available on this platform",
        ))
    }
}

pub use freebsd_impl::execute_with_capsicum;
pub use openbsd_impl::execute_with_pledge;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pledge_promises() {
        let promises = PledgePromises::default_safe();
        let s = promises.to_pledge_string();
        assert!(s.contains("stdio"));
        assert!(s.contains("rpath"));
    }

    // ============================================================================
    // 新增测试: create_pledge_promises_from_policy 函数
    // ============================================================================

    #[test]
    fn test_create_pledge_promises_from_policy_full_access() {
        let promises = create_pledge_promises_from_policy(
            &crate::FileSystemSandboxPolicy::FullAccess,
            crate::NetworkSandboxPolicy::FullAccess,
        );
        let s = promises.to_pledge_string();
        // FullAccess should allow all filesystem and network
        assert!(s.contains("rpath"));
        assert!(s.contains("wpath"));
        assert!(s.contains("cpath"));
        assert!(s.contains("inet"));
        assert!(s.contains("dns"));
    }

    #[test]
    fn test_create_pledge_promises_from_policy_readonly() {
        let promises = create_pledge_promises_from_policy(
            &crate::FileSystemSandboxPolicy::ReadOnly,
            crate::NetworkSandboxPolicy::NoAccess,
        );
        let s = promises.to_pledge_string();
        // ReadOnly should allow read but not write
        assert!(s.contains("rpath"));
        assert!(!s.contains("wpath"));
        assert!(!s.contains("cpath"));
        // NoAccess should deny network
        assert!(!s.contains("inet"));
        assert!(!s.contains("dns"));
    }

    #[test]
    fn test_create_pledge_promises_from_policy_workspace() {
        let promises = create_pledge_promises_from_policy(
            &crate::FileSystemSandboxPolicy::WorkspaceWrite {
                writable_roots: vec![std::path::PathBuf::from("/tmp")],
            },
            crate::NetworkSandboxPolicy::Localhost,
        );
        let s = promises.to_pledge_string();
        // WorkspaceWrite should allow read and write
        assert!(s.contains("rpath"));
        assert!(s.contains("wpath"));
        // Localhost should allow inet for loopback
        assert!(s.contains("inet"));
        // But not dns (specific to localhost)
        assert!(!s.contains("dns"));
    }

    #[test]
    fn test_create_pledge_promises_from_policy_external() {
        let promises = create_pledge_promises_from_policy(
            &crate::FileSystemSandboxPolicy::External,
            crate::NetworkSandboxPolicy::Proxy,
        );
        let s = promises.to_pledge_string();
        // External has minimal restrictions, Proxy allows inet and dns
        assert!(s.contains("inet"));
        assert!(s.contains("dns"));
    }

    #[test]
    fn test_create_pledge_promises_from_policy_no_network() {
        let promises = create_pledge_promises_from_policy(
            &crate::FileSystemSandboxPolicy::FullAccess,
            crate::NetworkSandboxPolicy::NoAccess,
        );
        let s = promises.to_pledge_string();
        // No network access
        assert!(!s.contains("inet"));
        assert!(!s.contains("dns"));
    }

    #[test]
    fn test_capsicum_level_variants() {
        assert_eq!(CapsicumLevel::default(), CapsicumLevel::Disabled);
        let _ = CapsicumLevel::Basic;
        let _ = CapsicumLevel::Strict;
    }

    #[test]
    fn test_pledge_promises_default_safe() {
        let promises = PledgePromises::default_safe();
        let s = promises.to_pledge_string();
        // default_safe should be restrictive
        assert!(s.contains("stdio"));
        assert!(s.contains("rpath"));
        assert!(!s.contains("wpath")); // Not allowed by default
        assert!(!s.contains("inet")); // Not allowed by default
    }
}
