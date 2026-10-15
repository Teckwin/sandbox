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

#[cfg(target_os = "openbsd")]
extern "C" {
    fn pledge(
        promises: *const std::ffi::CStr,
        execpromises: *const std::ffi::CStr,
    ) -> std::os::raw::c_int;
}

trait CapsicumApi {
    fn enter(&self) -> std::io::Result<()>;
}

fn enforce_capsicum(api: &impl CapsicumApi) -> std::io::Result<()> {
    api.enter()
}

#[cfg(target_os = "freebsd")]
struct NativeCapsicumApi;

#[cfg(target_os = "freebsd")]
impl CapsicumApi for NativeCapsicumApi {
    fn enter(&self) -> std::io::Result<()> {
        let result = unsafe { cap_enter() };
        if result == 0 {
            Ok(())
        } else {
            Err(std::io::Error::last_os_error())
        }
    }
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

trait PledgeApi {
    fn pledge(
        &self,
        promises: &std::ffi::CStr,
        execpromises: &std::ffi::CStr,
    ) -> std::io::Result<()>;
}

fn enforce_pledge(api: &impl PledgeApi, promises: &PledgePromises) -> std::io::Result<()> {
    let exec_handoff =
        std::ffi::CString::new("stdio rpath exec").expect("static pledge promises are valid");
    let exec_promises = std::ffi::CString::new(promises.to_pledge_string()).map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid pledge promises")
    })?;
    api.pledge(exec_handoff.as_c_str(), exec_promises.as_c_str())
}

#[cfg(target_os = "openbsd")]
struct NativePledgeApi;

#[cfg(target_os = "openbsd")]
impl PledgeApi for NativePledgeApi {
    fn pledge(
        &self,
        promises: &std::ffi::CStr,
        execpromises: &std::ffi::CStr,
    ) -> std::io::Result<()> {
        let result = unsafe { pledge(promises, execpromises) };
        if result == 0 {
            Ok(())
        } else {
            Err(std::io::Error::last_os_error())
        }
    }
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
            tmppath: false,
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
        crate::FileSystemSandboxPolicy::ReadOnlyWithRoots { .. } => {
            // Pledge cannot express path-scoped reads; deny reads rather than
            // widening this policy to global rpath access.
            promises.rpath = false;
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
            // pledge cannot restrict inet to loopback destinations.
            promises.inet = false;
            promises.dns = false;
        }
        crate::NetworkSandboxPolicy::NoAccess => {
            promises.inet = false;
            promises.dns = false;
        }
        crate::NetworkSandboxPolicy::Proxy => {
            // pledge cannot restrict inet to a configured proxy endpoint.
            promises.inet = false;
            promises.dns = false;
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
    use std::ffi::CString;
    use std::fs::File;
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::process::CommandExt;
    use std::path::PathBuf;
    use std::process::{Command, Stdio};

    extern "C" {
        static mut environ: *mut *mut libc::c_char;
    }

    fn open_executable(program: &str) -> std::io::Result<File> {
        let candidates = if program.contains('/') {
            vec![PathBuf::from(program)]
        } else {
            let path = std::env::var_os("PATH")
                .unwrap_or_else(|| std::ffi::OsString::from("/bin:/usr/bin:/usr/local/bin"));
            std::env::split_paths(&path)
                .map(|directory| directory.join(program))
                .collect()
        };
        let mut last_error = None;
        for candidate in candidates {
            let path = CString::new(candidate.as_os_str().as_bytes()).map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::InvalidInput, "path contains NUL")
            })?;
            let fd = unsafe { libc::open(path.as_ptr(), libc::O_EXEC) };
            if fd >= 0 {
                return Ok(unsafe { File::from_raw_fd(fd) });
            }
            last_error = Some(std::io::Error::last_os_error());
        }
        Err(last_error.unwrap_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::NotFound, "executable not found")
        }))
    }

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

        let executable = open_executable(program)?;
        let executable_fd = executable.as_raw_fd();
        let argv_storage = std::iter::once(program)
            .chain(args.iter().map(String::as_str))
            .map(CString::new)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::InvalidInput, "argument contains NUL")
            })?;
        let argv_pointers = argv_storage
            .iter()
            .map(|argument| argument.as_ptr() as usize)
            .chain(std::iter::once(0))
            .collect::<Vec<_>>()
            .into_boxed_slice();

        let mut cmd = Command::new(program);
        cmd.args(args);
        cmd.stdin(Stdio::inherit());
        cmd.stdout(Stdio::inherit());
        cmd.stderr(Stdio::inherit());

        unsafe {
            cmd.pre_exec(move || {
                let _argv_storage = &argv_storage;
                let flags = libc::fcntl(executable_fd, libc::F_GETFD);
                if flags == -1
                    || libc::fcntl(executable_fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) == -1
                {
                    return Err(std::io::Error::last_os_error());
                }
                super::enforce_capsicum(&super::NativeCapsicumApi)?;
                let argv = argv_pointers.as_ptr() as *const *const libc::c_char;
                let envp = environ as *const *const libc::c_char;
                if libc::fexecve(executable_fd, argv, envp) == -1 {
                    Err(std::io::Error::last_os_error())
                } else {
                    Err(std::io::Error::other("fexecve returned without executing"))
                }
            });
        }

        let result = cmd.spawn();
        drop(executable);
        result
    }
}

#[cfg(target_os = "openbsd")]
mod openbsd_impl {
    use std::os::unix::process::CommandExt;
    use std::process::{Command, Stdio};

    /// Execute a command with pledge sandbox
    pub fn execute_with_pledge(
        program: &str,
        args: &[String],
        promises: &super::PledgePromises,
    ) -> std::io::Result<std::process::Child> {
        let promises = promises.clone();

        let mut cmd = Command::new(program);
        cmd.args(args);
        cmd.stdin(Stdio::inherit());
        cmd.stdout(Stdio::inherit());
        cmd.stderr(Stdio::inherit());

        cmd.pre_exec(move || super::enforce_pledge(&super::NativePledgeApi, &promises));

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
    use std::cell::{Cell, RefCell};
    use std::io;

    struct MockCapsicumApi {
        calls: Cell<usize>,
        fail: bool,
    }

    impl CapsicumApi for MockCapsicumApi {
        fn enter(&self) -> io::Result<()> {
            self.calls.set(self.calls.get() + 1);
            if self.fail {
                Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "mock cap_enter failure",
                ))
            } else {
                Ok(())
            }
        }
    }

    #[derive(Default)]
    struct MockPledgeApi {
        promises: RefCell<Option<String>>,
        execpromises: RefCell<Option<String>>,
        fail: bool,
    }

    impl PledgeApi for MockPledgeApi {
        fn pledge(
            &self,
            promises: &std::ffi::CStr,
            execpromises: &std::ffi::CStr,
        ) -> io::Result<()> {
            *self.promises.borrow_mut() = Some(promises.to_string_lossy().into_owned());
            *self.execpromises.borrow_mut() = Some(execpromises.to_string_lossy().into_owned());
            if self.fail {
                Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "mock pledge failure",
                ))
            } else {
                Ok(())
            }
        }
    }

    #[test]
    fn test_pledge_promises() {
        let promises = PledgePromises::default_safe();
        let s = promises.to_pledge_string();
        assert!(s.contains("stdio"));
        assert!(s.contains("rpath"));
    }

    #[test]
    fn pledge_string_includes_every_enabled_promise() {
        let promises = PledgePromises {
            stdio: true,
            rpath: true,
            wpath: true,
            cpath: true,
            dpath: true,
            fpath: true,
            inet: true,
            unix: true,
            dns: true,
            proc: true,
            exec: true,
            id: true,
            chown: true,
            flock: true,
            tmppath: true,
            error: true,
        };
        assert_eq!(
            promises.to_pledge_string(),
            "stdio rpath wpath cpath dpath fpath inet unix dns proc exec id chown flock tmppath error"
        );
    }

    #[test]
    fn pledge_string_is_empty_when_no_promises_are_enabled() {
        assert_eq!(PledgePromises::default().to_pledge_string(), "");
    }

    #[test]
    fn mock_adapters_accept_successful_enforcement() {
        let capsicum = MockCapsicumApi {
            calls: Cell::new(0),
            fail: false,
        };
        enforce_capsicum(&capsicum).unwrap();
        assert_eq!(capsicum.calls.get(), 1);

        let pledge = MockPledgeApi::default();
        enforce_pledge(&pledge, &PledgePromises::default_safe()).unwrap();
        assert_eq!(
            pledge.promises.borrow().as_deref(),
            Some("stdio rpath exec")
        );
        assert_eq!(
            pledge.execpromises.borrow().as_deref(),
            Some("stdio rpath error")
        );
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
    fn pledge_fails_closed_for_path_scoped_read_only_roots() {
        let promises = create_pledge_promises_from_policy(
            &crate::FileSystemSandboxPolicy::ReadOnlyWithRoots {
                read_only_roots: vec![std::path::PathBuf::from("/workspace")],
            },
            crate::NetworkSandboxPolicy::NoAccess,
        );
        assert!(!promises.rpath);
        assert!(!promises.wpath);
        assert!(!promises.cpath);
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
        // pledge cannot limit inet to loopback, so fail closed.
        assert!(!s.split_whitespace().any(|promise| promise == "inet"));
        assert!(!s.contains("dns"));
    }

    #[test]
    fn test_create_pledge_promises_from_policy_external() {
        let promises = create_pledge_promises_from_policy(
            &crate::FileSystemSandboxPolicy::External,
            crate::NetworkSandboxPolicy::Proxy,
        );
        let s = promises.to_pledge_string();
        // pledge cannot restrict access to the configured proxy endpoint.
        assert!(!s.split_whitespace().any(|promise| promise == "inet"));
        assert!(!s.contains("dns"));
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

    #[test]
    fn mock_capsicum_adapter_calls_and_propagates_failure() {
        let api = MockCapsicumApi {
            calls: Cell::new(0),
            fail: true,
        };

        let error = enforce_capsicum(&api).unwrap_err();

        assert_eq!(api.calls.get(), 1);
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn mock_pledge_adapter_receives_policy_and_propagates_failure() {
        let api = MockPledgeApi {
            promises: RefCell::new(None),
            execpromises: RefCell::new(None),
            fail: true,
        };

        let error = enforce_pledge(&api, &PledgePromises::default_safe()).unwrap_err();

        assert_eq!(api.promises.borrow().as_deref(), Some("stdio rpath exec"));
        assert_eq!(
            api.execpromises.borrow().as_deref(),
            Some("stdio rpath error")
        );
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    }
}

#[cfg(all(test, target_os = "freebsd"))]
mod native_freebsd_tests {
    use super::{execute_with_capsicum, CapsicumLevel};
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn capsicum_command_cannot_create_a_file() {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory = std::env::temp_dir().join(format!("ai-sandbox-capsicum-{suffix}"));
        std::fs::create_dir_all(&directory).unwrap();
        let denied_path = directory.join("denied-write");
        let mut child = execute_with_capsicum(
            "/usr/bin/touch",
            &[denied_path.to_string_lossy().into_owned()],
            CapsicumLevel::Basic,
        )
        .expect("the Capsicum child should execute through its pre-opened descriptor");
        let status = child.wait().unwrap();

        assert_eq!(status.code(), Some(1));
        assert!(!denied_path.exists());
        std::fs::remove_dir_all(directory).unwrap();
    }
}

#[cfg(all(test, target_os = "openbsd"))]
mod native_openbsd_tests {
    use super::{execute_with_pledge, PledgePromises};
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn pledge_command_cannot_create_a_file() {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory = std::env::temp_dir().join(format!("ai-sandbox-pledge-{suffix}"));
        std::fs::create_dir_all(&directory).unwrap();
        let denied_path = directory.join("denied-write");
        let mut child = execute_with_pledge(
            "/usr/bin/touch",
            &[denied_path.to_string_lossy().into_owned()],
            &PledgePromises::default_safe(),
        )
        .expect("the pledge child should complete the exec handoff");
        let status = child.wait().unwrap();

        assert_eq!(status.code(), Some(1));
        assert!(!denied_path.exists());
        std::fs::remove_dir_all(directory).unwrap();
    }
}
