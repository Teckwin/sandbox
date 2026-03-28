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
        _level: super::CapsicumLevel,
    ) -> std::io::Result<std::process::Child> {
        let mut cmd = Command::new(program);
        cmd.args(args);
        cmd.stdin(Stdio::inherit());
        cmd.stdout(Stdio::inherit());
        cmd.stderr(Stdio::inherit());
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
}
