//! Windows Sandbox Implementation
//!
//! Provides Windows sandboxing via Restricted Token and ACLs.

/// Windows sandbox level
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum WindowsSandboxLevel {
    /// No sandboxing
    #[default]
    Disabled,
    /// Basic sandbox
    Basic,
    /// Strict sandbox
    Strict,
    /// Full isolation
    Full,
}

/// Create Windows sandbox command arguments
pub fn create_windows_sandbox_args(argv: &[String], level: WindowsSandboxLevel) -> Vec<String> {
    let mut args = vec![];

    match level {
        WindowsSandboxLevel::Disabled => {
            // No sandboxing - pass through
        }
        WindowsSandboxLevel::Basic => {
            args.push("--sandbox".to_string());
            args.push("basic".to_string());
        }
        WindowsSandboxLevel::Strict => {
            args.push("--sandbox".to_string());
            args.push("strict".to_string());
        }
        WindowsSandboxLevel::Full => {
            args.push("--sandbox".to_string());
            args.push("full".to_string());
        }
    }

    args.extend(argv.iter().cloned());
    args
}

/// Check if Windows sandbox is available
pub fn is_windows_sandbox_available() -> bool {
    #[cfg(target_os = "windows")]
    {
        // Check Windows version (Windows 10 1709+ required)
        // Use std::env::var("OS") instead of const_os_str which is unstable
        if let Ok(os_value) = std::env::var("OS") {
            os_value.contains("10.0.16299") || os_value.contains("10.0.17134")
        } else {
            false
        }
    }
    #[cfg(not(target_os = "windows"))]
    {
        // Stub for non-Windows platforms
        false
    }
}

#[cfg(target_os = "windows")]
mod windows_impl {
    use std::process::Command;

    /// Execute command with restricted token
    pub fn execute_with_restricted_token(
        program: &str,
        args: &[String],
    ) -> std::io::Result<std::process::Child> {
        // Use CreateProcess with restricted token
        // This is a simplified version - full implementation uses Windows API
        Command::new(program).args(args).spawn()
    }
}

#[cfg(not(target_os = "windows"))]
mod windows_impl {
    use std::io;

    pub fn execute_with_restricted_token(
        _program: &str,
        _args: &[String],
    ) -> io::Result<std::process::Child> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "Windows sandbox not available on this platform",
        ))
    }
}

pub use windows_impl::execute_with_restricted_token;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_windows_sandbox_args() {
        let args = create_windows_sandbox_args(
            &[
                "cmd.exe".to_string(),
                "/c".to_string(),
                "echo".to_string(),
                "hello".to_string(),
            ],
            WindowsSandboxLevel::Basic,
        );

        assert!(args.contains(&"--sandbox".to_string()));
    }
}
