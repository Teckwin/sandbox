//! Linux Bubblewrap Integration
//!
//! Provides integration with bubblewrap (bwrap) for Linux process sandboxing.

use std::path::{Path, PathBuf};

/// Bubblewrap executable finder
pub struct BwrapFinder {
    system_path: Option<std::path::PathBuf>,
    vendored_path: Option<std::path::PathBuf>,
}

impl BwrapFinder {
    /// Create a new BwrapFinder
    pub fn new() -> Self {
        #[cfg(target_os = "linux")]
        {
            Self {
                system_path: which("bwrap").ok(),
                vendored_path: None,
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            Self {
                system_path: None,
                vendored_path: None,
            }
        }
    }

    /// Set vendored bubblewrap path
    pub fn with_vendored(mut self, path: std::path::PathBuf) -> Self {
        self.vendored_path = Some(path);
        self
    }

    /// Find the bubblewrap executable
    pub fn find(&self) -> Option<std::path::PathBuf> {
        // Prefer system bwrap
        if let Some(ref path) = self.system_path {
            return Some(path.clone());
        }
        // Fall back to vendored
        self.vendored_path.clone()
    }

    /// Check if bwrap is available
    pub fn is_available(&self) -> bool {
        self.system_path.is_some() || self.vendored_path.is_some()
    }
}

impl Default for BwrapFinder {
    fn default() -> Self {
        Self::new()
    }
}

/// Bubblewrap argument builder
pub struct BwrapArgs {
    args: Vec<String>,
}

impl BwrapArgs {
    /// Create new empty args
    pub fn new() -> Self {
        Self { args: Vec::new() }
    }

    /// Set the working directory
    pub fn cwd(mut self, path: &Path) -> Self {
        self.args.push("--cwd".to_string());
        self.args.push(path.to_string_lossy().to_string());
        self
    }

    /// Mount a directory read-only
    pub fn ro_bind(mut self, source: &Path, target: &Path) -> Self {
        self.args.push("--ro-bind".to_string());
        self.args.push(source.to_string_lossy().to_string());
        self.args.push(target.to_string_lossy().to_string());
        self
    }

    /// Mount a directory read-write
    pub fn rw_bind(mut self, source: &Path, target: &Path) -> Self {
        self.args.push("--rw".to_string());
        self.args.push(source.to_string_lossy().to_string());
        self.args.push(target.to_string_lossy().to_string());
        self
    }

    /// Create a temporary directory
    pub fn tmp_dir(mut self, path: &str) -> Self {
        self.args.push("--tmpfs".to_string());
        self.args.push(path.to_string());
        self
    }

    /// Unshare user namespace
    pub fn unshare_user(mut self) -> Self {
        self.args.push("--unshare-user".to_string());
        self
    }

    /// Unshare IPC namespace
    pub fn unshare_ipc(mut self) -> Self {
        self.args.push("--unshare-ipc".to_string());
        self
    }

    /// Unshare network namespace
    pub fn unshare_net(mut self) -> Self {
        self.args.push("--unshare-net".to_string());
        self
    }

    /// Seccomp filter
    pub fn seccomp(mut self, fd: i32) -> Self {
        self.args.push("--seccomp".to_string());
        self.args.push(fd.to_string());
        self
    }

    /// Add a variable
    pub fn env(mut self, key: &str, value: &str) -> Self {
        self.args.push("--env".to_string());
        self.args.push(format!("{}={}", key, value));
        self
    }

    /// Command separator
    pub fn separator(mut self) -> Self {
        self.args.push("--".to_string());
        self
    }

    /// Add command and arguments
    pub fn command(mut self, argv: Vec<String>) -> Self {
        self.args.extend(argv);
        self
    }

    /// Build the argument vector
    pub fn build(self) -> Vec<String> {
        self.args
    }
}

impl Default for BwrapArgs {
    fn default() -> Self {
        Self::new()
    }
}

/// Create a basic sandboxed bwrap command for read-only access
pub fn create_readonly_bwrap_command(argv: Vec<String>, cwd: &Path) -> Vec<String> {
    BwrapArgs::new()
        .cwd(cwd)
        .ro_bind(Path::new("/"), Path::new("/"))
        .separator()
        .command(argv)
        .build()
}

/// Create a workspace bwrap command
pub fn create_workspace_bwrap_command(
    argv: Vec<String>,
    cwd: &Path,
    writable_roots: &[PathBuf],
) -> Vec<String> {
    let mut args = BwrapArgs::new();
    args = args.cwd(cwd);

    // Add writable roots
    for root in writable_roots {
        args = args.rw_bind(root, root);
    }

    // Mount everything else read-only
    args = args.ro_bind(Path::new("/"), Path::new("/"));

    args.separator().command(argv).build()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bwrap_finder() {
        let finder = BwrapFinder::new();
        let _ = finder.find();
    }

    #[test]
    fn test_bwrap_args() {
        let args = BwrapArgs::new()
            .cwd(Path::new("/tmp"))
            .ro_bind(Path::new("/usr"), Path::new("/usr"))
            .separator()
            .command(vec!["ls".to_string()])
            .build();

        assert!(args.contains(&"--cwd".to_string()));
        assert!(args.contains(&"--ro-bind".to_string()));
    }
}
