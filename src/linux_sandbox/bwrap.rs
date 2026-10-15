//! Linux Bubblewrap Integration
//!
//! Provides integration with bubblewrap (bwrap) for Linux process sandboxing.

#[cfg(target_os = "linux")]
use which::which;

use std::collections::HashSet;
use std::path::{Path, PathBuf};

#[derive(Debug, thiserror::Error)]
pub enum BwrapBuildError {
    #[error("bubblewrap cannot enforce network policy {0:?}")]
    UnsupportedNetworkPolicy(crate::NetworkSandboxPolicy),
    #[error("sandbox mount path does not exist: {0}")]
    MissingMountPath(PathBuf),
    #[error("sandbox path is not valid UTF-8: {0}")]
    InvalidMountPath(PathBuf),
    #[error("filesystem root cannot be mounted writable: {0}")]
    WritableFilesystemRoot(PathBuf),
    #[error("filesystem root cannot be exposed as an additional read-only root")]
    ReadOnlyFilesystemRoot,
    #[error("read-only root would expose the workspace parent: {0}")]
    ReadOnlyRootContainsWorkspace(PathBuf),
    #[error("filesystem policy cannot be enforced by Bubblewrap: {0}")]
    UnsupportedFilesystemPolicy(&'static str),
}

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

    /// Set the working directory inside the sandbox.
    pub fn cwd(mut self, path: &Path) -> Self {
        self.args.push("--chdir".to_string());
        self.args.push(path.to_string_lossy().to_string());
        self
    }

    /// Create a directory in the sandbox root filesystem.
    pub fn dir(mut self, path: &Path) -> Self {
        self.args.push("--dir".to_string());
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

    /// Mount a directory read-write.
    pub fn rw_bind(mut self, source: &Path, target: &Path) -> Self {
        self.args.push("--bind".to_string());
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

    /// Mount a device filesystem inside the sandbox.
    pub fn dev(mut self, path: &str) -> Self {
        self.args.push("--dev".to_string());
        self.args.push(path.to_string());
        self
    }

    /// Mount a proc filesystem inside the sandbox.
    pub fn proc(mut self, path: &str) -> Self {
        self.args.push("--proc".to_string());
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

    /// Unshare the process ID namespace.
    pub fn unshare_pid(mut self) -> Self {
        self.args.push("--unshare-pid".to_string());
        self
    }

    /// Unshare network namespace
    pub fn unshare_net(mut self) -> Self {
        self.args.push("--unshare-net".to_string());
        self
    }

    /// Put the sandbox in a new session.
    pub fn new_session(mut self) -> Self {
        self.args.push("--new-session".to_string());
        self
    }

    /// Ensure the sandbox exits when this process exits.
    pub fn die_with_parent(mut self) -> Self {
        self.args.push("--die-with-parent".to_string());
        self
    }

    /// Seccomp filter
    pub fn seccomp(mut self, fd: i32) -> Self {
        self.args.push("--seccomp".to_string());
        self.args.push(fd.to_string());
        self
    }

    /// Clear the inherited environment.
    pub fn clear_env(mut self) -> Self {
        self.args.push("--clearenv".to_string());
        self
    }

    /// Add an explicit environment variable.
    pub fn env(mut self, key: &str, value: &str) -> Self {
        self.args.push("--setenv".to_string());
        self.args.push(key.to_string());
        self.args.push(value.to_string());
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

fn mount_path(path: &Path) -> Result<String, BwrapBuildError> {
    let canonical = path
        .canonicalize()
        .map_err(|_| BwrapBuildError::MissingMountPath(path.to_path_buf()))?;
    canonical
        .to_str()
        .map(str::to_owned)
        .ok_or_else(|| BwrapBuildError::InvalidMountPath(canonical))
}

fn add_system_mounts(args: BwrapArgs) -> BwrapArgs {
    add_system_mounts_with_procfs(args, true)
}

#[cfg(test)]
fn add_system_mounts_with(args: BwrapArgs, path_exists: impl Fn(&Path) -> bool) -> BwrapArgs {
    add_system_mounts_with_procfs_and(args, true, &path_exists)
}

fn add_system_mounts_with_procfs(args: BwrapArgs, mount_procfs: bool) -> BwrapArgs {
    add_system_mounts_with_procfs_and(args, mount_procfs, &|path| path.exists())
}

fn add_system_mounts_with_procfs_and(
    mut args: BwrapArgs,
    mount_procfs: bool,
    path_exists: &dyn Fn(&Path) -> bool,
) -> BwrapArgs {
    for path in ["/usr", "/bin", "/sbin", "/lib", "/lib64", "/etc"] {
        let path = Path::new(path);
        if path_exists(path) {
            args = args.ro_bind(path, path);
        }
    }

    args = args.dev("/dev");
    if mount_procfs {
        args = args.proc("/proc");
    }
    args.tmp_dir("/tmp")
        .tmp_dir("/tmp")
        .tmp_dir("/home")
        .tmp_dir("/root")
        .unshare_user()
        .unshare_pid()
        .unshare_ipc()
        .new_session()
        .die_with_parent()
}

pub(crate) fn create_support_probe_args() -> Vec<String> {
    add_system_mounts_with_procfs(BwrapArgs::new(), false)
        .cwd(Path::new("/usr"))
        .clear_env()
        .separator()
        .command(vec!["/usr/bin/true".into()])
        .build()
}

#[cfg(test)]
pub(crate) fn create_support_probe_args_with_procfs(mount_procfs: bool) -> Vec<String> {
    add_system_mounts_with_procfs(BwrapArgs::new(), mount_procfs)
        .cwd(Path::new("/usr"))
        .clear_env()
        .separator()
        .command(vec!["/usr/bin/true".into()])
        .build()
}

fn add_process_isolation(args: BwrapArgs) -> BwrapArgs {
    args.dev("/dev")
        .proc("/proc")
        .unshare_user()
        .unshare_pid()
        .unshare_ipc()
        .new_session()
        .die_with_parent()
}

/// Create a read-only Bubblewrap command with an isolated temporary directory.
pub fn create_readonly_bwrap_command(
    argv: Vec<String>,
    cwd: &Path,
    env: &[(String, String)],
    network_access: crate::NetworkSandboxPolicy,
) -> Result<Vec<String>, BwrapBuildError> {
    create_readonly_bwrap_command_with_roots(argv, cwd, &[], env, network_access)
}

/// Create a read-only Bubblewrap command with additional explicit read-only roots.
/// The cwd is already mounted read-only; roots inside it are therefore redundant.
pub fn create_readonly_bwrap_command_with_roots(
    argv: Vec<String>,
    cwd: &Path,
    read_only_roots: &[PathBuf],
    env: &[(String, String)],
    network_access: crate::NetworkSandboxPolicy,
) -> Result<Vec<String>, BwrapBuildError> {
    let cwd = mount_path(cwd)?;
    let mut args = add_system_mounts(BwrapArgs::new())
        .ro_bind(Path::new(&cwd), Path::new(&cwd))
        .cwd(Path::new(&cwd))
        .clear_env();
    args = add_read_only_roots(args, read_only_roots, Path::new(&cwd))?;
    args = add_network_policy(args, network_access)?;
    for (key, value) in filtered_environment(env) {
        args = args.env(key, value);
    }
    Ok(args.separator().command(argv).build())
}

/// Create a Bubblewrap command with explicit writable roots.
pub fn create_workspace_bwrap_command(
    argv: Vec<String>,
    cwd: &Path,
    writable_roots: &[PathBuf],
    env: &[(String, String)],
    network_access: crate::NetworkSandboxPolicy,
) -> Result<Vec<String>, BwrapBuildError> {
    let cwd = mount_path(cwd)?;
    let mut args = add_system_mounts(BwrapArgs::new())
        .ro_bind(Path::new(&cwd), Path::new(&cwd))
        .cwd(Path::new(&cwd));

    for root in writable_roots {
        let root = mount_path(root)?;
        if Path::new(&root) == Path::new("/") {
            return Err(BwrapBuildError::WritableFilesystemRoot(PathBuf::from(root)));
        }
        args = args.rw_bind(Path::new(&root), Path::new(&root));
    }

    args = args.clear_env();
    args = add_network_policy(args, network_access)?;
    for (key, value) in filtered_environment(env) {
        args = args.env(key, value);
    }
    Ok(args.separator().command(argv).build())
}

/// Create a Bubblewrap command while preserving full filesystem access.
pub fn create_full_access_bwrap_command(
    argv: Vec<String>,
    cwd: &Path,
    env: &[(String, String)],
    network_access: crate::NetworkSandboxPolicy,
) -> Result<Vec<String>, BwrapBuildError> {
    let cwd = mount_path(cwd)?;
    let mut args = add_process_isolation(
        BwrapArgs::new()
            .rw_bind(Path::new("/"), Path::new("/"))
            .cwd(Path::new(&cwd))
            .clear_env(),
    );
    args = add_network_policy(args, network_access)?;
    for (key, value) in filtered_environment(env) {
        args = args.env(key, value);
    }
    Ok(args.separator().command(argv).build())
}

fn add_network_policy(
    args: BwrapArgs,
    network_access: crate::NetworkSandboxPolicy,
) -> Result<BwrapArgs, BwrapBuildError> {
    match network_access {
        crate::NetworkSandboxPolicy::NoAccess => Ok(args.unshare_net()),
        crate::NetworkSandboxPolicy::FullAccess => Ok(args),
        crate::NetworkSandboxPolicy::Localhost | crate::NetworkSandboxPolicy::Proxy => {
            Err(BwrapBuildError::UnsupportedNetworkPolicy(network_access))
        }
    }
}

fn add_read_only_roots(
    mut args: BwrapArgs,
    roots: &[PathBuf],
    cwd: &Path,
) -> Result<BwrapArgs, BwrapBuildError> {
    let mut canonical_roots = Vec::new();
    for root in roots {
        if !root.is_absolute()
            || root
                .components()
                .any(|component| component == std::path::Component::ParentDir)
        {
            return Err(BwrapBuildError::UnsupportedFilesystemPolicy(
                "read-only roots must be absolute canonical paths",
            ));
        }
        let root = PathBuf::from(mount_path(root)?);
        if root == Path::new("/") {
            return Err(BwrapBuildError::ReadOnlyFilesystemRoot);
        }
        if root == cwd || root.starts_with(cwd) || is_system_mounted(&root) {
            continue;
        }
        if cwd.starts_with(&root) {
            return Err(BwrapBuildError::ReadOnlyRootContainsWorkspace(root));
        }
        canonical_roots.push(root);
    }
    canonical_roots.sort();
    canonical_roots.dedup();

    let mut created_dirs = HashSet::new();
    for root in canonical_roots {
        let mut parents = root.ancestors().skip(1).collect::<Vec<_>>();
        parents.reverse();
        for parent in parents {
            if should_skip_created_parent(parent, cwd) {
                continue;
            }
            if created_dirs.insert(parent.to_path_buf()) {
                args = args.dir(parent);
            }
        }
        args = args.ro_bind(&root, &root);
    }
    Ok(args)
}

fn is_system_mounted(path: &Path) -> bool {
    ["/usr", "/bin", "/sbin", "/lib", "/lib64", "/etc"]
        .iter()
        .any(|root| path == Path::new(root) || path.starts_with(root))
}

fn should_skip_created_parent(parent: &Path, cwd: &Path) -> bool {
    parent == Path::new("/")
        || parent == Path::new("/tmp")
        || parent == Path::new("/home")
        || parent == Path::new("/root")
        || parent == cwd
        || cwd.starts_with(parent)
        || is_system_mounted(parent)
}

fn filtered_environment<'a>(
    env: &'a [(String, String)],
) -> impl Iterator<Item = (&'a str, &'a str)> {
    env.iter().filter_map(|(key, value)| {
        let unsafe_key = key.starts_with("LD_")
            || key.starts_with("DYLD_")
            || matches!(
                key.as_str(),
                "BASH_ENV" | "ENV" | "NODE_OPTIONS" | "PERL5OPT" | "PYTHONINSPECT" | "RUBYOPT"
            );
        (!unsafe_key).then_some((key.as_str(), value.as_str()))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bwrap_finder() {
        let finder = BwrapFinder::new();
        let _ = finder.find();
        let vendored = PathBuf::from("/custom/bwrap");
        let finder = BwrapFinder {
            system_path: None,
            vendored_path: Some(vendored.clone()),
        };
        assert!(finder.is_available());
        assert_eq!(finder.find(), Some(vendored));
        let system = PathBuf::from("/usr/bin/bwrap");
        let finder = BwrapFinder {
            system_path: Some(system.clone()),
            vendored_path: Some(PathBuf::from("/custom/bwrap")),
        };
        assert!(finder.is_available());
        assert_eq!(finder.find(), Some(system));
        assert!(!BwrapFinder {
            system_path: None,
            vendored_path: None,
        }
        .is_available());
    }

    #[test]
    fn test_bwrap_args() {
        let args = BwrapArgs::new()
            .cwd(Path::new("/tmp"))
            .ro_bind(Path::new("/usr"), Path::new("/usr"))
            .separator()
            .command(vec!["ls".to_string()])
            .build();

        assert!(args.contains(&"--chdir".to_string()));
        assert!(args.contains(&"--ro-bind".to_string()));
    }

    #[test]
    fn test_bwrap_uses_supported_argument_names() {
        let args = BwrapArgs::new()
            .cwd(Path::new("/tmp"))
            .rw_bind(Path::new("/tmp"), Path::new("/tmp"))
            .clear_env()
            .env("PATH", "/usr/bin")
            .build();

        assert!(args.contains(&"--chdir".to_string()));
        assert!(args.contains(&"--bind".to_string()));
        assert!(args.contains(&"--clearenv".to_string()));
        assert!(args.contains(&"--setenv".to_string()));
        assert!(!args.contains(&"--cwd".to_string()));
        assert!(!args.contains(&"--rw".to_string()));
        assert!(!args.contains(&"--env".to_string()));
    }

    #[test]
    fn readonly_builder_mounts_configured_roots_and_creates_target_parents() {
        use std::time::{SystemTime, UNIX_EPOCH};

        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let cwd_root = std::env::temp_dir().join(format!("ai-sandbox-cwd-{unique}"));
        let tool_root = std::env::temp_dir().join(format!("ai-sandbox-tool-{unique}"));
        let cwd = cwd_root.join("workspace");
        let toolchain = tool_root.join(".rustup").join("toolchains").join("stable");
        std::fs::create_dir_all(&cwd).unwrap();
        std::fs::create_dir_all(&toolchain).unwrap();

        let args = create_readonly_bwrap_command_with_roots(
            vec!["/usr/bin/true".into()],
            &cwd,
            std::slice::from_ref(&toolchain),
            &[],
            crate::NetworkSandboxPolicy::NoAccess,
        )
        .unwrap();
        let cwd = cwd.canonicalize().unwrap().to_string_lossy().into_owned();
        let toolchain = toolchain
            .canonicalize()
            .unwrap()
            .to_string_lossy()
            .into_owned();
        let tool_parent = tool_root
            .canonicalize()
            .unwrap()
            .to_string_lossy()
            .into_owned();
        assert!(args
            .windows(3)
            .any(|parts| { parts == ["--ro-bind", toolchain.as_str(), toolchain.as_str()] }));
        assert!(args
            .windows(2)
            .any(|parts| { parts == ["--dir", tool_parent.as_str()] }));
        assert!(args
            .windows(3)
            .any(|parts| { parts == ["--ro-bind", cwd.as_str(), cwd.as_str()] }));
        assert!(!args
            .windows(3)
            .any(|parts| { parts == ["--bind", toolchain.as_str(), toolchain.as_str()] }));

        std::fs::remove_dir_all(cwd_root).unwrap();
        std::fs::remove_dir_all(tool_root).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn readonly_builder_handles_sibling_roots_under_home_directory() {
        use std::time::{SystemTime, UNIX_EPOCH};

        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let home = PathBuf::from(std::env::var_os("HOME").expect("HOME must be set for tests"));
        let base = home.join(format!("ai-sandbox-home-roots-{suffix}"));
        let cwd = base.join("workspace");
        let toolchain = base.join("tools").join("stable");
        std::fs::create_dir_all(&cwd).unwrap();
        std::fs::create_dir_all(&toolchain).unwrap();

        let result = create_readonly_bwrap_command_with_roots(
            vec!["/usr/bin/true".into()],
            &cwd,
            std::slice::from_ref(&toolchain),
            &[],
            crate::NetworkSandboxPolicy::NoAccess,
        );
        let expected_toolchain = toolchain
            .canonicalize()
            .unwrap()
            .to_string_lossy()
            .into_owned();
        std::fs::remove_dir_all(&base).unwrap();
        let args = result.unwrap();
        assert!(args.windows(3).any(|parts| {
            parts
                == [
                    "--ro-bind",
                    expected_toolchain.as_str(),
                    expected_toolchain.as_str(),
                ]
        }));
    }

    #[test]
    fn readonly_builder_validates_skips_and_deduplicates_roots() {
        use std::time::{SystemTime, UNIX_EPOCH};

        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("ai-sandbox-roots-{suffix}"));
        let cwd = root.join("workspace");
        let nested = cwd.join("nested");
        let tool_a = root.join("tools").join("a");
        let tool_b = root.join("tools").join("b");
        std::fs::create_dir_all(&nested).unwrap();
        std::fs::create_dir_all(&tool_a).unwrap();
        std::fs::create_dir_all(&tool_b).unwrap();

        let mut roots = vec![
            cwd.clone(),
            nested,
            tool_a.clone(),
            tool_a.clone(),
            tool_b.clone(),
        ];
        #[cfg(unix)]
        roots.push(PathBuf::from("/usr"));
        let args = create_readonly_bwrap_command_with_roots(
            vec!["true".into()],
            &cwd,
            &roots,
            &[],
            crate::NetworkSandboxPolicy::NoAccess,
        )
        .unwrap();
        let tool_a = tool_a
            .canonicalize()
            .unwrap()
            .to_string_lossy()
            .into_owned();
        let tool_b = tool_b
            .canonicalize()
            .unwrap()
            .to_string_lossy()
            .into_owned();
        let shared_parent = root.join("tools").canonicalize().unwrap();
        let shared_parent = shared_parent.to_string_lossy();
        assert_eq!(
            args.windows(3)
                .filter(|parts| *parts == ["--ro-bind", tool_a.as_str(), tool_a.as_str()])
                .count(),
            1
        );
        assert!(args
            .windows(3)
            .any(|parts| parts == ["--ro-bind", tool_b.as_str(), tool_b.as_str()]));
        assert_eq!(
            args.windows(2)
                .filter(|parts| *parts == ["--dir", shared_parent.as_ref()])
                .count(),
            1
        );
        #[cfg(unix)]
        assert_eq!(
            args.windows(3)
                .filter(|parts| *parts == ["--ro-bind", "/usr", "/usr"])
                .count(),
            1
        );

        assert!(matches!(
            create_readonly_bwrap_command_with_roots(
                vec!["true".into()],
                &cwd,
                &[PathBuf::from("relative")],
                &[],
                crate::NetworkSandboxPolicy::NoAccess,
            ),
            Err(BwrapBuildError::UnsupportedFilesystemPolicy(_))
        ));
        assert!(matches!(
            create_readonly_bwrap_command_with_roots(
                vec!["true".into()],
                &cwd,
                &[PathBuf::from("/tmp/../tmp")],
                &[],
                crate::NetworkSandboxPolicy::NoAccess,
            ),
            Err(BwrapBuildError::UnsupportedFilesystemPolicy(_))
        ));
        assert!(matches!(
            create_readonly_bwrap_command_with_roots(
                vec!["true".into()],
                &cwd,
                &[PathBuf::from("/")],
                &[],
                crate::NetworkSandboxPolicy::NoAccess,
            ),
            Err(BwrapBuildError::ReadOnlyFilesystemRoot)
        ));
        assert!(matches!(
            create_readonly_bwrap_command_with_roots(
                vec!["true".into()],
                &cwd,
                std::slice::from_ref(&root),
                &[],
                crate::NetworkSandboxPolicy::NoAccess,
            ),
            Err(BwrapBuildError::ReadOnlyRootContainsWorkspace(_))
        ));
        assert!(matches!(
            create_readonly_bwrap_command_with_roots(
                vec!["true".into()],
                &cwd,
                &[root.join("missing")],
                &[],
                crate::NetworkSandboxPolicy::NoAccess,
            ),
            Err(BwrapBuildError::MissingMountPath(_))
        ));

        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn test_unsupported_network_policies_fail_closed() {
        for network in [
            crate::NetworkSandboxPolicy::Localhost,
            crate::NetworkSandboxPolicy::Proxy,
        ] {
            let error = create_readonly_bwrap_command(
                vec!["true".to_string()],
                Path::new("/tmp"),
                &[],
                network,
            )
            .unwrap_err();
            assert_eq!(
                error.to_string(),
                format!("bubblewrap cannot enforce network policy {network:?}")
            );
        }
        assert!(!matches!(
            create_readonly_bwrap_command(
                vec!["true".to_string()],
                Path::new("/tmp"),
                &[],
                crate::NetworkSandboxPolicy::Localhost,
            ),
            Err(BwrapBuildError::UnsupportedNetworkPolicy(
                crate::NetworkSandboxPolicy::Proxy
            ))
        ));
    }

    #[test]
    fn mount_builders_cover_existing_and_missing_paths_and_environment_filtering() {
        let cwd = std::env::current_dir().unwrap();
        let args = create_readonly_bwrap_command(
            vec!["true".into()],
            &cwd,
            &[
                ("PATH".into(), "/usr/bin".into()),
                ("LD_PRELOAD".into(), "/tmp/inject.so".into()),
                ("DYLD_INSERT_LIBRARIES".into(), "/tmp/inject.dylib".into()),
                ("NODE_OPTIONS".into(), "--require inject".into()),
            ],
            crate::NetworkSandboxPolicy::FullAccess,
        )
        .unwrap();
        assert!(args
            .windows(3)
            .any(|parts| parts == ["--setenv", "PATH", "/usr/bin"]));
        assert!(!has_unsafe_environment_name(&args));
        for key in ["LD_PRELOAD", "DYLD_INSERT_LIBRARIES", "NODE_OPTIONS"] {
            assert!(has_unsafe_environment_name(&[key.to_string()]));
        }

        let empty_workspace = create_workspace_bwrap_command(
            vec!["true".into()],
            &cwd,
            &[],
            &[("PATH".into(), "/usr/bin".into())],
            crate::NetworkSandboxPolicy::NoAccess,
        )
        .unwrap();
        assert!(empty_workspace
            .windows(3)
            .any(|parts| parts == ["--setenv", "PATH", "/usr/bin"]));

        let full_access_workspace = create_workspace_bwrap_command(
            vec!["true".into()],
            &cwd,
            &[],
            &[],
            crate::NetworkSandboxPolicy::FullAccess,
        )
        .unwrap();
        assert!(!full_access_workspace
            .iter()
            .any(|arg| arg == "--unshare-net"));

        let writable_workspace = create_workspace_bwrap_command(
            vec!["true".into()],
            &cwd,
            std::slice::from_ref(&cwd),
            &[],
            crate::NetworkSandboxPolicy::NoAccess,
        )
        .unwrap();
        let canonical_cwd = cwd.canonicalize().unwrap().to_string_lossy().into_owned();
        assert!(writable_workspace
            .windows(3)
            .any(|parts| parts == ["--bind", canonical_cwd.as_str(), canonical_cwd.as_str()]));

        assert!(matches!(
            create_full_access_bwrap_command(
                vec!["true".into()],
                &cwd,
                &[],
                crate::NetworkSandboxPolicy::Localhost,
            ),
            Err(BwrapBuildError::UnsupportedNetworkPolicy(
                crate::NetworkSandboxPolicy::Localhost
            ))
        ));
        assert!(create_full_access_bwrap_command(
            vec!["true".into()],
            &cwd,
            &[],
            crate::NetworkSandboxPolicy::FullAccess,
        )
        .is_ok());
        assert!(matches!(
            create_full_access_bwrap_command(
                vec!["true".into()],
                &cwd,
                &[],
                crate::NetworkSandboxPolicy::Proxy,
            ),
            Err(BwrapBuildError::UnsupportedNetworkPolicy(
                crate::NetworkSandboxPolicy::Proxy
            ))
        ));

        let missing = std::env::temp_dir().join("ai-sandbox-missing-mount-path");
        assert!(matches!(
            create_readonly_bwrap_command(
                vec!["true".into()],
                &missing,
                &[],
                crate::NetworkSandboxPolicy::NoAccess,
            ),
            Err(BwrapBuildError::MissingMountPath(_))
        ));
        assert!(matches!(
            create_workspace_bwrap_command(
                vec!["true".into()],
                &cwd,
                &[missing],
                &[],
                crate::NetworkSandboxPolicy::NoAccess,
            ),
            Err(BwrapBuildError::MissingMountPath(_))
        ));
        assert!(matches!(
            create_workspace_bwrap_command(
                vec!["true".into()],
                &cwd,
                &[PathBuf::from("/")],
                &[],
                crate::NetworkSandboxPolicy::NoAccess,
            ),
            Err(BwrapBuildError::WritableFilesystemRoot(_))
        ));
    }

    fn has_unsafe_environment_name(args: &[String]) -> bool {
        args.iter().any(|arg| {
            arg == "LD_PRELOAD" || arg == "DYLD_INSERT_LIBRARIES" || arg == "NODE_OPTIONS"
        })
    }

    #[test]
    fn injected_mount_predicate_covers_present_and_missing_system_paths() {
        let args = add_system_mounts_with(BwrapArgs::new(), |path| path == Path::new("/usr"));
        let args = args.build();
        assert!(args
            .windows(3)
            .any(|parts| parts == ["--ro-bind", "/usr", "/usr"]));
        assert!(!args
            .windows(3)
            .any(|parts| parts == ["--ro-bind", "/bin", "/bin"]));
    }

    #[test]
    fn bwrap_support_probe_uses_system_baseline_without_procfs() {
        let args = create_support_probe_args();
        assert!(args
            .windows(3)
            .any(|parts| parts == ["--ro-bind", "/usr", "/usr"]));
        assert!(args.contains(&"--dev".to_string()));
        assert!(!args.windows(2).any(|parts| parts == ["--proc", "/proc"]));
        assert_eq!(args.last().map(String::as_str), Some("/usr/bin/true"));

        let procfs_args = create_support_probe_args_with_procfs(true);
        assert!(procfs_args
            .windows(2)
            .any(|parts| parts == ["--proc", "/proc"]));
    }

    #[test]
    fn protected_parent_filter_handles_each_exclusion_and_ordinary_parent() {
        let cwd = Path::new("/workspace/project");
        for parent in [
            Path::new("/"),
            Path::new("/tmp"),
            Path::new("/home"),
            Path::new("/root"),
            cwd,
            Path::new("/workspace"),
            Path::new("/usr"),
            Path::new("/usr/local"),
        ] {
            assert!(should_skip_created_parent(parent, cwd), "{parent:?}");
        }
        assert!(!should_skip_created_parent(Path::new("/opt/tools"), cwd));
    }

    #[cfg(unix)]
    #[test]
    fn test_workspace_write_rejects_symlink_to_filesystem_root() {
        use std::os::unix::fs::symlink;
        use std::time::{SystemTime, UNIX_EPOCH};

        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let base = std::env::temp_dir().join(format!("ai-sandbox-root-link-{suffix}"));
        std::fs::create_dir_all(&base).unwrap();
        let root_link = base.join("workspace");
        symlink("/", &root_link).unwrap();

        let result = create_workspace_bwrap_command(
            vec!["true".to_string()],
            Path::new("/tmp"),
            &[root_link.clone()],
            &[],
            crate::NetworkSandboxPolicy::NoAccess,
        );

        std::fs::remove_file(root_link).unwrap();
        std::fs::remove_dir(base).unwrap();
        assert!(matches!(
            result,
            Err(BwrapBuildError::WritableFilesystemRoot(_))
        ));
    }

    #[cfg(unix)]
    #[test]
    fn non_utf8_mount_paths_are_rejected() {
        use std::os::unix::ffi::OsStringExt;

        let path = std::env::temp_dir().join(std::ffi::OsString::from_vec(vec![b'a', 0xff]));
        std::fs::create_dir_all(&path).unwrap();
        let result = create_readonly_bwrap_command(
            vec!["true".into()],
            &path,
            &[],
            crate::NetworkSandboxPolicy::NoAccess,
        );
        std::fs::remove_dir_all(&path).unwrap();
        assert!(matches!(result, Err(BwrapBuildError::InvalidMountPath(_))));
    }
}
