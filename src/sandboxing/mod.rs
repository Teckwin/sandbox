//! Sandbox Manager - Cross-platform sandbox abstraction

#![allow(dead_code)]

pub mod mxc_config;
pub mod seatbelt;
pub use mxc_config::MxcSandboxConfig;

#[cfg(target_os = "macos")]
pub use seatbelt::MACOS_PATH_TO_SEATBELT_EXECUTABLE;

use std::collections::HashMap;
#[allow(unused_imports)]
use std::ffi::OsString;
use std::path::{Component, Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

/// Platform-specific sandbox types
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum SandboxType {
    /// No sandboxing
    #[default]
    None,
    /// macOS Seatbelt (sandbox-exec)
    MacosSeatbelt,
    /// Linux Bubblewrap namespaces
    LinuxSeccomp,
    /// Windows Restricted Token
    WindowsRestrictedToken,
    /// FreeBSD Capsicum
    FreeBSDCapsicum,
    /// OpenBSD pledge
    OpenBSDPledge,
}

impl SandboxType {
    pub fn as_metric_tag(self) -> &'static str {
        match self {
            SandboxType::None => "none",
            SandboxType::MacosSeatbelt => "seatbelt",
            SandboxType::LinuxSeccomp => "seccomp",
            SandboxType::WindowsRestrictedToken => "windows_sandbox",
            SandboxType::FreeBSDCapsicum => "capsicum",
            SandboxType::OpenBSDPledge => "pledge",
        }
    }

    /// Get the name of this sandbox type
    pub fn name(&self) -> &'static str {
        match self {
            SandboxType::None => "none",
            SandboxType::MacosSeatbelt => "seatbelt",
            SandboxType::LinuxSeccomp => "linux-seccomp",
            SandboxType::WindowsRestrictedToken => "windows-restricted-token",
            SandboxType::FreeBSDCapsicum => "capsicum",
            SandboxType::OpenBSDPledge => "pledge",
        }
    }
}

/// Sandbox preference setting
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum SandboxablePreference {
    /// Automatically select based on platform
    #[default]
    Auto,
    /// Require sandboxing
    Require,
    /// Forbid sandboxing
    Forbid,
}

/// Network sandbox policy
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum NetworkSandboxPolicy {
    /// Full network access
    #[default]
    FullAccess,
    /// No network access
    NoAccess,
    /// Allow localhost only
    Localhost,
    /// Use system proxy
    Proxy,
}

/// File system sandbox policy
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub enum FileSystemSandboxPolicy {
    /// Full filesystem access
    #[default]
    FullAccess,
    /// Read-only access
    ReadOnly,
    /// Read-only access to the working directory and explicitly listed roots.
    ReadOnlyWithRoots { read_only_roots: Vec<PathBuf> },
    /// Workspace-only write access
    WorkspaceWrite {
        /// Allowed writable roots
        writable_roots: Vec<PathBuf>,
    },
    /// External sandbox (no policy applied by us)
    External,
}

/// Sandbox policy definition
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SandboxPolicy {
    /// No sandboxing - full access (deprecated: use ReadOnly as default)
    DangerFullAccess,
    /// Read-only sandbox (安全的默认选项)
    ReadOnly {
        file_system: FileSystemSandboxPolicy,
        network_access: NetworkSandboxPolicy,
    },
    /// External sandbox with network control
    ExternalSandbox {
        network_access: NetworkSandboxPolicy,
    },
    /// Workspace write access
    WorkspaceWrite {
        writable_roots: Vec<PathBuf>,
        network_access: NetworkSandboxPolicy,
    },
}

impl Default for SandboxPolicy {
    /// 默认使用安全的 ReadOnly 策略
    fn default() -> Self {
        SandboxPolicy::ReadOnly {
            file_system: FileSystemSandboxPolicy::ReadOnly,
            network_access: NetworkSandboxPolicy::NoAccess,
        }
    }
}

impl SandboxPolicy {
    /// Get the network policy from this sandbox policy
    pub fn network_policy(&self) -> NetworkSandboxPolicy {
        match self {
            SandboxPolicy::DangerFullAccess => NetworkSandboxPolicy::FullAccess,
            SandboxPolicy::ReadOnly { network_access, .. } => *network_access,
            SandboxPolicy::ExternalSandbox { network_access } => *network_access,
            SandboxPolicy::WorkspaceWrite { network_access, .. } => *network_access,
        }
    }

    /// Get the filesystem policy from this sandbox policy
    pub fn filesystem_policy(&self) -> FileSystemSandboxPolicy {
        match self {
            SandboxPolicy::DangerFullAccess => FileSystemSandboxPolicy::FullAccess,
            SandboxPolicy::ReadOnly { file_system, .. } => file_system.clone(),
            SandboxPolicy::ExternalSandbox { .. } => FileSystemSandboxPolicy::External,
            SandboxPolicy::WorkspaceWrite { writable_roots, .. } => {
                // Security check: if writable_roots is empty, downgrade to ReadOnly
                if writable_roots.is_empty() {
                    FileSystemSandboxPolicy::ReadOnly
                } else {
                    FileSystemSandboxPolicy::WorkspaceWrite {
                        writable_roots: writable_roots.clone(),
                    }
                }
            }
        }
    }

    /// Check if a path contains path traversal attack attempts
    pub fn contains_path_traversal(path: &Path) -> bool {
        let path_str = path.to_string_lossy();

        // Check for ".." pattern
        if path_str.contains("..") {
            return true;
        }

        // Check for "./" or "/." patterns (hidden files or current directory)
        if path_str.contains("/.") || path_str.contains("./") {
            return true;
        }

        false
    }

    /// 验证策略是否安全（用于创建沙箱请求前的检查）
    /// This method is also available via the SandboxPolicyExt trait
    pub fn is_safe(&self) -> bool {
        match self {
            // DangerFullAccess is not secure
            SandboxPolicy::DangerFullAccess => false,
            // The ReadOnly variant must not introduce a more permissive
            // filesystem policy that then selects a writable backend.
            SandboxPolicy::ReadOnly { file_system, .. } => match file_system {
                FileSystemSandboxPolicy::ReadOnly => true,
                FileSystemSandboxPolicy::ReadOnlyWithRoots { read_only_roots } => {
                    !read_only_roots.is_empty()
                        && read_only_roots.iter().all(|path| {
                            path.is_absolute()
                                && path != Path::new("/")
                                && !path
                                    .components()
                                    .any(|component| component == Component::ParentDir)
                        })
                }
                _ => false,
            },
            // ExternalSandbox is not controlled by us, treat as potentially insecure
            SandboxPolicy::ExternalSandbox { .. } => false,
            // WorkspaceWrite must have non-empty writable_roots and no path traversal
            SandboxPolicy::WorkspaceWrite { writable_roots, .. } => {
                if writable_roots.is_empty() {
                    return false;
                }
                if writable_roots
                    .iter()
                    .any(|path| !path.is_absolute() || path == Path::new("/"))
                {
                    return false;
                }
                // Check all paths for path traversal attacks
                !writable_roots
                    .iter()
                    .any(|p| SandboxPolicy::contains_path_traversal(p))
            }
        }
    }
}

/// Trait to extend SandboxPolicy with additional security checks
pub trait SandboxPolicyExt {
    fn is_safe(&self) -> bool;
}

impl SandboxPolicyExt for SandboxPolicy {
    fn is_safe(&self) -> bool {
        SandboxPolicy::is_safe(self)
    }
}
/// A command to be executed with sandboxing
#[derive(Debug)]
pub struct SandboxCommand {
    pub program: OsString,
    pub args: Vec<String>,
    pub cwd: PathBuf,
    pub env: HashMap<String, String>,
}

/// The transformed request ready for execution
#[derive(Debug)]
pub struct SandboxExecRequest {
    pub command: Vec<String>,
    pub cwd: PathBuf,
    pub env: HashMap<String, String>,
    pub sandbox: SandboxType,
    pub sandbox_policy: SandboxPolicy,
    pub file_system_policy: FileSystemSandboxPolicy,
    pub network_policy: NetworkSandboxPolicy,
    pub arg0: Option<String>,
    execution: PreparedExecution,
}

#[derive(Debug)]
struct PreparedExecution {
    command: Vec<String>,
    cwd: PathBuf,
    env: HashMap<String, String>,
    sandbox: SandboxType,
    timeout: Option<Duration>,
}

fn remove_proc_mount(args: &mut Vec<String>) -> Result<(), SandboxTransformError> {
    let separator = args
        .iter()
        .position(|argument| argument == "--")
        .ok_or_else(|| {
            SandboxTransformError::BubblewrapBuild(
                "transformed command is missing the option separator".into(),
            )
        })?;
    let proc_mount = args[..separator]
        .windows(2)
        .position(|pair| pair[0] == "--proc" && pair[1] == "/proc")
        .ok_or_else(|| {
            SandboxTransformError::BubblewrapBuild(
                "transformed command is missing the procfs mount".into(),
            )
        })?;
    args.drain(proc_mount..proc_mount + 2);
    Ok(())
}

fn should_omit_proc_mount(sandbox: SandboxType, mount_procfs: bool) -> bool {
    (sandbox == SandboxType::LinuxSeccomp) & !mount_procfs
}

fn apply_procfs_policy(
    request: &mut SandboxExecRequest,
    mount_procfs: bool,
) -> Result<(), SandboxTransformError> {
    if should_omit_proc_mount(request.sandbox, mount_procfs) {
        remove_proc_mount(&mut request.command)?;
        request.execution.command = request.command.clone();
    }
    Ok(())
}

impl SandboxExecRequest {
    /// Spawn the transformed command through the selected sandbox backend.
    pub fn spawn(&self) -> Result<Child, SandboxExecutionError> {
        if self.execution.command.is_empty() {
            return Err(SandboxExecutionError::InvalidCommand(
                "sandbox command is empty".to_string(),
            ));
        }

        match self.execution.sandbox {
            #[cfg(target_os = "linux")]
            SandboxType::LinuxSeccomp => {
                crate::linux_sandbox::ensure_bwrap_support()
                    .map_err(SandboxExecutionError::Unsupported)?;
                self.spawn_transformed()
            }
            #[cfg(target_os = "macos")]
            SandboxType::MacosSeatbelt => self.spawn_transformed(),
            SandboxType::None => Err(SandboxExecutionError::Unsupported(
                "unprotected execution is not available through SandboxExecRequest".to_string(),
            )),
            _ => Err(SandboxExecutionError::Unsupported(format!(
                "sandbox backend {} has no verified executor on this platform",
                self.sandbox.name()
            ))),
        }
    }

    /// Spawn the transformed command with piped stdin, stdout, and stderr.
    /// The caller owns draining stdout/stderr to avoid blocking the child.
    pub fn spawn_with_stdio(&self) -> Result<Child, SandboxExecutionError> {
        self.spawn_with_stdio_in_group(false)
    }

    /// Spawn the transformed command with piped stdio in a new Unix process
    /// group so the caller can terminate the sandbox wrapper and descendants.
    pub fn spawn_with_stdio_in_process_group(&self) -> Result<Child, SandboxExecutionError> {
        #[cfg(unix)]
        {
            self.spawn_with_stdio_in_group(true)
        }
        #[cfg(not(unix))]
        {
            Err(SandboxExecutionError::Unsupported(
                "separate process groups are unavailable on this platform".into(),
            ))
        }
    }

    fn spawn_with_stdio_in_group(
        &self,
        process_group: bool,
    ) -> Result<Child, SandboxExecutionError> {
        if self.execution.command.is_empty() {
            return Err(SandboxExecutionError::InvalidCommand(
                "sandbox command is empty".to_string(),
            ));
        }

        match self.execution.sandbox {
            #[cfg(target_os = "linux")]
            SandboxType::LinuxSeccomp => {
                crate::linux_sandbox::ensure_bwrap_support()
                    .map_err(SandboxExecutionError::Unsupported)?;
                self.spawn_transformed_with_stdio(process_group)
            }
            #[cfg(target_os = "macos")]
            SandboxType::MacosSeatbelt => self.spawn_transformed_with_stdio(process_group),
            SandboxType::None => Err(SandboxExecutionError::Unsupported(
                "unprotected execution is not available through SandboxExecRequest".to_string(),
            )),
            _ => Err(SandboxExecutionError::Unsupported(format!(
                "sandbox backend {} has no verified executor on this platform",
                self.sandbox.name()
            ))),
        }
    }

    /// Run the transformed command and terminate it when the timeout expires.
    pub fn run(&self, timeout: Duration) -> Result<ExitStatus, SandboxExecutionError> {
        self.run_with_spawn(timeout, Box::new(|request| request.spawn()))
    }

    fn run_with_spawn(
        &self,
        timeout: Duration,
        spawn: Box<dyn FnOnce(&Self) -> Result<Child, SandboxExecutionError>>,
    ) -> Result<ExitStatus, SandboxExecutionError> {
        let timeout = self
            .execution
            .timeout
            .map_or(timeout, |configured| timeout.min(configured));
        let mut child = spawn(self)?;
        let started = Instant::now();

        loop {
            if let Some(status) = child.try_wait().map_err(SandboxExecutionError::Io)? {
                return Ok(status);
            }
            if started.elapsed() >= timeout {
                let _ = child.kill();
                let _ = child.wait();
                return Err(SandboxExecutionError::TimedOut(timeout));
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    /// Spawn the transformed command and wait.
    ///
    /// Requests created from MXC config enforce its `timeout_ms`; legacy
    /// requests without a configured timeout wait without a deadline.
    pub fn wait(&self) -> Result<ExitStatus, SandboxExecutionError> {
        self.wait_with_spawn(Box::new(|request| request.spawn()))
    }

    fn wait_with_spawn(
        &self,
        spawn: Box<dyn FnOnce(&Self) -> Result<Child, SandboxExecutionError>>,
    ) -> Result<ExitStatus, SandboxExecutionError> {
        if let Some(timeout) = self.execution.timeout {
            return self.run_with_spawn(timeout, spawn);
        }
        let mut child = spawn(self)?;
        child.wait().map_err(SandboxExecutionError::Io)
    }

    fn spawn_transformed(&self) -> Result<Child, SandboxExecutionError> {
        self.command_for_spawn()
            .spawn()
            .map_err(SandboxExecutionError::Io)
    }

    fn spawn_transformed_with_stdio(
        &self,
        process_group: bool,
    ) -> Result<Child, SandboxExecutionError> {
        self.command_for_spawn_with_io(true, process_group)
            .spawn()
            .map_err(SandboxExecutionError::Io)
    }

    fn command_for_spawn(&self) -> Command {
        self.command_for_spawn_with_io(false, false)
    }

    fn command_for_spawn_with_stdio(&self) -> Command {
        self.command_for_spawn_with_io(true, false)
    }

    fn command_for_spawn_with_io(&self, piped: bool, process_group: bool) -> Command {
        let mut command = Command::new(&self.execution.command[0]);
        command
            .args(&self.execution.command[1..])
            .current_dir(&self.execution.cwd);
        let stdio = if piped {
            Stdio::piped()
        } else {
            Stdio::inherit()
        };
        command.stdin(stdio).stdout(if piped {
            Stdio::piped()
        } else {
            Stdio::inherit()
        });
        command.stderr(if piped {
            Stdio::piped()
        } else {
            Stdio::inherit()
        });
        command.env_clear();
        #[cfg(unix)]
        if process_group {
            use std::os::unix::process::CommandExt;
            command.process_group(0);
        }
        #[cfg(not(unix))]
        let _ = process_group;
        for (key, value) in &self.execution.env {
            if !is_unsafe_environment_key(key) {
                command.env(key, value);
            }
        }
        command
    }
}

/// Sandbox transformation error
#[derive(Debug)]
pub enum SandboxTransformError {
    InvalidMxcConfig(String),
    BubblewrapUnavailable,
    BubblewrapBuild(String),
    UnprotectedExecution,
    UnsupportedPolicy(String),
    #[cfg(not(target_os = "macos"))]
    SeatbeltUnavailable,
    PlatformNotSupported,
    /// Policy is not safe (e.g., empty writable_roots or path traversal detected)
    UnsafePolicy(String),
}

impl std::fmt::Display for SandboxTransformError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidMxcConfig(reason) => write!(f, "invalid MXC sandbox config: {reason}"),
            Self::BubblewrapUnavailable => write!(f, "bubblewrap executable is unavailable"),
            Self::BubblewrapBuild(reason) => {
                write!(f, "failed to build bubblewrap command: {reason}")
            }
            Self::UnprotectedExecution => {
                write!(
                    f,
                    "unprotected execution is not allowed through the sandbox API"
                )
            }
            Self::UnsupportedPolicy(reason) => {
                write!(f, "sandbox policy is unsupported: {reason}")
            }
            #[cfg(not(target_os = "macos"))]
            Self::SeatbeltUnavailable => write!(f, "seatbelt sandbox is only available on macOS"),
            Self::PlatformNotSupported => write!(f, "sandbox is not supported on this platform"),
            Self::UnsafePolicy(reason) => write!(f, "unsafe policy: {}", reason),
        }
    }
}

impl std::error::Error for SandboxTransformError {}

/// Errors raised while starting or supervising a sandboxed process.
#[derive(Debug, thiserror::Error)]
pub enum SandboxExecutionError {
    #[error("sandbox transformation failed: {0}")]
    Transform(#[from] SandboxTransformError),
    #[error("sandbox execution is unsupported: {0}")]
    Unsupported(String),
    #[error("invalid sandbox command: {0}")]
    InvalidCommand(String),
    #[error("sandbox process I/O failed: {0}")]
    Io(#[source] std::io::Error),
    #[error("sandbox process exceeded timeout of {0:?}")]
    TimedOut(Duration),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum HostPlatform {
    Linux,
    Macos,
    Windows,
    FreeBsd,
    OpenBsd,
    Other,
}

fn current_host_platform() -> HostPlatform {
    #[cfg(target_os = "linux")]
    {
        HostPlatform::Linux
    }
    #[cfg(target_os = "macos")]
    {
        HostPlatform::Macos
    }
    #[cfg(target_os = "windows")]
    {
        HostPlatform::Windows
    }
    #[cfg(target_os = "freebsd")]
    {
        HostPlatform::FreeBsd
    }
    #[cfg(target_os = "openbsd")]
    {
        HostPlatform::OpenBsd
    }
    #[cfg(not(any(
        target_os = "linux",
        target_os = "macos",
        target_os = "windows",
        target_os = "freebsd",
        target_os = "openbsd"
    )))]
    {
        HostPlatform::Other
    }
}

/// Get the appropriate sandbox type for the current platform.
pub fn get_platform_sandbox(windows_sandbox_enabled: bool) -> Option<SandboxType> {
    get_platform_sandbox_for(current_host_platform(), windows_sandbox_enabled)
}

fn get_platform_sandbox_for(
    platform: HostPlatform,
    windows_sandbox_enabled: bool,
) -> Option<SandboxType> {
    match platform {
        HostPlatform::Linux => Some(SandboxType::LinuxSeccomp),
        HostPlatform::Macos => Some(SandboxType::MacosSeatbelt),
        HostPlatform::FreeBsd => Some(SandboxType::FreeBSDCapsicum),
        HostPlatform::OpenBsd => Some(SandboxType::OpenBSDPledge),
        HostPlatform::Windows => {
            if windows_sandbox_enabled {
                Some(SandboxType::WindowsRestrictedToken)
            } else {
                None
            }
        }
        HostPlatform::Other => None,
    }
}

/// Sandbox Manager - creates sandboxed execution requests
#[derive(Default)]
pub struct SandboxManager;

impl SandboxManager {
    pub fn new() -> Self {
        Self
    }

    /// Select initial sandbox type based on preferences
    #[allow(unused_variables)]
    pub fn select_initial(
        &self,
        file_system_policy: &FileSystemSandboxPolicy,
        network_policy: NetworkSandboxPolicy,
        pref: SandboxablePreference,
        windows_sandbox_enabled: bool,
    ) -> SandboxType {
        match pref {
            SandboxablePreference::Forbid => SandboxType::None,
            SandboxablePreference::Require => {
                get_platform_sandbox(windows_sandbox_enabled).unwrap_or(SandboxType::None)
            }
            SandboxablePreference::Auto => {
                let platform_sandbox = get_platform_sandbox(windows_sandbox_enabled);
                // Always use platform sandbox for Auto mode
                platform_sandbox.unwrap_or(SandboxType::None)
            }
        }
    }

    /// Create a sandbox execution request
    pub fn create_exec_request(
        &self,
        command: SandboxCommand,
        policy: SandboxPolicy,
    ) -> Result<SandboxExecRequest, SandboxTransformError> {
        let sandbox = self.select_initial(
            &FileSystemSandboxPolicy::default(),
            NetworkSandboxPolicy::default(),
            SandboxablePreference::Auto,
            cfg!(target_os = "windows"),
        );
        self.create_exec_request_with_sandbox(command, policy, sandbox)
    }

    fn create_exec_request_with_sandbox(
        &self,
        command: SandboxCommand,
        policy: SandboxPolicy,
        sandbox: SandboxType,
    ) -> Result<SandboxExecRequest, SandboxTransformError> {
        if !policy.is_safe() {
            return Err(SandboxTransformError::UnsafePolicy(
                "policy failed safety validation".to_string(),
            ));
        }
        if matches!(sandbox, SandboxType::None) {
            return Err(SandboxTransformError::PlatformNotSupported);
        }
        self.transform_command(command, policy, sandbox, None)
    }

    /// Create an execution request from the MXC policy JSON subset supported
    /// by ai-sandbox. The workload command remains a separate argv value.
    pub fn create_exec_request_from_mxc_json(
        &self,
        command: SandboxCommand,
        config_json: &str,
    ) -> Result<SandboxExecRequest, SandboxTransformError> {
        let config = MxcSandboxConfig::from_json(config_json)?;
        let policy = config.sandbox_policy()?;
        let sandbox = config.sandbox_type()?;
        let mut request = self.transform_command(command, policy, sandbox, None)?;
        request.execution.timeout = Some(config.timeout());
        apply_procfs_policy(&mut request, config.filesystem.mount_procfs)?;
        Ok(request)
    }

    /// Create a read-only sandbox request with explicitly mounted additional roots.
    pub fn create_exec_request_with_read_only_roots(
        &self,
        command: SandboxCommand,
        policy: SandboxPolicy,
        mut read_only_roots: Vec<PathBuf>,
    ) -> Result<SandboxExecRequest, SandboxTransformError> {
        let SandboxPolicy::ReadOnly {
            file_system: FileSystemSandboxPolicy::ReadOnly,
            network_access,
        } = policy
        else {
            return Err(SandboxTransformError::UnsupportedPolicy(
                "additional read-only roots require a ReadOnly policy".into(),
            ));
        };
        if !command.cwd.is_absolute() {
            return Err(SandboxTransformError::UnsafePolicy(
                "read-only sandbox cwd must be absolute".into(),
            ));
        }
        read_only_roots.push(command.cwd.clone());
        self.create_exec_request(
            command,
            SandboxPolicy::ReadOnly {
                file_system: FileSystemSandboxPolicy::ReadOnlyWithRoots { read_only_roots },
                network_access,
            },
        )
    }

    /// Transform a command for sandbox execution
    pub fn transform_command(
        &self,
        command: SandboxCommand,
        policy: SandboxPolicy,
        sandbox: SandboxType,
        _linux_sandbox_exe: Option<&Path>,
    ) -> Result<SandboxExecRequest, SandboxTransformError> {
        let SandboxCommand {
            program,
            args,
            cwd,
            env,
        } = command;
        let (policy, cwd) = normalize_read_only_roots(policy, &cwd)?;
        if !policy.is_safe() {
            return Err(SandboxTransformError::UnsafePolicy(
                "policy failed safety validation".to_string(),
            ));
        }
        let argv: Vec<OsString> = std::iter::once(program)
            .chain(args.iter().map(OsString::from))
            .collect();
        let argv = os_argv_to_strings(argv);
        let _env_pairs: Vec<(String, String)> = env
            .iter()
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect();
        #[cfg(any(target_os = "windows", target_os = "freebsd", target_os = "openbsd"))]
        let _ = (&cwd, &argv);

        let (argv, arg0_override): (Vec<String>, Option<String>) = match sandbox {
            SandboxType::None => Err(SandboxTransformError::UnprotectedExecution),
            #[cfg(target_os = "macos")]
            SandboxType::MacosSeatbelt => {
                let args = crate::sandboxing::seatbelt::create_seatbelt_command_args_for_policies(
                    argv,
                    &policy.filesystem_policy(),
                    policy.network_policy(),
                    &cwd,
                    false,
                    None,
                )
                .map_err(|error| SandboxTransformError::UnsupportedPolicy(error.to_string()))?;
                let mut full_command = vec![MACOS_PATH_TO_SEATBELT_EXECUTABLE.to_string()];
                full_command.extend(args);
                Ok((full_command, None))
            }
            #[cfg(not(target_os = "macos"))]
            SandboxType::MacosSeatbelt => Err(SandboxTransformError::SeatbeltUnavailable),
            #[cfg(target_os = "linux")]
            SandboxType::LinuxSeccomp => {
                let exe = crate::linux_sandbox::find_system_bwrap_in_path()
                    .ok_or(SandboxTransformError::BubblewrapUnavailable)?;
                let args = create_linux_bwrap_args(&argv, &cwd, &_env_pairs, &policy)?;
                let mut full_command = vec![exe.to_string_lossy().to_string()];
                full_command.extend(args);
                Ok((full_command, Some("bwrap".to_string())))
            }
            #[cfg(not(target_os = "linux"))]
            SandboxType::LinuxSeccomp => Err(SandboxTransformError::PlatformNotSupported),
            SandboxType::WindowsRestrictedToken
            | SandboxType::FreeBSDCapsicum
            | SandboxType::OpenBSDPledge => Err(SandboxTransformError::PlatformNotSupported),
        }?;

        Ok(SandboxExecRequest {
            command: argv.clone(),
            cwd: cwd.clone(),
            env: env.clone(),
            sandbox,
            sandbox_policy: policy.clone(),
            file_system_policy: policy.filesystem_policy(),
            network_policy: policy.network_policy(),
            arg0: arg0_override,
            execution: PreparedExecution {
                command: argv,
                cwd,
                env,
                sandbox,
                timeout: None,
            },
        })
    }
}

fn normalize_read_only_roots(
    policy: SandboxPolicy,
    cwd: &Path,
) -> Result<(SandboxPolicy, PathBuf), SandboxTransformError> {
    let SandboxPolicy::ReadOnly {
        file_system: FileSystemSandboxPolicy::ReadOnlyWithRoots { read_only_roots },
        network_access,
    } = policy
    else {
        return Ok((policy, cwd.to_path_buf()));
    };

    let canonical_cwd = cwd
        .canonicalize()
        .map_err(|error| SandboxTransformError::UnsafePolicy(format!("invalid cwd: {error}")))?;
    let mut canonical_roots = vec![canonical_cwd.clone()];
    for root in read_only_roots {
        if !root.is_absolute()
            || root == Path::new("/")
            || root
                .components()
                .any(|component| component == Component::ParentDir)
        {
            return Err(SandboxTransformError::UnsafePolicy(format!(
                "invalid read-only root: {}",
                root.display()
            )));
        }
        let root = root.canonicalize().map_err(|error| {
            SandboxTransformError::UnsafePolicy(format!(
                "unable to canonicalize read-only root {}: {error}",
                root.display()
            ))
        })?;
        if root == Path::new("/") {
            return Err(SandboxTransformError::UnsafePolicy(
                "filesystem root cannot be an additional read-only mount".into(),
            ));
        }
        if canonical_cwd.starts_with(&root) && canonical_cwd != root {
            return Err(SandboxTransformError::UnsafePolicy(format!(
                "read-only root {} contains the working directory",
                root.display()
            )));
        }
        if root != canonical_cwd && !root.starts_with(&canonical_cwd) {
            canonical_roots.push(root);
        }
    }
    canonical_roots.sort();
    canonical_roots.dedup();

    Ok((
        SandboxPolicy::ReadOnly {
            file_system: FileSystemSandboxPolicy::ReadOnlyWithRoots {
                read_only_roots: canonical_roots,
            },
            network_access,
        },
        canonical_cwd,
    ))
}

fn os_argv_to_strings(argv: Vec<OsString>) -> Vec<String> {
    argv.into_iter()
        .map(|s| {
            s.into_string()
                .unwrap_or_else(|s| s.to_string_lossy().into_owned())
        })
        .collect()
}

fn is_unsafe_environment_key(key: &str) -> bool {
    key.starts_with("LD_")
        || key.starts_with("DYLD_")
        || matches!(
            key,
            "BASH_ENV" | "ENV" | "NODE_OPTIONS" | "PERL5OPT" | "PYTHONINSPECT" | "RUBYOPT"
        )
}

fn should_require_platform_sandbox(
    file_system_policy: &FileSystemSandboxPolicy,
    network_policy: NetworkSandboxPolicy,
) -> bool {
    !matches!(file_system_policy, FileSystemSandboxPolicy::FullAccess)
        || !matches!(network_policy, NetworkSandboxPolicy::FullAccess)
}

#[cfg(target_os = "macos")]
#[allow(dead_code)]
fn create_seatbelt_command_args(_policy: &SandboxPolicy) -> Vec<String> {
    vec!["-p".to_string(), "(version 1)".to_string()]
}

#[cfg(target_os = "linux")]
fn create_linux_bwrap_args(
    argv: &[String],
    cwd: &Path,
    env: &[(String, String)],
    policy: &SandboxPolicy,
) -> Result<Vec<String>, SandboxTransformError> {
    let result = match policy.filesystem_policy() {
        FileSystemSandboxPolicy::FullAccess => {
            crate::linux_sandbox::bwrap::create_full_access_bwrap_command(
                argv.to_vec(),
                cwd,
                env,
                policy.network_policy(),
            )
        }
        FileSystemSandboxPolicy::ReadOnly => {
            crate::linux_sandbox::bwrap::create_readonly_bwrap_command(
                argv.to_vec(),
                cwd,
                env,
                policy.network_policy(),
            )
        }
        FileSystemSandboxPolicy::ReadOnlyWithRoots { read_only_roots } => {
            crate::linux_sandbox::bwrap::create_readonly_bwrap_command_with_roots(
                argv.to_vec(),
                cwd,
                &read_only_roots,
                env,
                policy.network_policy(),
            )
        }
        FileSystemSandboxPolicy::WorkspaceWrite { writable_roots } => {
            crate::linux_sandbox::bwrap::create_workspace_bwrap_command(
                argv.to_vec(),
                cwd,
                &writable_roots,
                env,
                policy.network_policy(),
            )
        }
        FileSystemSandboxPolicy::External => {
            return Err(SandboxTransformError::UnsafePolicy(
                "external filesystem policy cannot be enforced by the Linux backend".to_string(),
            ))
        }
    };
    result.map_err(|error| SandboxTransformError::BubblewrapBuild(error.to_string()))
}

#[cfg(not(target_os = "linux"))]
#[allow(dead_code)]
fn create_linux_sandbox_args(_policy: &SandboxPolicy, _cwd: &Path) -> Vec<String> {
    vec![]
}

#[cfg(test)]
#[allow(clippy::assertions_on_constants)]
mod tests {
    use super::*;

    fn run_if_bwrap_supported(support: Result<(), String>, test: Box<dyn FnOnce()>) {
        match support {
            Ok(()) => test(),
            Err(error) => eprintln!("skipping Bubblewrap runtime test: {error}"),
        }
    }

    #[test]
    fn bwrap_capability_gate_covers_run_and_skip_outcomes() {
        let ran = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let ran_in_test = std::sync::Arc::clone(&ran);
        run_if_bwrap_supported(
            Ok(()),
            Box::new(move || ran_in_test.store(true, std::sync::atomic::Ordering::Relaxed)),
        );
        assert!(ran.load(std::sync::atomic::Ordering::Relaxed));
        run_if_bwrap_supported(
            Err("unsupported test capability".into()),
            Box::new(|| panic!("unsupported Bubblewrap test body must not run")),
        );
    }

    #[test]
    fn mutated_public_request_fields_cannot_change_spawned_command() {
        let mut env = HashMap::new();
        env.insert("PLAN_VALUE".to_string(), "original".to_string());
        let mut request = SandboxExecRequest {
            command: vec!["/bin/true".to_string()],
            cwd: PathBuf::from("/"),
            env: env.clone(),
            sandbox: SandboxType::LinuxSeccomp,
            sandbox_policy: SandboxPolicy::default(),
            file_system_policy: FileSystemSandboxPolicy::ReadOnly,
            network_policy: NetworkSandboxPolicy::NoAccess,
            arg0: None,
            execution: PreparedExecution {
                command: vec!["/usr/bin/printf".to_string(), "safe".to_string()],
                cwd: PathBuf::from("/"),
                env,
                sandbox: SandboxType::LinuxSeccomp,
                timeout: None,
            },
        };

        request.command = vec![
            "/bin/sh".to_string(),
            "-c".to_string(),
            "unsafe".to_string(),
        ];
        request.cwd = PathBuf::from("/tmp");
        request.env.clear();
        request.sandbox = SandboxType::None;

        let command = request.command_for_spawn();
        assert_eq!(
            command.get_program(),
            std::ffi::OsStr::new("/usr/bin/printf")
        );
        assert_eq!(
            command.get_args().collect::<Vec<_>>(),
            vec![std::ffi::OsStr::new("safe")]
        );
        assert_eq!(
            command
                .get_envs()
                .find(|(key, _)| *key == std::ffi::OsStr::new("PLAN_VALUE"))
                .and_then(|(_, value)| value),
            Some(std::ffi::OsStr::new("original"))
        );
        assert_eq!(request.execution.sandbox, SandboxType::LinuxSeccomp);
    }

    #[test]
    fn procfs_removal_only_changes_bubblewrap_options_before_separator() {
        let mut args = vec![
            "bwrap".into(),
            "--proc".into(),
            "/proc".into(),
            "--".into(),
            "/usr/bin/printf".into(),
            "--proc".into(),
            "/proc".into(),
        ];
        remove_proc_mount(&mut args).unwrap();
        assert_eq!(args, ["bwrap", "--", "/usr/bin/printf", "--proc", "/proc"]);
    }

    #[test]
    fn procfs_removal_fails_closed_when_bwrap_shape_is_unrecognized() {
        assert!(matches!(
            remove_proc_mount(&mut vec!["bwrap".into(), "--proc".into(), "/proc".into()]),
            Err(SandboxTransformError::BubblewrapBuild(_))
        ));
        assert!(matches!(
            remove_proc_mount(&mut vec!["bwrap".into(), "--".into(), "true".into()]),
            Err(SandboxTransformError::BubblewrapBuild(_))
        ));
    }

    #[test]
    fn procfs_selection_omits_only_for_linux_without_explicit_mount() {
        assert!(should_omit_proc_mount(SandboxType::LinuxSeccomp, false));
        assert!(!should_omit_proc_mount(SandboxType::LinuxSeccomp, true));
        assert!(!should_omit_proc_mount(SandboxType::MacosSeatbelt, false));
    }

    #[test]
    fn procfs_request_mutation_covers_omit_mount_and_other_backend() {
        let mut omitted = request_for_process_tests("true", SandboxType::LinuxSeccomp);
        omitted.command = vec![
            "bwrap".into(),
            "--proc".into(),
            "/proc".into(),
            "--".into(),
            "true".into(),
        ];
        omitted.execution.command = omitted.command.clone();
        apply_procfs_policy(&mut omitted, false).unwrap();
        assert!(!omitted
            .command
            .windows(2)
            .any(|pair| pair == ["--proc", "/proc"]));
        assert_eq!(omitted.execution.command, omitted.command);

        let mut mounted = request_for_process_tests("true", SandboxType::LinuxSeccomp);
        mounted.command = vec![
            "bwrap".into(),
            "--proc".into(),
            "/proc".into(),
            "--".into(),
            "true".into(),
        ];
        mounted.execution.command = mounted.command.clone();
        apply_procfs_policy(&mut mounted, true).unwrap();
        assert!(mounted
            .command
            .windows(2)
            .any(|pair| pair == ["--proc", "/proc"]));

        let mut seatbelt = request_for_process_tests("true", SandboxType::MacosSeatbelt);
        seatbelt.command = vec!["sandbox-exec".into(), "--".into(), "true".into()];
        seatbelt.execution.command = seatbelt.command.clone();
        apply_procfs_policy(&mut seatbelt, false).unwrap();
        assert_eq!(seatbelt.command[0], "sandbox-exec");
    }

    fn request_for_process_tests(program: &str, sandbox: SandboxType) -> SandboxExecRequest {
        SandboxExecRequest {
            command: vec![program.to_string()],
            cwd: std::env::current_dir().unwrap(),
            env: HashMap::new(),
            sandbox,
            sandbox_policy: SandboxPolicy::default(),
            file_system_policy: FileSystemSandboxPolicy::ReadOnly,
            network_policy: NetworkSandboxPolicy::NoAccess,
            arg0: None,
            execution: PreparedExecution {
                command: vec![program.to_string()],
                cwd: std::env::current_dir().unwrap(),
                env: HashMap::new(),
                sandbox,
                timeout: None,
            },
        }
    }

    fn timed_out_duration(result: Result<ExitStatus, SandboxExecutionError>) -> Option<Duration> {
        match result {
            Err(SandboxExecutionError::TimedOut(timeout)) => Some(timeout),
            _ => None,
        }
    }

    #[test]
    fn timeout_classifier_covers_timed_out_and_other_results() {
        let timeout = Duration::from_millis(25);
        assert_eq!(
            timed_out_duration(Err(SandboxExecutionError::TimedOut(timeout))),
            Some(timeout)
        );
        assert_eq!(
            timed_out_duration(Err(SandboxExecutionError::Unsupported("other".into()))),
            None
        );
    }

    fn sandbox_command_for_mxc_config_tests() -> SandboxCommand {
        SandboxCommand {
            program: OsString::from("true"),
            args: Vec::new(),
            cwd: std::env::current_dir().unwrap(),
            env: HashMap::new(),
        }
    }

    #[test]
    fn manager_mxc_json_rejects_parse_and_unrepresentable_policy_errors() {
        let manager = SandboxManager::new();
        assert!(matches!(
            manager.create_exec_request_from_mxc_json(sandbox_command_for_mxc_config_tests(), "{"),
            Err(SandboxTransformError::InvalidMxcConfig(_))
        ));
        assert!(matches!(
            manager.create_exec_request_from_mxc_json(
                sandbox_command_for_mxc_config_tests(),
                r#"{"filesystem":{"denied_paths":["/secret"]}}"#
            ),
            Err(SandboxTransformError::UnsupportedPolicy(_))
        ));
    }

    #[test]
    fn manager_creation_fails_closed_for_unsafe_policy_and_no_sandbox() {
        let manager = SandboxManager::new();
        let command = sandbox_command_for_mxc_config_tests();
        assert!(matches!(
            manager.create_exec_request_with_sandbox(
                command,
                SandboxPolicy::default(),
                SandboxType::None
            ),
            Err(SandboxTransformError::PlatformNotSupported)
        ));
        assert!(matches!(
            manager.create_exec_request_with_sandbox(
                sandbox_command_for_mxc_config_tests(),
                SandboxPolicy::DangerFullAccess,
                SandboxType::LinuxSeccomp
            ),
            Err(SandboxTransformError::UnsafePolicy(_))
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn manager_mxc_json_rejects_foreign_containment_before_transform() {
        assert!(matches!(
            SandboxManager::new().create_exec_request_from_mxc_json(
                sandbox_command_for_mxc_config_tests(),
                r#"{"containment":"seatbelt"}"#
            ),
            Err(SandboxTransformError::UnsupportedPolicy(_))
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn spawn_with_stdio_reads_explicit_roots_and_round_trips_stdin() {
        use std::io::Write;
        use std::time::{SystemTime, UNIX_EPOCH};

        run_if_bwrap_supported(
            crate::linux_sandbox::ensure_bwrap_procfs_support(),
            Box::new(|| {
                let unique = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_nanos();
                let workspace_parent =
                    std::env::temp_dir().join(format!("ai-sandbox-workspace-{unique}"));
                let toolchain_root =
                    std::env::temp_dir().join(format!("ai-sandbox-toolchain-{unique}"));
                std::fs::create_dir_all(&workspace_parent).unwrap();
                std::fs::create_dir_all(&toolchain_root).unwrap();
                struct Cleanup(Vec<PathBuf>);
                impl Drop for Cleanup {
                    fn drop(&mut self) {
                        for path in &self.0 {
                            let _ = std::fs::remove_dir_all(path);
                        }
                    }
                }
                let _cleanup = Cleanup(vec![workspace_parent.clone(), toolchain_root.clone()]);

                let workspace = workspace_parent.join("workspace");
                std::fs::create_dir_all(&workspace).unwrap();
                let toolchain_file = toolchain_root.join("runtime.txt");
                std::fs::write(&toolchain_file, b"toolchain").unwrap();
                let command = SandboxCommand {
                    program: "/usr/bin/cat".into(),
                    args: vec![toolchain_file.to_string_lossy().into_owned(), "-".into()],
                    cwd: workspace,
                    env: HashMap::new(),
                };
                let policy = SandboxPolicy::ReadOnly {
                    file_system: FileSystemSandboxPolicy::ReadOnly,
                    network_access: NetworkSandboxPolicy::NoAccess,
                };
                let request = SandboxManager::new()
                    .create_exec_request_with_read_only_roots(command, policy, vec![toolchain_root])
                    .unwrap();

                let mut child = request.spawn_with_stdio_in_process_group().unwrap();
                let mut stdin = child.stdin.take().expect("stdin should be piped");
                assert!(child.stdout.is_some(), "stdout should be piped");
                assert!(child.stderr.is_some(), "stderr should be piped");
                stdin.write_all(b"+stdin").unwrap();
                drop(stdin);
                let output = child.wait_with_output().unwrap();

                assert!(
                    output.status.success(),
                    "{}",
                    String::from_utf8_lossy(&output.stderr)
                );
                assert_eq!(output.stdout, b"toolchain+stdin");
            }),
        );
    }

    #[test]
    fn request_spawn_rejects_empty_and_unavailable_backends() {
        let mut empty = request_for_process_tests("true", SandboxType::None);
        empty.execution.command.clear();
        assert!(matches!(
            empty.spawn(),
            Err(SandboxExecutionError::InvalidCommand(_))
        ));
        assert!(matches!(
            empty.spawn_with_stdio(),
            Err(SandboxExecutionError::InvalidCommand(_))
        ));
        assert!(matches!(
            empty.spawn_with_stdio_in_process_group(),
            Err(SandboxExecutionError::InvalidCommand(_))
        ));

        let valid_unprotected = request_for_process_tests("true", SandboxType::None);
        assert!(matches!(
            valid_unprotected.spawn_with_stdio(),
            Err(SandboxExecutionError::Unsupported(_))
        ));
        assert!(matches!(
            valid_unprotected.spawn_with_stdio_in_process_group(),
            Err(SandboxExecutionError::Unsupported(_))
        ));

        let unprotected = request_for_process_tests("true", SandboxType::None);
        assert!(matches!(
            unprotected.spawn(),
            Err(SandboxExecutionError::Unsupported(_))
        ));

        let unsupported = request_for_process_tests("true", SandboxType::FreeBSDCapsicum);
        assert!(matches!(
            unsupported.spawn(),
            Err(SandboxExecutionError::Unsupported(_))
        ));

        let mut empty_wait = request_for_process_tests("true", SandboxType::None);
        empty_wait.execution.command.clear();
        assert!(matches!(
            empty_wait.run(Duration::ZERO),
            Err(SandboxExecutionError::InvalidCommand(_))
        ));
        assert!(matches!(
            empty_wait.wait(),
            Err(SandboxExecutionError::InvalidCommand(_))
        ));
    }

    #[test]
    fn request_wait_returns_status_and_propagates_spawn_errors() {
        let request = request_for_process_tests("true", SandboxType::None);
        let status = request
            .wait_with_spawn(Box::new(|_| {
                Command::new("true")
                    .spawn()
                    .map_err(SandboxExecutionError::Io)
            }))
            .unwrap();
        assert!(status.success());

        let error = request.wait_with_spawn(Box::new(|_| {
            Err(SandboxExecutionError::Unsupported(
                "mock spawn failure".into(),
            ))
        }));
        assert!(matches!(error, Err(SandboxExecutionError::Unsupported(_))));
    }

    #[test]
    fn request_run_returns_early_status_and_enforces_timeout() {
        let request = request_for_process_tests("true", SandboxType::None);
        let status = request
            .run_with_spawn(
                Duration::from_secs(5),
                Box::new(|_| {
                    Command::new("true")
                        .spawn()
                        .map_err(SandboxExecutionError::Io)
                }),
            )
            .unwrap();
        assert!(status.success());

        let timeout = Duration::from_millis(20);
        let result = request.run_with_spawn(
            timeout,
            Box::new(|_| {
                Command::new("sleep")
                    .arg("1")
                    .spawn()
                    .map_err(SandboxExecutionError::Io)
            }),
        );
        assert_eq!(timed_out_duration(result), Some(timeout));
    }

    #[test]
    fn configured_timeout_caps_a_longer_run_timeout() {
        let configured = Duration::from_millis(20);
        let request = request_for_process_tests("sleep", SandboxType::None);
        let mut request = request;
        request.execution.timeout = Some(configured);
        let result = request.run_with_spawn(
            Duration::from_secs(2),
            Box::new(|_| {
                Command::new("sleep")
                    .arg("1")
                    .spawn()
                    .map_err(SandboxExecutionError::Io)
            }),
        );
        assert_eq!(timed_out_duration(result), Some(configured));
    }

    #[test]
    fn configured_timeout_also_bounds_wait() {
        let configured = Duration::from_millis(20);
        let mut request = request_for_process_tests("sleep", SandboxType::None);
        request.execution.timeout = Some(configured);
        let result = request.wait_with_spawn(Box::new(|_| {
            Command::new("sleep")
                .arg("1")
                .spawn()
                .map_err(SandboxExecutionError::Io)
        }));
        assert_eq!(timed_out_duration(result), Some(configured));
    }

    #[test]
    fn unsafe_environment_keys_cover_prefix_and_exact_matches() {
        for key in [
            "LD_PRELOAD",
            "DYLD_LIBRARY_PATH",
            "BASH_ENV",
            "ENV",
            "NODE_OPTIONS",
            "PERL5OPT",
            "PYTHONINSPECT",
            "RUBYOPT",
        ] {
            assert!(is_unsafe_environment_key(key), "{key} should be filtered");
        }
        for key in ["PATH", "HOME", "LD", "DYLD", "NODE_PATH", "PYTHONPATH"] {
            assert!(!is_unsafe_environment_key(key), "{key} should be retained");
        }

        let request = SandboxExecRequest {
            execution: PreparedExecution {
                command: vec!["true".into()],
                cwd: std::env::current_dir().unwrap(),
                env: [
                    ("PATH".into(), "/usr/bin".into()),
                    ("LD_PRELOAD".into(), "inject.so".into()),
                ]
                .into(),
                sandbox: SandboxType::None,
                timeout: None,
            },
            ..request_for_process_tests("/bin/sh", SandboxType::None)
        };
        let mut command = request.command_for_spawn();
        command.arg("-c");
        command.arg("test \"$PATH\" = /usr/bin && test -z \"${LD_PRELOAD:-}\"");
        assert!(command.status().unwrap().success());
    }

    #[test]
    fn test_get_platform_sandbox() {
        // On Windows, sandbox requires windows_sandbox_enabled = true
        // Use true to ensure test passes on all platforms
        #[cfg(target_os = "windows")]
        let result = get_platform_sandbox(true);
        #[cfg(not(target_os = "windows"))]
        let result = get_platform_sandbox(false);

        #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
        assert!(result.is_some());
        #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
        assert!(result.is_none());
    }

    #[test]
    fn platform_selector_covers_supported_hosts_and_windows_opt_in() {
        for (platform, expected) in [
            (HostPlatform::Linux, Some(SandboxType::LinuxSeccomp)),
            (HostPlatform::Macos, Some(SandboxType::MacosSeatbelt)),
            (HostPlatform::FreeBsd, Some(SandboxType::FreeBSDCapsicum)),
            (HostPlatform::OpenBsd, Some(SandboxType::OpenBSDPledge)),
            (HostPlatform::Other, None),
        ] {
            assert_eq!(get_platform_sandbox_for(platform, false), expected);
        }
        assert_eq!(get_platform_sandbox_for(HostPlatform::Windows, false), None);
        assert_eq!(
            get_platform_sandbox_for(HostPlatform::Windows, true),
            Some(SandboxType::WindowsRestrictedToken)
        );
    }

    #[test]
    fn platform_requirement_checks_filesystem_and_network_restrictions() {
        assert!(!should_require_platform_sandbox(
            &FileSystemSandboxPolicy::FullAccess,
            NetworkSandboxPolicy::FullAccess
        ));
        assert!(should_require_platform_sandbox(
            &FileSystemSandboxPolicy::ReadOnly,
            NetworkSandboxPolicy::FullAccess
        ));
        assert!(should_require_platform_sandbox(
            &FileSystemSandboxPolicy::FullAccess,
            NetworkSandboxPolicy::NoAccess
        ));
        assert!(should_require_platform_sandbox(
            &FileSystemSandboxPolicy::ReadOnly,
            NetworkSandboxPolicy::NoAccess
        ));
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn test_sandbox_manager_create_request() {
        let manager = SandboxManager::new();
        let command = SandboxCommand {
            program: OsString::from("ls"),
            args: vec!["-la".to_string()],
            cwd: PathBuf::from("/tmp"),
            env: HashMap::new(),
        };

        let result = manager.create_exec_request(command, SandboxPolicy::default());
        assert!(result.is_ok());
    }

    #[test]
    #[cfg(not(target_os = "macos"))]
    fn test_sandbox_manager_create_request() {
        // Skip test on non-macOS platforms as it requires platform-specific sandbox executable
        // The test verifies that create_exec_request works, but it requires a sandbox executable
        // which is only available on macOS (seatbelt)
    }

    // ============================================================================
    // 破坏性测试 - 沙箱策略安全性验证
    // ============================================================================

    #[test]
    fn test_default_policy_should_be_secure() {
        // 默认策略应该是安全的，不应该是 DangerFullAccess
        // 根据安全最佳实践，默认应该拒绝访问
        let default_policy = SandboxPolicy::default();

        // 默认策略不应该是完全无限制的
        assert!(
            !matches!(default_policy, SandboxPolicy::DangerFullAccess),
            "默认策略不应该是 DangerFullAccess，这是安全漏洞！"
        );
    }

    #[test]
    fn readonly_policy_rejects_permissive_filesystem_modes() {
        for file_system in [
            FileSystemSandboxPolicy::FullAccess,
            FileSystemSandboxPolicy::External,
            FileSystemSandboxPolicy::WorkspaceWrite {
                writable_roots: vec![PathBuf::from("/tmp")],
            },
        ] {
            let policy = SandboxPolicy::ReadOnly {
                file_system,
                network_access: NetworkSandboxPolicy::NoAccess,
            };
            assert!(!policy.is_safe());
        }

        let read_only = SandboxPolicy::ReadOnly {
            file_system: FileSystemSandboxPolicy::ReadOnly,
            network_access: NetworkSandboxPolicy::NoAccess,
        };
        assert!(read_only.is_safe());
        assert!(!SandboxPolicy::ReadOnly {
            file_system: FileSystemSandboxPolicy::ReadOnlyWithRoots {
                read_only_roots: Vec::new(),
            },
            network_access: NetworkSandboxPolicy::NoAccess,
        }
        .is_safe());
    }

    #[test]
    fn sandbox_preference_selection_covers_forbid_require_and_auto() {
        let manager = SandboxManager::new();
        let filesystem = FileSystemSandboxPolicy::ReadOnly;
        let network = NetworkSandboxPolicy::NoAccess;
        assert_eq!(
            manager.select_initial(&filesystem, network, SandboxablePreference::Forbid, false,),
            SandboxType::None
        );
        let expected =
            get_platform_sandbox(cfg!(target_os = "windows")).unwrap_or(SandboxType::None);
        assert_eq!(
            manager.select_initial(
                &filesystem,
                network,
                SandboxablePreference::Require,
                cfg!(target_os = "windows"),
            ),
            expected
        );
        assert_eq!(
            manager.select_initial(
                &filesystem,
                network,
                SandboxablePreference::Auto,
                cfg!(target_os = "windows"),
            ),
            expected
        );
    }

    #[test]
    fn policy_traversal_and_safety_predicates_cover_all_path_shapes() {
        for path in ["/workspace/../outside", "/workspace/.hidden", "./relative"] {
            assert!(SandboxPolicy::contains_path_traversal(Path::new(path)));
        }
        assert!(!SandboxPolicy::contains_path_traversal(Path::new(
            "/workspace/project"
        )));

        assert!(!SandboxPolicy::DangerFullAccess.is_safe());
        assert!(!SandboxPolicy::ExternalSandbox {
            network_access: NetworkSandboxPolicy::NoAccess,
        }
        .is_safe());
        assert!(!SandboxPolicy::WorkspaceWrite {
            writable_roots: vec![],
            network_access: NetworkSandboxPolicy::NoAccess,
        }
        .is_safe());

        for root in [PathBuf::from("relative"), PathBuf::from("/")] {
            assert!(!SandboxPolicy::WorkspaceWrite {
                writable_roots: vec![root],
                network_access: NetworkSandboxPolicy::NoAccess,
            }
            .is_safe());
        }
        assert!(!SandboxPolicy::WorkspaceWrite {
            writable_roots: vec![PathBuf::from("/workspace/../outside")],
            network_access: NetworkSandboxPolicy::NoAccess,
        }
        .is_safe());
        assert!(SandboxPolicy::WorkspaceWrite {
            writable_roots: vec![PathBuf::from("/workspace/project")],
            network_access: NetworkSandboxPolicy::NoAccess,
        }
        .is_safe());
    }

    #[test]
    fn execution_entrypoints_reject_full_access_inside_readonly_policy() {
        let policy = SandboxPolicy::ReadOnly {
            file_system: FileSystemSandboxPolicy::FullAccess,
            network_access: NetworkSandboxPolicy::NoAccess,
        };
        let command = || SandboxCommand {
            program: OsString::from("tool"),
            args: Vec::new(),
            cwd: PathBuf::from("/tmp"),
            env: HashMap::new(),
        };
        let manager = SandboxManager::new();

        assert!(matches!(
            manager.create_exec_request(command(), policy.clone()),
            Err(SandboxTransformError::UnsafePolicy(_))
        ));
        assert!(matches!(
            manager.transform_command(command(), policy, SandboxType::LinuxSeccomp, None),
            Err(SandboxTransformError::UnsafePolicy(_))
        ));
    }

    #[test]
    fn test_workspace_write_rejects_empty_paths() {
        // WorkspaceWrite 应该拒绝空的 writable_roots
        let empty_policy = SandboxPolicy::WorkspaceWrite {
            writable_roots: vec![],
            network_access: NetworkSandboxPolicy::NoAccess,
        };

        // 获取文件系统策略并验证 - 空路径应该被降级为 ReadOnly
        let fs_policy = empty_policy.filesystem_policy();
        match fs_policy {
            FileSystemSandboxPolicy::ReadOnly => {
                // 预期行为：空路径被降级为只读 - 测试通过
            }
            FileSystemSandboxPolicy::WorkspaceWrite { writable_roots } => {
                assert!(
                    !writable_roots.is_empty(),
                    "空的 writable_roots 应该被拒绝或自动处理"
                );
            }
            _ => {
                panic!("Unexpected filesystem policy variant");
            }
        }

        // 验证 is_safe 方法
        assert!(
            !empty_policy.is_safe(),
            "空 writable_roots 的 WorkspaceWrite 应该是不安全的"
        );

        // 验证非空的是安全的
        let safe_policy = SandboxPolicy::WorkspaceWrite {
            writable_roots: vec![PathBuf::from("/tmp")],
            network_access: NetworkSandboxPolicy::NoAccess,
        };
        assert!(
            safe_policy.is_safe(),
            "有有效路径的 WorkspaceWrite 应该是安全的"
        );
    }

    #[test]
    fn test_workspace_write_rejects_path_traversal() {
        // WorkspaceWrite 应该拒绝包含路径遍历的路径
        let traversal_paths = vec![
            PathBuf::from("/tmp/../etc"),
            PathBuf::from("/tmp/../../etc"),
            PathBuf::from("/home/../../../root"),
            PathBuf::from("/tmp/./secret"),
        ];

        for path in traversal_paths {
            let policy = SandboxPolicy::WorkspaceWrite {
                writable_roots: vec![path.clone()],
                network_access: NetworkSandboxPolicy::NoAccess,
            };

            // 包含路径遍历的路径应该被认为是不安全的
            assert!(
                !policy.is_safe(),
                "包含路径遍历的路径 {:?} 应该被认为是不安全的",
                path
            );
        }
    }

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new(label: &str) -> Self {
            use std::time::{SystemTime, UNIX_EPOCH};

            let unique = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let path = std::env::temp_dir().join(format!(
                "ai-sandbox-{label}-{}-{unique}",
                std::process::id()
            ));
            std::fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn read_only_roots_policy_requires_absolute_non_root_paths() {
        let policy = |roots| SandboxPolicy::ReadOnly {
            file_system: FileSystemSandboxPolicy::ReadOnlyWithRoots {
                read_only_roots: roots,
            },
            network_access: NetworkSandboxPolicy::NoAccess,
        };

        assert!(policy(vec![
            PathBuf::from("/workspace"),
            PathBuf::from("/toolchain")
        ])
        .is_safe());
        assert!(!policy(Vec::new()).is_safe());
        assert!(!policy(vec![PathBuf::from("relative")]).is_safe());
        assert!(!policy(vec![PathBuf::from("/")]).is_safe());
        assert!(!policy(vec![PathBuf::from("/opt/../etc")]).is_safe());
    }

    #[test]
    fn read_only_root_normalization_rejects_unsafe_roots_and_deduplicates_valid_roots() {
        let directory = TestDirectory::new("root-normalization");
        let cwd = directory.0.join("workspace");
        let additional_root = directory.0.join("toolchain");
        let nested_root = cwd.join("nested-toolchain");
        std::fs::create_dir_all(&cwd).unwrap();
        std::fs::create_dir_all(&additional_root).unwrap();
        std::fs::create_dir_all(&nested_root).unwrap();
        let policy = |read_only_roots| SandboxPolicy::ReadOnly {
            file_system: FileSystemSandboxPolicy::ReadOnlyWithRoots { read_only_roots },
            network_access: NetworkSandboxPolicy::NoAccess,
        };

        for invalid_root in [
            PathBuf::from("relative"),
            PathBuf::from("/"),
            PathBuf::from("/tmp/../etc"),
            directory.0.join("missing"),
            directory.0.clone(),
        ] {
            assert!(normalize_read_only_roots(policy(vec![invalid_root]), &cwd).is_err());
        }

        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;

            let root_alias = directory.0.join("root-alias");
            symlink("/", &root_alias).unwrap();
            assert!(normalize_read_only_roots(policy(vec![root_alias]), &cwd).is_err());
        }

        let (normalized, normalized_cwd) = normalize_read_only_roots(
            policy(vec![
                cwd.clone(),
                nested_root,
                additional_root.clone(),
                additional_root.clone(),
            ]),
            &cwd,
        )
        .unwrap();
        assert_eq!(normalized_cwd, cwd.canonicalize().unwrap());
        let mut expected_roots = vec![
            cwd.canonicalize().unwrap(),
            additional_root.canonicalize().unwrap(),
        ];
        expected_roots.sort();
        let expected_filesystem = FileSystemSandboxPolicy::ReadOnlyWithRoots {
            read_only_roots: expected_roots,
        };
        assert_eq!(
            format!("{:?}", normalized.filesystem_policy()),
            format!("{expected_filesystem:?}")
        );
    }

    #[test]
    fn additional_read_only_roots_reject_wrong_policy_and_relative_cwd() {
        let manager = SandboxManager::new();
        let command = |cwd| SandboxCommand {
            program: OsString::from("tool"),
            args: Vec::new(),
            cwd,
            env: HashMap::new(),
        };
        let policy = SandboxPolicy::ReadOnly {
            file_system: FileSystemSandboxPolicy::FullAccess,
            network_access: NetworkSandboxPolicy::NoAccess,
        };
        assert!(matches!(
            manager.create_exec_request_with_read_only_roots(
                command(PathBuf::from("/tmp")),
                policy,
                Vec::new(),
            ),
            Err(SandboxTransformError::UnsupportedPolicy(_))
        ));

        let policy = SandboxPolicy::ReadOnly {
            file_system: FileSystemSandboxPolicy::ReadOnly,
            network_access: NetworkSandboxPolicy::NoAccess,
        };
        assert!(matches!(
            manager.create_exec_request_with_read_only_roots(
                command(PathBuf::from("relative")),
                policy,
                Vec::new(),
            ),
            Err(SandboxTransformError::UnsafePolicy(_))
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn manager_includes_read_only_roots_in_prepared_bwrap_command() {
        let workspace = TestDirectory::new("workspace");
        let toolchain = TestDirectory::new("toolchain");
        let command = SandboxCommand {
            program: "/usr/bin/cat".into(),
            args: Vec::new(),
            cwd: workspace.0.clone(),
            env: HashMap::new(),
        };
        let policy = SandboxPolicy::ReadOnly {
            file_system: FileSystemSandboxPolicy::ReadOnly,
            network_access: NetworkSandboxPolicy::NoAccess,
        };

        let request = SandboxManager::new()
            .create_exec_request_with_read_only_roots(command, policy, vec![toolchain.0.clone()])
            .unwrap();

        let toolchain = toolchain
            .0
            .canonicalize()
            .unwrap()
            .to_string_lossy()
            .into_owned();
        let mut expected_roots = vec![
            workspace.0.canonicalize().unwrap(),
            PathBuf::from(&toolchain),
        ];
        expected_roots.sort();
        let expected_filesystem = FileSystemSandboxPolicy::ReadOnlyWithRoots {
            read_only_roots: expected_roots,
        };
        assert_eq!(
            format!("{:?}", request.file_system_policy),
            format!("{expected_filesystem:?}")
        );
        assert!(request
            .command
            .windows(3)
            .any(|parts| { parts == ["--ro-bind", toolchain.as_str(), toolchain.as_str()] }));
    }

    #[cfg(unix)]
    #[test]
    fn piped_command_builder_round_trips_stdin_to_stdout() {
        use std::io::Write;

        let mut request = request_for_process_tests("/bin/cat", SandboxType::LinuxSeccomp);
        request.execution.command.push("-".into());
        let mut child = request
            .command_for_spawn_with_io(true, true)
            .spawn()
            .unwrap();
        assert_eq!(
            unsafe { libc::getpgid(child.id() as libc::pid_t) },
            child.id() as libc::pid_t
        );
        let mut stdin = child.stdin.take().expect("stdin should be piped");
        assert!(child.stdout.is_some(), "stdout should be piped");
        assert!(child.stderr.is_some(), "stderr should be piped");
        stdin.write_all(b"piped").unwrap();
        drop(stdin);

        let output = child.wait_with_output().unwrap();
        assert!(output.status.success());
        assert_eq!(output.stdout, b"piped");
    }

    #[test]
    fn test_workspace_write_accepts_valid_paths() {
        // WorkspaceWrite 应该接受有效的规范化路径
        let valid_paths = vec![
            PathBuf::from("/tmp"),
            PathBuf::from("/home/user/workspace"),
            PathBuf::from("/var/data"),
        ];

        for path in valid_paths {
            let policy = SandboxPolicy::WorkspaceWrite {
                writable_roots: vec![path.clone()],
                network_access: NetworkSandboxPolicy::NoAccess,
            };

            assert!(policy.is_safe(), "有效路径 {:?} 应该被认为安全的", path);
        }
    }

    #[test]
    fn test_readonly_policy_structure() {
        // 测试只读策略结构
        let policy = SandboxPolicy::ReadOnly {
            file_system: FileSystemSandboxPolicy::ReadOnly,
            network_access: NetworkSandboxPolicy::NoAccess,
        };

        match policy {
            SandboxPolicy::ReadOnly {
                file_system,
                network_access,
            } => {
                assert!(matches!(file_system, FileSystemSandboxPolicy::ReadOnly));
                assert!(matches!(network_access, NetworkSandboxPolicy::NoAccess));
            }
            _ => panic!("Expected ReadOnly policy"),
        }
    }

    #[test]
    fn test_workspace_policy_validates_paths() {
        // 测试工作区策略路径验证
        let policy = SandboxPolicy::WorkspaceWrite {
            writable_roots: vec![PathBuf::from("/tmp"), PathBuf::from("/home/user/workspace")],
            network_access: NetworkSandboxPolicy::Localhost,
        };

        match policy {
            SandboxPolicy::WorkspaceWrite {
                writable_roots,
                network_access,
            } => {
                assert_eq!(writable_roots.len(), 2);
                assert!(matches!(network_access, NetworkSandboxPolicy::Localhost));
            }
            _ => panic!("Expected WorkspaceWrite policy"),
        }
    }

    #[test]
    fn test_network_policy_variants() {
        // 测试网络策略变体
        assert!(matches!(
            NetworkSandboxPolicy::default(),
            NetworkSandboxPolicy::FullAccess
        ));
        assert!(matches!(
            NetworkSandboxPolicy::NoAccess,
            NetworkSandboxPolicy::NoAccess
        ));
        assert!(matches!(
            NetworkSandboxPolicy::Localhost,
            NetworkSandboxPolicy::Localhost
        ));
        assert!(matches!(
            NetworkSandboxPolicy::Proxy,
            NetworkSandboxPolicy::Proxy
        ));
    }

    #[test]
    fn test_filesystem_policy_variants() {
        // 测试文件系统策略变体
        assert!(matches!(
            FileSystemSandboxPolicy::default(),
            FileSystemSandboxPolicy::FullAccess
        ));
        assert!(matches!(
            FileSystemSandboxPolicy::ReadOnly,
            FileSystemSandboxPolicy::ReadOnly
        ));
        assert!(matches!(
            FileSystemSandboxPolicy::External,
            FileSystemSandboxPolicy::External
        ));

        // 测试 WorkspaceWrite 变体
        let ws = FileSystemSandboxPolicy::WorkspaceWrite {
            writable_roots: vec![PathBuf::from("/tmp")],
        };
        assert!(matches!(ws, FileSystemSandboxPolicy::WorkspaceWrite { .. }));
    }

    #[test]
    fn test_sandbox_type_all_variants() {
        // 测试所有沙箱类型
        let types = vec![
            SandboxType::None,
            SandboxType::MacosSeatbelt,
            SandboxType::LinuxSeccomp,
            SandboxType::WindowsRestrictedToken,
            SandboxType::FreeBSDCapsicum,
            SandboxType::OpenBSDPledge,
        ];

        for sandbox_type in types {
            let name = sandbox_type.name();
            let tag = sandbox_type.as_metric_tag();
            assert!(!name.is_empty());
            assert!(!tag.is_empty());
        }
    }

    #[test]
    fn test_sandbox_command_validation() {
        let command = SandboxCommand {
            program: OsString::from("ls"),
            args: vec!["-la".to_string(), "/tmp".to_string()],
            cwd: PathBuf::from("/tmp"),
            env: HashMap::new(),
        };

        assert_eq!(command.program, OsString::from("ls"));
        assert_eq!(command.args, vec!["-la", "/tmp"]);
        assert_eq!(command.cwd, PathBuf::from("/tmp"));
    }

    #[test]
    fn test_sandbox_preference_variants() {
        // 测试沙箱偏好设置
        assert!(matches!(
            SandboxablePreference::default(),
            SandboxablePreference::Auto
        ));
        assert!(matches!(
            SandboxablePreference::Require,
            SandboxablePreference::Require
        ));
        assert!(matches!(
            SandboxablePreference::Forbid,
            SandboxablePreference::Forbid
        ));
    }

    // ============================================================================
    // 破坏性测试 - 边界条件和错误处理
    // ============================================================================

    #[test]
    fn test_empty_program_name() {
        let manager = SandboxManager::new();
        let command = SandboxCommand {
            program: OsString::from(""),
            args: vec![],
            cwd: PathBuf::from("/tmp"),
            env: HashMap::new(),
        };

        let result = manager.create_exec_request(command, SandboxPolicy::default());
        assert!(result.is_ok());
    }

    #[test]
    fn test_very_long_program_name() {
        let manager = SandboxManager::new();
        let long_name = "A".repeat(10000);
        let command = SandboxCommand {
            program: OsString::from(long_name),
            args: vec![],
            cwd: PathBuf::from("/tmp"),
            env: HashMap::new(),
        };

        let result = manager.create_exec_request(command, SandboxPolicy::default());
        assert!(result.is_ok());
    }

    #[test]
    fn test_special_characters_in_args() {
        let manager = SandboxManager::new();
        let command = SandboxCommand {
            program: OsString::from("ls"),
            args: vec![
                "-la".to_string(),
                "/tmp".to_string(),
                ";rm -rf /".to_string(),
                "|cat /etc/passwd".to_string(),
                "`whoami`".to_string(),
                "$(id)".to_string(),
            ],
            cwd: PathBuf::from("/tmp"),
            env: HashMap::new(),
        };

        let result = manager.create_exec_request(command, SandboxPolicy::default());
        assert!(result.is_ok());
    }

    #[test]
    fn test_empty_cwd() {
        let manager = SandboxManager::new();
        let command = SandboxCommand {
            program: OsString::from("ls"),
            args: vec![],
            cwd: PathBuf::from(""),
            env: HashMap::new(),
        };

        let result = manager.create_exec_request(command, SandboxPolicy::default());
        assert!(matches!(
            result,
            Err(SandboxTransformError::BubblewrapBuild(_))
        ));
    }

    #[test]
    fn test_nonexistent_cwd() {
        let manager = SandboxManager::new();
        let command = SandboxCommand {
            program: OsString::from("ls"),
            args: vec![],
            cwd: PathBuf::from("/nonexistent/path/that/does/not/exist"),
            env: HashMap::new(),
        };

        let result = manager.create_exec_request(command, SandboxPolicy::default());
        assert!(matches!(
            result,
            Err(SandboxTransformError::BubblewrapBuild(_))
        ));
    }

    // ============================================================================
    // 破坏性测试 - Policy Clone 和序列化
    // ============================================================================

    #[test]
    fn test_policy_clone() {
        // 测试策略克隆
        let policy = SandboxPolicy::ReadOnly {
            file_system: FileSystemSandboxPolicy::ReadOnly,
            network_access: NetworkSandboxPolicy::NoAccess,
        };

        let cloned = policy.clone();
        assert_eq!(policy, cloned);
    }

    #[test]
    fn test_policy_debug_format() {
        // 测试策略调试格式
        let policy = SandboxPolicy::WorkspaceWrite {
            writable_roots: vec![PathBuf::from("/tmp")],
            network_access: NetworkSandboxPolicy::Localhost,
        };

        let debug_str = format!("{:?}", policy);
        assert!(!debug_str.is_empty());
    }

    // ============================================================================
    // 新增测试: 验证 network_policy() 和 filesystem_policy() 方法
    // ============================================================================

    #[test]
    fn test_sandbox_policy_network_policy_method() {
        // 测试 SandboxPolicy::network_policy() 方法
        let policy_full = SandboxPolicy::DangerFullAccess;
        assert_eq!(
            policy_full.network_policy(),
            NetworkSandboxPolicy::FullAccess
        );

        let policy_readonly = SandboxPolicy::ReadOnly {
            file_system: FileSystemSandboxPolicy::ReadOnly,
            network_access: NetworkSandboxPolicy::NoAccess,
        };
        assert_eq!(
            policy_readonly.network_policy(),
            NetworkSandboxPolicy::NoAccess
        );

        let policy_external = SandboxPolicy::ExternalSandbox {
            network_access: NetworkSandboxPolicy::Localhost,
        };
        assert_eq!(
            policy_external.network_policy(),
            NetworkSandboxPolicy::Localhost
        );

        let policy_workspace = SandboxPolicy::WorkspaceWrite {
            writable_roots: vec![PathBuf::from("/tmp")],
            network_access: NetworkSandboxPolicy::Proxy,
        };
        assert_eq!(
            policy_workspace.network_policy(),
            NetworkSandboxPolicy::Proxy
        );
    }

    #[test]
    fn test_sandbox_policy_filesystem_policy_method() {
        // 测试 SandboxPolicy::filesystem_policy() 方法
        let policy_full = SandboxPolicy::DangerFullAccess;
        assert_eq!(
            policy_full.filesystem_policy(),
            FileSystemSandboxPolicy::FullAccess
        );

        let policy_readonly = SandboxPolicy::ReadOnly {
            file_system: FileSystemSandboxPolicy::ReadOnly,
            network_access: NetworkSandboxPolicy::NoAccess,
        };
        assert_eq!(
            policy_readonly.filesystem_policy(),
            FileSystemSandboxPolicy::ReadOnly
        );

        let policy_external = SandboxPolicy::ExternalSandbox {
            network_access: NetworkSandboxPolicy::Localhost,
        };
        assert_eq!(
            policy_external.filesystem_policy(),
            FileSystemSandboxPolicy::External
        );

        let policy_workspace = SandboxPolicy::WorkspaceWrite {
            writable_roots: vec![PathBuf::from("/tmp"), PathBuf::from("/home")],
            network_access: NetworkSandboxPolicy::FullAccess,
        };
        let fs_policy = policy_workspace.filesystem_policy();
        match fs_policy {
            FileSystemSandboxPolicy::WorkspaceWrite { writable_roots } => {
                assert_eq!(writable_roots.len(), 2);
            }
            _ => panic!("Expected WorkspaceWrite variant"),
        }
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn test_sandbox_exec_request_carries_network_policy() {
        // 测试 SandboxExecRequest 正确携带 network_policy
        let manager = SandboxManager::new();

        // 测试 NoAccess 策略
        let policy = SandboxPolicy::ReadOnly {
            file_system: FileSystemSandboxPolicy::ReadOnly,
            network_access: NetworkSandboxPolicy::NoAccess,
        };
        let command = SandboxCommand {
            program: OsString::from("ls"),
            args: vec![],
            cwd: PathBuf::from("/tmp"),
            env: HashMap::new(),
        };
        let request = manager.create_exec_request(command, policy).unwrap();
        assert_eq!(request.network_policy, NetworkSandboxPolicy::NoAccess);

        // 测试 Localhost 策略
        let policy_localhost = SandboxPolicy::ReadOnly {
            file_system: FileSystemSandboxPolicy::ReadOnly,
            network_access: NetworkSandboxPolicy::Localhost,
        };
        let command = SandboxCommand {
            program: OsString::from("ls"),
            args: vec![],
            cwd: PathBuf::from("/tmp"),
            env: HashMap::new(),
        };
        let request = manager
            .create_exec_request(command, policy_localhost)
            .unwrap();
        assert_eq!(request.network_policy, NetworkSandboxPolicy::Localhost);
    }

    #[test]
    #[cfg(not(target_os = "macos"))]
    fn test_sandbox_exec_request_carries_network_policy() {
        // Skip on non-macOS as it requires platform-specific sandbox executable
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn test_sandbox_exec_request_carries_filesystem_policy() {
        // 测试 SandboxExecRequest 正确携带 file_system_policy
        let manager = SandboxManager::new();

        // 测试 ReadOnly 策略
        let policy = SandboxPolicy::ReadOnly {
            file_system: FileSystemSandboxPolicy::ReadOnly,
            network_access: NetworkSandboxPolicy::FullAccess,
        };
        let command = SandboxCommand {
            program: OsString::from("ls"),
            args: vec![],
            cwd: PathBuf::from("/tmp"),
            env: HashMap::new(),
        };
        let request = manager.create_exec_request(command, policy).unwrap();
        assert_eq!(
            request.file_system_policy,
            FileSystemSandboxPolicy::ReadOnly
        );

        // 测试 WorkspaceWrite 策略
        let policy_workspace = SandboxPolicy::WorkspaceWrite {
            writable_roots: vec![PathBuf::from("/workspace")],
            network_access: NetworkSandboxPolicy::FullAccess,
        };
        let command = SandboxCommand {
            program: OsString::from("ls"),
            args: vec![],
            cwd: PathBuf::from("/tmp"),
            env: HashMap::new(),
        };
        let request = manager
            .create_exec_request(command, policy_workspace)
            .unwrap();
        match request.file_system_policy {
            FileSystemSandboxPolicy::WorkspaceWrite { writable_roots } => {
                assert_eq!(writable_roots.len(), 1);
            }
            _ => panic!("Expected WorkspaceWrite variant"),
        }
    }

    #[test]
    #[cfg(not(target_os = "macos"))]
    fn test_sandbox_exec_request_carries_filesystem_policy() {
        // Skip on non-macOS as it requires platform-specific sandbox executable
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_linux_executor_enforces_filesystem_boundaries() {
        use std::fs;
        use std::time::{SystemTime, UNIX_EPOCH};

        run_if_bwrap_supported(
            crate::linux_sandbox::ensure_bwrap_procfs_support(),
            Box::new(|| {
                let suffix = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .expect("system clock is before Unix epoch")
                    .as_nanos();
                let base = std::env::temp_dir().join(format!("ai-sandbox-boundary-{suffix}"));
                let workspace = base.join("workspace");
                let outside = base.join("outside");
                fs::create_dir_all(&workspace).unwrap();
                fs::write(&outside, "outside").unwrap();

                let manager = SandboxManager::new();
                let readonly = SandboxPolicy::ReadOnly {
                    file_system: FileSystemSandboxPolicy::ReadOnly,
                    network_access: NetworkSandboxPolicy::NoAccess,
                };
                let unreadable = manager
                    .create_exec_request(
                        SandboxCommand {
                            program: OsString::from("/bin/sh"),
                            args: vec![
                                "-c".to_string(),
                                format!("test ! -r {}", outside.display()),
                            ],
                            cwd: workspace.clone(),
                            env: HashMap::new(),
                        },
                        readonly.clone(),
                    )
                    .unwrap();
                assert!(unreadable.run(Duration::from_secs(2)).unwrap().success());

                let blocked_write = manager
                    .create_exec_request(
                        SandboxCommand {
                            program: OsString::from("/usr/bin/touch"),
                            args: vec![workspace.join("blocked").display().to_string()],
                            cwd: workspace.clone(),
                            env: HashMap::new(),
                        },
                        readonly,
                    )
                    .unwrap();
                assert!(!blocked_write.run(Duration::from_secs(2)).unwrap().success());
                assert!(!workspace.join("blocked").exists());

                let writable = manager
                    .create_exec_request(
                        SandboxCommand {
                            program: OsString::from("/usr/bin/touch"),
                            args: vec![workspace.join("allowed").display().to_string()],
                            cwd: workspace.clone(),
                            env: HashMap::new(),
                        },
                        SandboxPolicy::WorkspaceWrite {
                            writable_roots: vec![workspace.clone()],
                            network_access: NetworkSandboxPolicy::NoAccess,
                        },
                    )
                    .unwrap();
                assert!(writable.run(Duration::from_secs(2)).unwrap().success());
                assert!(workspace.join("allowed").exists());

                let literal_argument = manager
                    .create_exec_request(
                        SandboxCommand {
                            program: OsString::from("/usr/bin/printf"),
                            args: vec!["%s".to_string(), format!("$(touch {})", outside.display())],
                            cwd: workspace.clone(),
                            env: HashMap::new(),
                        },
                        SandboxPolicy::WorkspaceWrite {
                            writable_roots: vec![workspace.clone()],
                            network_access: NetworkSandboxPolicy::NoAccess,
                        },
                    )
                    .unwrap();
                assert!(literal_argument
                    .run(Duration::from_secs(2))
                    .unwrap()
                    .success());
                assert_eq!(fs::read_to_string(&outside).unwrap(), "outside");

                fs::remove_dir_all(base).unwrap();
            }),
        );
    }
}
