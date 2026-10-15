use serde::Deserialize;
use std::path::{Component, Path, PathBuf};
use std::time::Duration;

use super::{
    FileSystemSandboxPolicy, NetworkSandboxPolicy, SandboxPolicy, SandboxTransformError,
    SandboxType,
};

pub const DEFAULT_MXC_TIMEOUT_MS: u32 = 30 * 60 * 1000;
const MAX_MXC_TIMEOUT_MS: u32 = 30 * 60 * 1000;

/// The supported policy-only subset of MXC's `source_lsp_mxc_config` JSON.
///
/// Commands are supplied separately as [`super::SandboxCommand`] argv, not as
/// MXC's shell-style `process.commandLine`. Unknown or unrepresentable policy
/// fields fail closed rather than being silently ignored.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MxcSandboxConfig {
    #[serde(default)]
    pub containment: MxcContainment,
    #[serde(default)]
    pub filesystem: MxcFilesystemConfig,
    #[serde(default)]
    pub network: MxcNetworkConfig,
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u32,
}

impl Default for MxcSandboxConfig {
    fn default() -> Self {
        Self {
            containment: MxcContainment::default(),
            filesystem: MxcFilesystemConfig::default(),
            network: MxcNetworkConfig::default(),
            timeout_ms: DEFAULT_MXC_TIMEOUT_MS,
        }
    }
}

impl MxcSandboxConfig {
    /// Parse strict JSON using the snake_case keys used by `conf.py`.
    pub fn from_json(json: &str) -> Result<Self, SandboxTransformError> {
        serde_json::from_str(json)
            .map_err(|error| SandboxTransformError::InvalidMxcConfig(error.to_string()))
    }

    /// Map supported MXC filesystem/network settings to this crate's policy.
    pub fn sandbox_policy(&self) -> Result<SandboxPolicy, SandboxTransformError> {
        self.validate_timeout()?;
        let network_access = self.network.to_sandbox_policy()?;
        if !self.filesystem.denied_paths.is_empty() {
            return Err(SandboxTransformError::UnsupportedPolicy(
                "MXC denied_paths are not representable by ai-sandbox".into(),
            ));
        }

        let readonly = validate_roots(&self.filesystem.readonly_paths, "readonly_paths")?;
        let readwrite = validate_roots(&self.filesystem.readwrite_paths, "readwrite_paths")?;
        let filesystem = match (readonly.is_empty(), readwrite.is_empty()) {
            (true, true) => FileSystemSandboxPolicy::ReadOnly,
            (false, true) => FileSystemSandboxPolicy::ReadOnlyWithRoots {
                read_only_roots: readonly,
            },
            (true, false) => FileSystemSandboxPolicy::WorkspaceWrite {
                writable_roots: readwrite,
            },
            (false, false) => {
                return Err(SandboxTransformError::UnsupportedPolicy(
                    "MXC mixed readonly_paths and readwrite_paths cannot be represented by ai-sandbox".into(),
                ));
            }
        };

        Ok(match filesystem {
            FileSystemSandboxPolicy::WorkspaceWrite { writable_roots } => {
                SandboxPolicy::WorkspaceWrite {
                    writable_roots,
                    network_access,
                }
            }
            file_system => SandboxPolicy::ReadOnly {
                file_system,
                network_access,
            },
        })
    }

    /// Resolve MXC containment only to executors implemented by this crate.
    pub fn sandbox_type(&self) -> Result<SandboxType, SandboxTransformError> {
        select_sandbox_type(self.containment, host_platform())
    }

    pub fn timeout(&self) -> Duration {
        Duration::from_millis(u64::from(self.timeout_ms))
    }

    fn validate_timeout(&self) -> Result<(), SandboxTransformError> {
        if (1..=MAX_MXC_TIMEOUT_MS).contains(&self.timeout_ms) {
            Ok(())
        } else {
            Err(SandboxTransformError::InvalidMxcConfig(format!(
                "timeout_ms must be between 1 and {MAX_MXC_TIMEOUT_MS}"
            )))
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum MxcContainment {
    #[default]
    Process,
    Bubblewrap,
    Seatbelt,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MxcFilesystemConfig {
    #[serde(default)]
    pub mount_procfs: bool,
    #[serde(default)]
    pub readonly_paths: Vec<PathBuf>,
    #[serde(default)]
    pub readwrite_paths: Vec<PathBuf>,
    #[serde(default)]
    pub denied_paths: Vec<PathBuf>,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MxcNetworkConfig {
    #[serde(default)]
    pub egress: MxcEgressConfig,
    #[serde(default)]
    pub ingress: MxcIngressConfig,
}

impl MxcNetworkConfig {
    fn to_sandbox_policy(&self) -> Result<NetworkSandboxPolicy, SandboxTransformError> {
        if !self.egress.allow.is_empty() || !self.egress.deny.is_empty() {
            return Err(SandboxTransformError::UnsupportedPolicy(
                "MXC explicit network rules are not representable by ai-sandbox".into(),
            ));
        }

        match (
            self.egress.default,
            self.ingress.default,
            self.ingress.host_loopback,
        ) {
            (MxcNetworkAction::Deny, MxcNetworkAction::Deny, MxcNetworkAction::Deny) => {
                Ok(NetworkSandboxPolicy::NoAccess)
            }
            (MxcNetworkAction::Allow, MxcNetworkAction::Allow, MxcNetworkAction::Allow) => {
                Ok(NetworkSandboxPolicy::FullAccess)
            }
            _ => Err(SandboxTransformError::UnsupportedPolicy(
                "mixed MXC egress, ingress, or host_loopback actions are not representable by ai-sandbox".into(),
            )),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum MxcNetworkAction {
    Allow,
    #[default]
    Deny,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MxcEgressConfig {
    #[serde(default)]
    pub default: MxcNetworkAction,
    #[serde(default)]
    pub allow: Vec<serde_json::Value>,
    #[serde(default)]
    pub deny: Vec<serde_json::Value>,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MxcIngressConfig {
    #[serde(default)]
    pub default: MxcNetworkAction,
    #[serde(default)]
    pub host_loopback: MxcNetworkAction,
}

#[derive(Clone, Copy)]
enum HostPlatform {
    Linux,
    Macos,
    Unsupported,
}

fn host_platform() -> HostPlatform {
    if cfg!(target_os = "linux") {
        HostPlatform::Linux
    } else if cfg!(target_os = "macos") {
        HostPlatform::Macos
    } else {
        HostPlatform::Unsupported
    }
}

fn select_sandbox_type(
    containment: MxcContainment,
    platform: HostPlatform,
) -> Result<SandboxType, SandboxTransformError> {
    match (containment, platform) {
        (MxcContainment::Process, HostPlatform::Linux)
        | (MxcContainment::Bubblewrap, HostPlatform::Linux) => Ok(SandboxType::LinuxSeccomp),
        (MxcContainment::Process, HostPlatform::Macos)
        | (MxcContainment::Seatbelt, HostPlatform::Macos) => Ok(SandboxType::MacosSeatbelt),
        (MxcContainment::Process, HostPlatform::Unsupported) => {
            Err(SandboxTransformError::PlatformNotSupported)
        }
        (MxcContainment::Bubblewrap, _) => Err(SandboxTransformError::UnsupportedPolicy(
            "MXC bubblewrap containment requires Linux".into(),
        )),
        (MxcContainment::Seatbelt, _) => Err(SandboxTransformError::UnsupportedPolicy(
            "MXC seatbelt containment requires macOS".into(),
        )),
    }
}

fn validate_roots(roots: &[PathBuf], field: &str) -> Result<Vec<PathBuf>, SandboxTransformError> {
    for root in roots {
        if !root.is_absolute()
            || root == Path::new("/")
            || root
                .components()
                .any(|component| component == Component::ParentDir)
        {
            return Err(SandboxTransformError::UnsafePolicy(format!(
                "MXC {field} entries must be absolute non-root paths without '..': {}",
                root.display()
            )));
        }
    }
    Ok(roots.to_vec())
}

fn default_timeout_ms() -> u32 {
    DEFAULT_MXC_TIMEOUT_MS
}

#[cfg(test)]
mod tests {
    use super::*;

    const DENY_ALL: &str = r#"{
        "containment": "process",
        "filesystem": {
            "mount_procfs": false,
            "readonly_paths": ["/opt/toolchain"],
            "readwrite_paths": [],
            "denied_paths": []
        },
        "network": {
            "egress": {"default": "deny"},
            "ingress": {"default": "deny", "host_loopback": "deny"}
        },
        "timeout_ms": 30000
    }"#;

    #[test]
    fn parses_sphinx_mxc_policy_json_and_maps_safe_roots() {
        let config = MxcSandboxConfig::from_json(DENY_ALL).unwrap();
        assert!(!config.filesystem.mount_procfs);
        assert_eq!(config.timeout(), Duration::from_secs(30));
        assert_eq!(config.sandbox_type().unwrap(), expected_current_sandbox());
        assert_eq!(
            config.sandbox_policy().unwrap(),
            SandboxPolicy::ReadOnly {
                file_system: FileSystemSandboxPolicy::ReadOnlyWithRoots {
                    read_only_roots: vec![PathBuf::from("/opt/toolchain")],
                },
                network_access: NetworkSandboxPolicy::NoAccess,
            }
        );
    }

    #[test]
    fn defaults_are_deny_all_no_proc_and_bounded() {
        let config = MxcSandboxConfig::from_json("{}").unwrap();
        assert_eq!(config, MxcSandboxConfig::default());
        assert!(!config.filesystem.mount_procfs);
        assert_eq!(config.timeout_ms, DEFAULT_MXC_TIMEOUT_MS);
        assert_eq!(
            config.network.to_sandbox_policy().unwrap(),
            NetworkSandboxPolicy::NoAccess
        );
        assert_eq!(
            config.sandbox_policy().unwrap(),
            SandboxPolicy::ReadOnly {
                file_system: FileSystemSandboxPolicy::ReadOnly,
                network_access: NetworkSandboxPolicy::NoAccess,
            }
        );
    }

    #[test]
    fn maps_workspace_write_only_when_no_readonly_roots_are_requested() {
        let config =
            MxcSandboxConfig::from_json(r#"{"filesystem":{"readwrite_paths":["/workspace"]}}"#)
                .unwrap();
        assert_eq!(
            config.sandbox_policy().unwrap(),
            SandboxPolicy::WorkspaceWrite {
                writable_roots: vec![PathBuf::from("/workspace")],
                network_access: NetworkSandboxPolicy::NoAccess,
            }
        );
    }

    #[test]
    fn maps_full_network_only_when_all_directional_actions_allow() {
        let config = MxcSandboxConfig::from_json(
            r#"{"network":{"egress":{"default":"allow"},"ingress":{"default":"allow","host_loopback":"allow"}}}"#,
        )
        .unwrap();
        assert_eq!(
            config.network.to_sandbox_policy().unwrap(),
            NetworkSandboxPolicy::FullAccess
        );
    }

    #[test]
    fn rejects_invalid_json_unknown_fields_and_invalid_types() {
        assert!(matches!(
            MxcSandboxConfig::from_json("{"),
            Err(SandboxTransformError::InvalidMxcConfig(_))
        ));
        assert!(MxcSandboxConfig::from_json(r#"{"extra":true}"#).is_err());
        assert!(MxcSandboxConfig::from_json(r#"{"filesystem":{"typo":[]}}"#).is_err());
        assert!(MxcSandboxConfig::from_json(r#"{"filesystem":{"mount_procfs":"false"}}"#).is_err());
    }

    #[test]
    fn rejects_unsafe_or_unrepresentable_filesystem_policies() {
        for path in ["relative", "/", "/workspace/../outside"] {
            let json = format!(r#"{{"filesystem":{{"readonly_paths":["{path}"]}}}}"#);
            assert!(matches!(
                MxcSandboxConfig::from_json(&json).unwrap().sandbox_policy(),
                Err(SandboxTransformError::UnsafePolicy(_))
            ));
        }
        for json in [
            r#"{"filesystem":{"denied_paths":["/secret"]}}"#,
            r#"{"filesystem":{"readonly_paths":["/tools"],"readwrite_paths":["/workspace"]}}"#,
        ] {
            assert!(matches!(
                MxcSandboxConfig::from_json(json).unwrap().sandbox_policy(),
                Err(SandboxTransformError::UnsupportedPolicy(_))
            ));
        }
    }

    #[test]
    fn rejects_mixed_network_actions_and_explicit_rules() {
        for json in [
            r#"{"network":{"egress":{"default":"allow"}}}"#,
            r#"{"network":{"ingress":{"default":"allow"}}}"#,
            r#"{"network":{"ingress":{"host_loopback":"allow"}}}"#,
            r#"{"network":{"egress":{"allow":[{}]}}}"#,
            r#"{"network":{"egress":{"deny":[{}]}}}"#,
        ] {
            assert!(matches!(
                MxcSandboxConfig::from_json(json)
                    .unwrap()
                    .network
                    .to_sandbox_policy(),
                Err(SandboxTransformError::UnsupportedPolicy(_))
            ));
        }
    }

    #[test]
    fn validates_timeout_boundaries() {
        for timeout in [0, MAX_MXC_TIMEOUT_MS + 1] {
            let json = format!(r#"{{"timeout_ms":{timeout}}}"#);
            assert!(matches!(
                MxcSandboxConfig::from_json(&json).unwrap().sandbox_policy(),
                Err(SandboxTransformError::InvalidMxcConfig(_))
            ));
        }
        for timeout in [1, MAX_MXC_TIMEOUT_MS] {
            let json = format!(r#"{{"timeout_ms":{timeout}}}"#);
            assert!(MxcSandboxConfig::from_json(&json)
                .unwrap()
                .sandbox_policy()
                .is_ok());
        }
    }

    #[test]
    fn containment_mapping_covers_supported_and_rejected_platforms() {
        for (containment, platform, expected) in [
            (
                MxcContainment::Process,
                HostPlatform::Linux,
                SandboxType::LinuxSeccomp,
            ),
            (
                MxcContainment::Bubblewrap,
                HostPlatform::Linux,
                SandboxType::LinuxSeccomp,
            ),
            (
                MxcContainment::Process,
                HostPlatform::Macos,
                SandboxType::MacosSeatbelt,
            ),
            (
                MxcContainment::Seatbelt,
                HostPlatform::Macos,
                SandboxType::MacosSeatbelt,
            ),
        ] {
            assert_eq!(
                select_sandbox_type(containment, platform).unwrap(),
                expected
            );
        }
        assert!(matches!(
            select_sandbox_type(MxcContainment::Process, HostPlatform::Unsupported),
            Err(SandboxTransformError::PlatformNotSupported)
        ));
        assert!(matches!(
            select_sandbox_type(MxcContainment::Bubblewrap, HostPlatform::Macos),
            Err(SandboxTransformError::UnsupportedPolicy(_))
        ));
        assert!(matches!(
            select_sandbox_type(MxcContainment::Seatbelt, HostPlatform::Linux),
            Err(SandboxTransformError::UnsupportedPolicy(_))
        ));
    }

    #[cfg(target_os = "linux")]
    fn expected_current_sandbox() -> SandboxType {
        SandboxType::LinuxSeccomp
    }

    #[cfg(target_os = "macos")]
    fn expected_current_sandbox() -> SandboxType {
        SandboxType::MacosSeatbelt
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    fn expected_current_sandbox() -> SandboxType {
        unreachable!("current sandbox platform is not supported by this crate")
    }
}
