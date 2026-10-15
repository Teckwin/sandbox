//! macOS Seatbelt (sandbox-exec) Implementation
//!
//! Provides macOS sandboxing via the native sandbox-exec mechanism.

#![allow(dead_code)]

#[allow(unused_imports)]
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::net::IpAddr;
use std::path::Path;

/// Path to the macOS sandbox-exec executable
pub const MACOS_PATH_TO_SEATBELT_EXECUTABLE: &str = "/usr/bin/sandbox-exec";

/// Base Seatbelt policy for basic sandbox
const MACOS_SEATBELT_BASE_POLICY: &str = r#"
(version 1)
(deny default)
(allow process-exec*)
(allow process-fork*)
"#;

/// Network policy for Seatbelt
const MACOS_SEATBELT_NETWORK_POLICY: &str = r#"
(allow network*)
"#;

/// Restricted read-only policy
const MACOS_RESTRICTED_READ_ONLY_POLICY: &str = r#"
(version 1)
(deny default)
(allow process-exec)
(allow process-fork)
(allow file-read*)
(allow network*)
"#;

fn is_loopback_host(host: &str) -> bool {
    let host_lower = host.to_lowercase();
    matches!(
        host_lower.as_str(),
        "localhost" | "localhost6" | "ip6-localhost"
    ) || host
        .strip_prefix('[')
        .and_then(|host| host.strip_suffix(']'))
        .unwrap_or(host)
        .parse::<IpAddr>()
        .is_ok_and(|address| address.is_loopback())
}

fn proxy_scheme_default_port(scheme: &str) -> u16 {
    match scheme {
        "https" => 443,
        "socks5" | "socks5h" | "socks4" | "socks4a" => 1080,
        _ => 80,
    }
}

fn escape_sbpl_string(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
}

fn quote_sbpl_path(path: &Path) -> String {
    format!("\"{}\"", escape_sbpl_string(&path.to_string_lossy()))
}

/// Get proxy ports from environment variables
pub fn proxy_loopback_ports_from_env(env: &HashMap<String, String>) -> Vec<u16> {
    let proxy_keys = [
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "http_proxy",
        "https_proxy",
        "all_proxy",
    ];

    let mut ports = BTreeSet::new();

    for key in &proxy_keys {
        let Some(proxy_url) = env.get(*key) else {
            continue;
        };
        let trimmed = proxy_url.trim();
        if trimmed.is_empty() {
            continue;
        }

        let candidate = if trimmed.contains("://") {
            trimmed.to_string()
        } else {
            format!("http://{trimmed}")
        };

        if let Ok(parsed) = url::Url::parse(&candidate) {
            if let Some(host) = parsed.host_str() {
                if is_loopback_host(host) {
                    let scheme = parsed.scheme().to_ascii_lowercase();
                    let port = parsed
                        .port()
                        .unwrap_or_else(|| proxy_scheme_default_port(&scheme));
                    ports.insert(port);
                }
            }
        }
    }

    ports.into_iter().collect()
}

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum SeatbeltPolicyError {
    #[error("Seatbelt cannot enforce the requested proxy network policy")]
    UnsupportedProxyNetworkPolicy,
    #[error("Seatbelt cannot enforce the requested external-sandbox network policy")]
    UnsupportedExternalNetworkPolicy,
    #[error("invalid Seatbelt read-only root: {0}")]
    InvalidReadOnlyRoot(String),
}

/// Create Seatbelt policy string from sandbox policy.
pub fn create_seatbelt_policy(
    policy: &super::SandboxPolicy,
) -> Result<String, SeatbeltPolicyError> {
    let network_policy = policy.network_policy();
    if matches!(network_policy, super::NetworkSandboxPolicy::Proxy) {
        return Err(SeatbeltPolicyError::UnsupportedProxyNetworkPolicy);
    }
    if matches!(policy, super::SandboxPolicy::ExternalSandbox { .. })
        && matches!(network_policy, super::NetworkSandboxPolicy::Localhost)
    {
        return Err(SeatbeltPolicyError::UnsupportedExternalNetworkPolicy);
    }

    Ok(match policy {
        super::SandboxPolicy::DangerFullAccess => {
            // No restrictions
            "(version 1)".to_string()
        }
        super::SandboxPolicy::ReadOnly {
            file_system,
            network_access,
        } => {
            let mut sbpl = String::from("(version 1)\n(deny default)\n");

            // Allow basic process operations
            sbpl.push_str("(allow process-exec)\n");
            sbpl.push_str("(allow process-fork)\n");

            match file_system {
                super::FileSystemSandboxPolicy::External => {}
                super::FileSystemSandboxPolicy::ReadOnlyWithRoots { read_only_roots } => {
                    let mut roots = BTreeSet::new();
                    for root in [
                        "/System",
                        "/usr",
                        "/bin",
                        "/sbin",
                        "/Library/Apple/System/Library",
                        "/private/var/db/dyld",
                    ] {
                        roots.insert(root.to_string());
                    }
                    for root in read_only_roots {
                        if !root.is_absolute()
                            || root == Path::new("/")
                            || root
                                .components()
                                .any(|component| component == std::path::Component::ParentDir)
                        {
                            return Err(SeatbeltPolicyError::InvalidReadOnlyRoot(
                                root.display().to_string(),
                            ));
                        }
                        roots.insert(root.to_string_lossy().into_owned());
                    }
                    for root in roots {
                        sbpl.push_str(&format!(
                            "(allow file-read* (subpath {}))\n",
                            quote_sbpl_path(Path::new(&root))
                        ));
                    }
                }
                _ => sbpl.push_str("(allow file-read*)\n"),
            }

            // Network access based on policy
            match network_access {
                super::NetworkSandboxPolicy::FullAccess => {
                    sbpl.push_str("(allow network*)\n");
                }
                super::NetworkSandboxPolicy::NoAccess => {
                    // No network access - don't add network rules
                }
                super::NetworkSandboxPolicy::Localhost => {
                    // Restrict to specific loopback addresses only
                    sbpl.push_str("(allow network* (local ip \"127.0.0.1\"))\n");
                    sbpl.push_str("(allow network* (local ip \"::1\"))\n");
                }
                super::NetworkSandboxPolicy::Proxy => unreachable!("proxy policy rejected above"),
            }

            sbpl
        }
        super::SandboxPolicy::ExternalSandbox { network_access } => {
            let mut sbpl = String::from("(version 1)\n");
            sbpl.push_str(match network_access {
                super::NetworkSandboxPolicy::NoAccess => "(deny network*)\n",
                super::NetworkSandboxPolicy::Localhost => {
                    unreachable!("external localhost policy rejected above")
                }
                _ => "",
            });
            sbpl
        }
        super::SandboxPolicy::WorkspaceWrite {
            writable_roots,
            network_access,
        } => {
            let mut sbpl = String::from("(version 1)\n(deny default)\n");

            // Allow process operations
            sbpl.push_str("(allow process-exec)\n");
            sbpl.push_str("(allow process-fork)\n");

            // File read access everywhere
            sbpl.push_str("(allow file-read*)\n");

            // File write access to specific roots
            for root in writable_roots {
                sbpl.push_str(&format!(
                    "(allow file-write* (subpath {}))\n",
                    quote_sbpl_path(root)
                ));
            }

            // Network access
            match network_access {
                super::NetworkSandboxPolicy::FullAccess => {
                    sbpl.push_str("(allow network*)\n");
                }
                super::NetworkSandboxPolicy::NoAccess => {
                    // No network access
                }
                super::NetworkSandboxPolicy::Localhost => {
                    // Restrict to specific loopback addresses only
                    sbpl.push_str("(allow network* (local ip \"127.0.0.1\"))\n");
                    sbpl.push_str("(allow network* (local ip \"::1\"))\n");
                }
                super::NetworkSandboxPolicy::Proxy => unreachable!("proxy policy rejected above"),
            }

            sbpl
        }
    })
}

/// Create Seatbelt command arguments from policy
pub fn create_seatbelt_command_args_for_policies(
    argv: Vec<String>,
    file_system_policy: &super::FileSystemSandboxPolicy,
    network_policy: super::NetworkSandboxPolicy,
    _cwd: &Path,
    _enforce_managed_network: bool,
    _network: Option<&()>,
) -> Result<Vec<String>, SeatbeltPolicyError> {
    let policy = match file_system_policy {
        super::FileSystemSandboxPolicy::WorkspaceWrite { writable_roots } => {
            super::SandboxPolicy::WorkspaceWrite {
                writable_roots: writable_roots.clone(),
                network_access: network_policy,
            }
        }
        file_system_policy => super::SandboxPolicy::ReadOnly {
            file_system: file_system_policy.clone(),
            network_access: network_policy,
        },
    };

    let policy_string = create_seatbelt_policy(&policy)?;

    let mut args = vec!["-p".to_string(), policy_string];
    args.push("--".to_string());
    args.extend(argv);

    Ok(args)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_seatbelt_policy_readonly() {
        let policy = super::super::SandboxPolicy::ReadOnly {
            file_system: super::super::FileSystemSandboxPolicy::ReadOnly,
            network_access: super::super::NetworkSandboxPolicy::NoAccess,
        };

        let sbpl = create_seatbelt_policy(&policy).unwrap();
        assert!(sbpl.contains("(deny default)"));
        assert!(sbpl.contains("(allow file-read*)"));
    }

    #[test]
    fn readonly_roots_generate_scoped_file_read_rules() {
        let policy = super::super::SandboxPolicy::ReadOnly {
            file_system: super::super::FileSystemSandboxPolicy::ReadOnlyWithRoots {
                read_only_roots: vec![
                    Path::new("/workspace").to_path_buf(),
                    Path::new("/toolchain").to_path_buf(),
                ],
            },
            network_access: super::super::NetworkSandboxPolicy::NoAccess,
        };

        let sbpl = create_seatbelt_policy(&policy).unwrap();

        assert!(sbpl.contains("(allow file-read* (subpath \"/workspace\"))"));
        assert!(sbpl.contains("(allow file-read* (subpath \"/toolchain\"))"));
        assert!(!sbpl.contains("(allow file-read*)\n"));
        assert!(!sbpl.contains("(allow network*"));
    }

    #[test]
    fn readonly_roots_reject_relative_root_filesystem_root_and_traversal() {
        for root in ["relative", "/", "/workspace/../outside"] {
            let policy = super::super::SandboxPolicy::ReadOnly {
                file_system: super::super::FileSystemSandboxPolicy::ReadOnlyWithRoots {
                    read_only_roots: vec![Path::new(root).to_path_buf()],
                },
                network_access: super::super::NetworkSandboxPolicy::NoAccess,
            };

            assert!(matches!(
                create_seatbelt_policy(&policy),
                Err(SeatbeltPolicyError::InvalidReadOnlyRoot(_))
            ));
        }
    }

    #[test]
    fn test_proxy_loopback_ports() {
        let mut env = HashMap::new();
        env.insert(
            "HTTP_PROXY".to_string(),
            "http://localhost:8080".to_string(),
        );

        let ports = proxy_loopback_ports_from_env(&env);
        assert!(ports.contains(&8080));
    }

    #[test]
    fn proxy_env_parser_filters_invalid_non_loopback_and_deduplicates_ports() {
        let env = HashMap::from([
            ("HTTP_PROXY".into(), " localhost ".into()),
            ("HTTPS_PROXY".into(), "https://127.0.0.1".into()),
            ("ALL_PROXY".into(), "socks5h://[::1]:1080".into()),
            ("http_proxy".into(), "http://localhost:8080".into()),
            ("https_proxy".into(), "http://192.168.1.1:3128".into()),
            ("all_proxy".into(), "not a url".into()),
        ]);
        assert_eq!(
            proxy_loopback_ports_from_env(&env),
            vec![80, 443, 1080, 8080]
        );

        let ignored = HashMap::from([
            ("HTTP_PROXY".into(), "  ".into()),
            ("HTTPS_PROXY".into(), "http://0.0.0.0:8080".into()),
            ("ALL_PROXY".into(), "http://example.com:1080".into()),
            ("all_proxy".into(), "file:///tmp/proxy".into()),
        ]);
        assert!(proxy_loopback_ports_from_env(&ignored).is_empty());
    }

    // ============================================================================
    // 新增测试: Localhost 网络策略
    // ============================================================================

    #[test]
    fn test_seatbelt_policy_localhost_restricted() {
        let policy = super::super::SandboxPolicy::ReadOnly {
            file_system: super::super::FileSystemSandboxPolicy::ReadOnly,
            network_access: super::super::NetworkSandboxPolicy::Localhost,
        };

        let sbpl = create_seatbelt_policy(&policy).unwrap();
        // Localhost policy should restrict to specific loopback addresses
        assert!(sbpl.contains("127.0.0.1"));
        assert!(sbpl.contains("::1"));
        // Should NOT contain the permissive "(allow network* (local ip))"
        assert!(!sbpl.contains("(allow network* (local ip))"));
    }

    #[test]
    fn test_seatbelt_policy_no_network() {
        let policy = super::super::SandboxPolicy::ReadOnly {
            file_system: super::super::FileSystemSandboxPolicy::ReadOnly,
            network_access: super::super::NetworkSandboxPolicy::NoAccess,
        };

        let sbpl = create_seatbelt_policy(&policy).unwrap();
        // No network should not contain network allow rules
        assert!(!sbpl.contains("(allow network"));
    }

    #[test]
    fn test_seatbelt_policy_full_access() {
        let policy = super::super::SandboxPolicy::ReadOnly {
            file_system: super::super::FileSystemSandboxPolicy::ReadOnly,
            network_access: super::super::NetworkSandboxPolicy::FullAccess,
        };

        let sbpl = create_seatbelt_policy(&policy).unwrap();
        // FullAccess should allow all network
        assert!(sbpl.contains("(allow network*)"));
    }

    #[test]
    fn test_seatbelt_workspace_write_with_localhost() {
        let policy = super::super::SandboxPolicy::WorkspaceWrite {
            writable_roots: vec![std::path::PathBuf::from("/tmp")],
            network_access: super::super::NetworkSandboxPolicy::Localhost,
        };

        let sbpl = create_seatbelt_policy(&policy).unwrap();
        // Should allow file write to /tmp
        assert!(sbpl.contains("/tmp"));
        // Should restrict localhost
        assert!(sbpl.contains("127.0.0.1"));
        assert!(sbpl.contains("::1"));
    }

    #[test]
    fn proxy_policy_fails_closed_instead_of_allowing_all_network() {
        let policy = super::super::SandboxPolicy::ReadOnly {
            file_system: super::super::FileSystemSandboxPolicy::ReadOnly,
            network_access: super::super::NetworkSandboxPolicy::Proxy,
        };

        assert_eq!(
            create_seatbelt_policy(&policy),
            Err(SeatbeltPolicyError::UnsupportedProxyNetworkPolicy)
        );
    }

    #[test]
    fn mock_seatbelt_launcher_receives_literal_argv() {
        let args = create_seatbelt_command_args_for_policies(
            vec!["tool".to_string(), "$(not-a-shell)".to_string()],
            &super::super::FileSystemSandboxPolicy::ReadOnly,
            super::super::NetworkSandboxPolicy::NoAccess,
            Path::new("/workspace"),
            false,
            None,
        )
        .unwrap();
        let mut launcher = MockSeatbeltLauncher::default();
        launcher.launch(MACOS_PATH_TO_SEATBELT_EXECUTABLE, args);

        assert_eq!(launcher.executable, MACOS_PATH_TO_SEATBELT_EXECUTABLE);
        assert_eq!(launcher.args[launcher.args.len() - 3], "--");
        assert_eq!(launcher.args[launcher.args.len() - 2], "tool");
        assert_eq!(launcher.args.last().unwrap(), "$(not-a-shell)");
    }

    #[derive(Default)]
    struct MockSeatbeltLauncher {
        executable: String,
        args: Vec<String>,
    }

    impl MockSeatbeltLauncher {
        fn launch(&mut self, executable: &str, args: Vec<String>) {
            self.executable = executable.to_string();
            self.args = args;
        }
    }

    #[test]
    fn test_is_loopback_host() {
        assert!(is_loopback_host("localhost"));
        assert!(is_loopback_host("127.0.0.1"));
        assert!(is_loopback_host("::1"));
        assert!(is_loopback_host("[::1]"));
        assert!(is_loopback_host("127.0.0.2"));
        assert!(is_loopback_host("127.0.0.255"));
        assert!(is_loopback_host("0:0:0:0:0:0:0:1"));
        assert!(!is_loopback_host("192.168.1.1"));
        assert!(!is_loopback_host("8.8.8.8"));
        assert!(!is_loopback_host("0.0.0.0"));
        assert!(!is_loopback_host("::"));
        assert!(!is_loopback_host("[2001:db8::1]"));
        assert!(!is_loopback_host("::1.attacker.example"));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn native_seatbelt_readonly_policy_denies_file_creation() {
        use std::process::Command;
        use std::time::{SystemTime, UNIX_EPOCH};

        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory = std::env::temp_dir().join(format!("ai-sandbox-seatbelt-{suffix}"));
        std::fs::create_dir_all(&directory).unwrap();
        let denied_path = directory.join("denied-write");
        let args = create_seatbelt_command_args_for_policies(
            vec![
                "/usr/bin/touch".into(),
                denied_path.to_string_lossy().into_owned(),
            ],
            &super::super::FileSystemSandboxPolicy::ReadOnly,
            super::super::NetworkSandboxPolicy::NoAccess,
            &directory,
            false,
            None,
        )
        .unwrap();
        let output = Command::new(MACOS_PATH_TO_SEATBELT_EXECUTABLE)
            .args(args)
            .output()
            .expect("sandbox-exec should be available on macOS");

        assert!(!output.status.success());
        assert!(String::from_utf8_lossy(&output.stderr).contains("Operation not permitted"));
        assert!(!denied_path.exists());
        std::fs::remove_dir_all(directory).unwrap();
    }
}
