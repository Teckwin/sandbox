//! macOS Seatbelt (sandbox-exec) Implementation
//!
//! Provides macOS sandboxing via the native sandbox-exec mechanism.

#![allow(dead_code)]

#[allow(unused_imports)]
use std::collections::{BTreeMap, BTreeSet, HashMap};
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
    host.eq_ignore_ascii_case("localhost") || host == "127.0.0.1" || host == "::1"
}

fn proxy_scheme_default_port(scheme: &str) -> u16 {
    match scheme {
        "https" => 443,
        "socks5" | "socks5h" | "socks4" | "socks4a" => 1080,
        _ => 80,
    }
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

/// Create Seatbelt policy string from sandbox policy
pub fn create_seatbelt_policy(policy: &super::SandboxPolicy) -> String {
    match policy {
        super::SandboxPolicy::DangerFullAccess => {
            // No restrictions
            "(version 1)".to_string()
        }
        super::SandboxPolicy::ReadOnly {
            file_system: _,
            network_access,
        } => {
            let mut sbpl = String::from("(version 1)\n(deny default)\n");

            // Allow basic process operations
            sbpl.push_str("(allow process-exec)\n");
            sbpl.push_str("(allow process-fork)\n");

            // File read access
            sbpl.push_str("(allow file-read*)\n");

            // Network access based on policy
            match network_access {
                super::NetworkSandboxPolicy::FullAccess => {
                    sbpl.push_str("(allow network*)\n");
                }
                super::NetworkSandboxPolicy::NoAccess => {
                    // No network access - don't add network rules
                }
                super::NetworkSandboxPolicy::Localhost => {
                    sbpl.push_str("(allow network* (local ip))\n");
                }
                super::NetworkSandboxPolicy::Proxy => {
                    // For proxy, we'll generate dynamic rules based on env
                    sbpl.push_str("(allow network*)\n");
                }
            }

            sbpl
        }
        super::SandboxPolicy::ExternalSandbox { network_access } => {
            let mut sbpl = String::from("(version 1)\n");
            sbpl.push_str(match network_access {
                super::NetworkSandboxPolicy::NoAccess => "(deny network*)\n",
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
                    "(allow file-write* (subpath \"{}\"))\n",
                    root.display()
                ));
            }

            // Network access
            match network_access {
                super::NetworkSandboxPolicy::FullAccess => {
                    sbpl.push_str("(allow network*)\n");
                }
                super::NetworkSandboxPolicy::NoAccess => {}
                _ => {
                    sbpl.push_str("(allow network*)\n");
                }
            }

            sbpl
        }
    }
}

/// Create Seatbelt command arguments from policy
pub fn create_seatbelt_command_args_for_policies(
    argv: Vec<String>,
    _file_system_policy: &super::FileSystemSandboxPolicy,
    network_policy: super::NetworkSandboxPolicy,
    _cwd: &Path,
    _enforce_managed_network: bool,
    _network: Option<&()>,
) -> Vec<String> {
    // Create basic policy
    let policy = match network_policy {
        super::NetworkSandboxPolicy::FullAccess => super::SandboxPolicy::ReadOnly {
            file_system: super::FileSystemSandboxPolicy::ReadOnly,
            network_access: network_policy,
        },
        super::NetworkSandboxPolicy::NoAccess => super::SandboxPolicy::ReadOnly {
            file_system: super::FileSystemSandboxPolicy::ReadOnly,
            network_access: network_policy,
        },
        _ => super::SandboxPolicy::ReadOnly {
            file_system: super::FileSystemSandboxPolicy::ReadOnly,
            network_access: network_policy,
        },
    };

    let policy_string = create_seatbelt_policy(&policy);

    let mut args = vec!["-p".to_string(), policy_string];
    args.push("--".to_string());
    args.extend(argv);

    args
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

        let sbpl = create_seatbelt_policy(&policy);
        assert!(sbpl.contains("(deny default)"));
        assert!(sbpl.contains("(allow file-read*)"));
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
}
