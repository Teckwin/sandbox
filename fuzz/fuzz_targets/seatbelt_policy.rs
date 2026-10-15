#![no_main]

use ai_sandbox::sandboxing::seatbelt::create_seatbelt_policy;
use ai_sandbox::{FileSystemSandboxPolicy, NetworkSandboxPolicy, SandboxPolicy};
use libfuzzer_sys::fuzz_target;
use std::path::PathBuf;

fuzz_target!(|data: &[u8]| {
    let network = match data.first().copied().unwrap_or_default() % 4 {
        0 => NetworkSandboxPolicy::NoAccess,
        1 => NetworkSandboxPolicy::FullAccess,
        2 => NetworkSandboxPolicy::Localhost,
        _ => NetworkSandboxPolicy::Proxy,
    };
    let roots = String::from_utf8_lossy(data)
        .split('\0')
        .take(8)
        .map(PathBuf::from)
        .collect::<Vec<_>>();
    let filesystem = if data.get(1).copied().unwrap_or_default() & 1 == 0 {
        FileSystemSandboxPolicy::ReadOnly
    } else {
        FileSystemSandboxPolicy::WorkspaceWrite {
            writable_roots: roots,
        }
    };
    let policy = SandboxPolicy::ReadOnly {
        file_system: filesystem,
        network_access: network,
    };
    let result = create_seatbelt_policy(&policy);

    if matches!(network, NetworkSandboxPolicy::Proxy) {
        assert!(result.is_err());
    }
    if matches!(network, NetworkSandboxPolicy::NoAccess) {
        assert!(!result.unwrap().contains("(allow network*"));
    }
});