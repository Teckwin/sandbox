#![no_main]

use ai_sandbox::windows_sandbox::{compute_allow_deny_paths, get_sandbox_level};
use ai_sandbox::windows_sandbox::WindowsSandboxPolicy;
use libfuzzer_sys::fuzz_target;
use std::path::{Path, PathBuf};

fuzz_target!(|data: &[u8]| {
    let fields: Vec<PathBuf> = String::from_utf8_lossy(data)
        .split('\0')
        .take(16)
        .map(PathBuf::from)
        .collect();
    let split = fields.len() / 2;
    let network_allowed = data.first().copied().unwrap_or_default() & 1 != 0;
    let policy = WindowsSandboxPolicy {
        read_allow: fields[..split].to_vec(),
        write_deny: fields[split..].to_vec(),
        network_allowed,
        use_private_desktop: data.get(1).copied().unwrap_or_default() & 1 != 0,
    };
    let level = get_sandbox_level(&policy);
    let (allow, _) = compute_allow_deny_paths(&policy, Path::new("/tmp"));

    assert!(allow.iter().any(|path| path == Path::new("/tmp")));
    if policy.read_allow.is_empty() && policy.write_deny.is_empty() && network_allowed {
        assert_eq!(level, ai_sandbox::WindowsSandboxLevel::Disabled);
    } else {
        assert_ne!(level, ai_sandbox::WindowsSandboxLevel::Disabled);
    }
});