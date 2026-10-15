#![no_main]

use ai_sandbox::linux_sandbox::{create_freebsd_sandbox_args, PledgePromises};
use ai_sandbox::{
    create_pledge_promises_from_policy, FileSystemSandboxPolicy, NetworkSandboxPolicy,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let filesystem = match data.first().copied().unwrap_or_default() % 4 {
        0 => FileSystemSandboxPolicy::ReadOnly,
        1 => FileSystemSandboxPolicy::FullAccess,
        2 => FileSystemSandboxPolicy::External,
        _ => FileSystemSandboxPolicy::WorkspaceWrite {
            writable_roots: Vec::new(),
        },
    };
    let network = match data.get(1).copied().unwrap_or_default() % 4 {
        0 => NetworkSandboxPolicy::NoAccess,
        1 => NetworkSandboxPolicy::FullAccess,
        2 => NetworkSandboxPolicy::Localhost,
        _ => NetworkSandboxPolicy::Proxy,
    };
    let promises = create_pledge_promises_from_policy(&filesystem, network);
    let serialized = promises.to_pledge_string();
    assert!(serialized.is_ascii());
    if matches!(
        network,
        NetworkSandboxPolicy::NoAccess
            | NetworkSandboxPolicy::Localhost
            | NetworkSandboxPolicy::Proxy
    ) {
        assert!(!serialized.split_whitespace().any(|promise| promise == "inet"));
        assert!(!serialized.split_whitespace().any(|promise| promise == "dns"));
    }

    let mut arbitrary = PledgePromises::default_safe();
    let bits = data.get(2).copied().unwrap_or_default();
    arbitrary.inet = bits & 1 != 0;
    arbitrary.dns = bits & 2 != 0;
    arbitrary.exec = bits & 4 != 0;
    arbitrary.proc = bits & 8 != 0;
    assert!(arbitrary.to_pledge_string().is_ascii());

    let argv = data
        .chunks(16)
        .take(16)
        .map(|chunk| String::from_utf8_lossy(chunk).into_owned())
        .collect::<Vec<_>>();
    let level = match bits % 3 {
        0 => ai_sandbox::linux_sandbox::CapsicumLevel::Disabled,
        1 => ai_sandbox::linux_sandbox::CapsicumLevel::Basic,
        _ => ai_sandbox::linux_sandbox::CapsicumLevel::Strict,
    };
    let _ = create_freebsd_sandbox_args(&argv, level);
});