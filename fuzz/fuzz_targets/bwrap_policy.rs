#![no_main]

use ai_sandbox::linux_sandbox::bwrap::{
    create_readonly_bwrap_command, create_workspace_bwrap_command,
};
use ai_sandbox::NetworkSandboxPolicy;
use libfuzzer_sys::fuzz_target;
use std::path::{Path, PathBuf};

fuzz_target!(|data: &[u8]| {
    let fields: Vec<String> = String::from_utf8_lossy(data)
        .split('\0')
        .take(24)
        .map(str::to_owned)
        .collect();
    let argv = if fields.is_empty() {
        vec!["true".to_string()]
    } else {
        fields.clone()
    };
    let env: Vec<(String, String)> = fields
        .chunks(2)
        .take(8)
        .filter_map(|pair| (pair.len() == 2).then(|| (pair[0].clone(), pair[1].clone())))
        .collect();
    let network = match data.first().copied().unwrap_or_default() % 4 {
        0 => NetworkSandboxPolicy::NoAccess,
        1 => NetworkSandboxPolicy::FullAccess,
        2 => NetworkSandboxPolicy::Localhost,
        _ => NetworkSandboxPolicy::Proxy,
    };
    let _ = create_readonly_bwrap_command(argv.clone(), Path::new("/tmp"), &env, network);

    let root = if data.get(1).copied().unwrap_or_default() & 1 == 0 {
        PathBuf::from("/tmp")
    } else {
        PathBuf::from("/")
    };
    let _ = create_workspace_bwrap_command(
        argv,
        Path::new("/tmp"),
        &[root],
        &env,
        network,
    );
});