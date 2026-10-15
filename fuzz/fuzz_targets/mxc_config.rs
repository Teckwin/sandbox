#![no_main]

use ai_sandbox::{MxcSandboxConfig, SandboxCommand, SandboxManager};
use libfuzzer_sys::fuzz_target;
use std::collections::HashMap;
use std::ffi::OsString;
use std::path::PathBuf;

const PROGRAM: &str = "/usr/bin/true";
const ARGUMENT: &str = "mxc-config-fuzz";

fuzz_target!(|data: &[u8]| {
    let Ok(json) = std::str::from_utf8(data) else {
        return;
    };
    let Ok(config) = MxcSandboxConfig::from_json(json) else {
        return;
    };
    let command = SandboxCommand {
        program: OsString::from(PROGRAM),
        args: vec![ARGUMENT.to_string()],
        cwd: PathBuf::from("/tmp"),
        env: HashMap::new(),
    };
    let Ok(request) = SandboxManager::new().create_exec_request_from_mxc_json(command, json) else {
        return;
    };

    let expected_argv = [PROGRAM.to_string(), ARGUMENT.to_string()];
    assert!(request.command.ends_with(&expected_argv));

    #[cfg(target_os = "linux")]
    {
        let mounted_procfs = request
            .command
            .windows(2)
            .any(|pair| pair == ["--proc", "/proc"]);
        assert_eq!(mounted_procfs, config.filesystem.mount_procfs);
    }
});
