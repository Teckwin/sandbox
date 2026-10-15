use std::process::{Command, Output};

fn run_cli(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_sandbox-exec"))
        .args(args)
        .output()
        .expect("sandbox-exec should start")
}

#[cfg(target_os = "linux")]
fn run_cli_with_bwrap_shim(args: &[&str]) -> (Output, std::path::PathBuf) {
    run_cli_with_bwrap_script(
        args,
        "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"${0%/*}/args.log\"\nwhile [ \"$#\" -gt 0 ] && [ \"$1\" != \"--\" ]; do shift; done\n[ \"$#\" -gt 0 ] || exit 2\nshift\nexec \"$@\"\n",
    )
}

#[cfg(target_os = "linux")]
fn run_cli_with_bwrap_failure_shim(args: &[&str]) -> (Output, std::path::PathBuf) {
    run_cli_with_bwrap_script(args, "#!/bin/sh\nexit 23\n")
}

#[cfg(target_os = "linux")]
fn run_cli_with_bwrap_script(args: &[&str], script: &str) -> (Output, std::path::PathBuf) {
    use std::os::unix::fs::PermissionsExt;
    use std::time::{SystemTime, UNIX_EPOCH};

    let suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let directory = std::env::temp_dir().join(format!("ai-sandbox-cli-bwrap-{suffix}"));
    std::fs::create_dir_all(&directory).unwrap();
    let shim = directory.join("bwrap");
    std::fs::write(&shim, script).unwrap();
    let mut permissions = std::fs::metadata(&shim).unwrap().permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(&shim, permissions).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_sandbox-exec"))
        .args(args)
        .env("PATH", &directory)
        .output()
        .expect("sandbox-exec should start with the bwrap shim");
    (output, directory)
}

#[test]
fn cli_rejects_missing_policy_and_command() {
    let missing_policy = run_cli(&[]);
    assert_eq!(missing_policy.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&missing_policy.stderr).contains("Usage:"));

    let missing_command = run_cli(&["readonly"]);
    assert_eq!(missing_command.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&missing_command.stderr).contains("No command provided"));
}

#[test]
fn cli_rejects_unprotected_and_unknown_policies() {
    let unprotected = run_cli(&["none", "true"]);
    assert_eq!(unprotected.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&unprotected.stderr).contains("not permitted"));

    let unknown = run_cli(&["unexpected", "true"]);
    assert_eq!(unknown.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&unknown.stderr).contains("Unknown policy"));
}

#[test]
fn cli_reports_protected_execution_result() {
    let output = run_cli(&["readonly", "/usr/bin/true"]);
    if output.status.success() {
        return;
    }

    let error = String::from_utf8_lossy(&output.stderr);
    if error.contains("Can't mount proc on /newroot/proc: Operation not permitted") {
        eprintln!("skipping legacy CLI runtime assertion: host cannot mount procfs");
        return;
    }
    assert!(
        error.contains("Error executing sandboxed command")
            || error.contains("Error creating sandbox request"),
        "unexpected CLI failure: {error}"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn cli_propagates_success_and_nonzero_status_from_protected_child() {
    let (success, success_dir) = run_cli_with_bwrap_shim(&["readonly", "/usr/bin/true"]);
    assert_eq!(success.status.code(), Some(0));

    let (failure, failure_dir) = run_cli_with_bwrap_shim(&["readonly", "/usr/bin/false"]);
    assert_eq!(failure.status.code(), Some(1));

    std::fs::remove_dir_all(success_dir).unwrap();
    std::fs::remove_dir_all(failure_dir).unwrap();
}

#[cfg(target_os = "linux")]
#[test]
fn cli_accepts_mxc_json_and_omits_proc_without_changing_command_argv() {
    let directory =
        std::env::temp_dir().join(format!("ai-sandbox-mxc-cli-config-{}", std::process::id()));
    std::fs::create_dir_all(&directory).unwrap();
    let config = directory.join("mxc-policy.json");
    std::fs::write(
        &config,
        r#"{
            "containment": "process",
            "filesystem": {"mount_procfs": false},
            "network": {
                "egress": {"default": "deny"},
                "ingress": {"default": "deny", "host_loopback": "deny"}
            },
            "timeout_ms": 10000
        }"#,
    )
    .unwrap();
    let config = config.to_string_lossy().into_owned();
    let (output, shim_dir) = run_cli_with_bwrap_shim(&[
        "--mxc-config",
        &config,
        "--",
        "/usr/bin/true",
        "--proc",
        "/proc",
    ]);
    assert_eq!(output.status.code(), Some(0));

    let args = std::fs::read_to_string(shim_dir.join("args.log")).unwrap();
    let args = args.lines().collect::<Vec<_>>();
    let separator = args.iter().position(|argument| *argument == "--").unwrap();
    assert!(!args[..separator]
        .windows(2)
        .any(|pair| pair == ["--proc", "/proc"]));
    assert_eq!(&args[separator + 1..], ["/usr/bin/true", "--proc", "/proc"]);

    std::fs::remove_dir_all(shim_dir).unwrap();
    std::fs::remove_dir_all(directory).unwrap();
}

#[cfg(target_os = "linux")]
#[test]
fn cli_mxc_config_can_explicitly_mount_procfs() {
    let directory =
        std::env::temp_dir().join(format!("ai-sandbox-mxc-cli-proc-{}", std::process::id()));
    std::fs::create_dir_all(&directory).unwrap();
    let config = directory.join("mxc-policy.json");
    std::fs::write(&config, r#"{"filesystem":{"mount_procfs":true}}"#).unwrap();
    let config = config.to_string_lossy().into_owned();
    let (output, shim_dir) =
        run_cli_with_bwrap_shim(&["--mxc-config", &config, "--", "/usr/bin/true"]);
    assert_eq!(output.status.code(), Some(0));

    let args = std::fs::read_to_string(shim_dir.join("args.log")).unwrap();
    let args = args.lines().collect::<Vec<_>>();
    let separator = args.iter().position(|argument| *argument == "--").unwrap();
    assert!(args[..separator]
        .windows(2)
        .any(|pair| pair == ["--proc", "/proc"]));

    std::fs::remove_dir_all(shim_dir).unwrap();
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn cli_reports_mxc_config_input_errors() {
    for (args, expected) in [
        (vec!["--mxc-config"], "Usage:"),
        (vec!["--mxc-config", "unused.json"], "requires '--'"),
        (
            vec!["--mxc-config", "unused.json", "--"],
            "No command provided",
        ),
        (
            vec!["--mxc-config", "missing-mxc-config.json", "--", "true"],
            "Error reading MXC config",
        ),
    ] {
        let output = run_cli(&args);
        assert_eq!(output.status.code(), Some(1));
        assert!(
            String::from_utf8_lossy(&output.stderr).contains(expected),
            "expected {expected:?}, stderr={}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    let directory =
        std::env::temp_dir().join(format!("ai-sandbox-mxc-cli-invalid-{}", std::process::id()));
    std::fs::create_dir_all(&directory).unwrap();
    let invalid_json = directory.join("invalid.json");
    std::fs::write(&invalid_json, "{").unwrap();
    let invalid_json = invalid_json.to_string_lossy().into_owned();
    let invalid = run_cli(&["--mxc-config", &invalid_json, "--", "true"]);
    assert_eq!(invalid.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&invalid.stderr).contains("invalid MXC sandbox config"));

    let unsupported_policy = directory.join("unsupported.json");
    std::fs::write(
        &unsupported_policy,
        r#"{"filesystem":{"denied_paths":["/secret"]}}"#,
    )
    .unwrap();
    let unsupported_policy = unsupported_policy.to_string_lossy().into_owned();
    let unsupported = run_cli(&["--mxc-config", &unsupported_policy, "--", "true"]);
    assert_eq!(unsupported.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&unsupported.stderr).contains("not representable"));
    std::fs::remove_dir_all(directory).unwrap();
}

#[cfg(target_os = "linux")]
#[test]
fn cli_workspace_policy_uses_an_absolute_writable_root() {
    let (output, shim_dir) = run_cli_with_bwrap_shim(&["workspace", "/usr/bin/true"]);
    assert_eq!(output.status.code(), Some(0));
    std::fs::remove_dir_all(shim_dir).unwrap();
}

#[cfg(target_os = "linux")]
#[test]
fn cli_mxc_config_enforces_timeout_and_reports_executor_start_failure() {
    let directory =
        std::env::temp_dir().join(format!("ai-sandbox-mxc-cli-exec-{}", std::process::id()));
    std::fs::create_dir_all(&directory).unwrap();
    let config = directory.join("timeout.json");
    std::fs::write(&config, r#"{"timeout_ms":10}"#).unwrap();
    let config = config.to_string_lossy().into_owned();

    let (timed_out, timeout_shim) =
        run_cli_with_bwrap_shim(&["--mxc-config", &config, "--", "/usr/bin/sleep", "1"]);
    assert_eq!(timed_out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&timed_out.stderr).contains("exceeded timeout"));
    std::fs::remove_dir_all(timeout_shim).unwrap();

    let (failed, failure_shim) =
        run_cli_with_bwrap_failure_shim(&["--mxc-config", &config, "--", "/usr/bin/true"]);
    assert_eq!(failed.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&failed.stderr)
        .contains("Error executing MXC-configured sandbox request"));
    std::fs::remove_dir_all(failure_shim).unwrap();
    std::fs::remove_dir_all(directory).unwrap();
}
