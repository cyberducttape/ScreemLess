use serde_json::Value;
use std::process::Command;

#[test]
fn invalid_cli_syntax_uses_documented_exit_code_and_help_remains_successful() {
    let invalid = Command::new(env!("CARGO_BIN_EXE_screamless"))
        .args(["preflight", "--server", "web01"])
        .output()
        .expect("run invalid CLI invocation");
    assert_eq!(invalid.status.code(), Some(3));
    assert!(String::from_utf8_lossy(&invalid.stderr).contains("--operation"));

    let help = Command::new(env!("CARGO_BIN_EXE_screamless"))
        .arg("--help")
        .output()
        .expect("run CLI help");
    assert_eq!(help.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&help.stdout).contains("Usage:"));
}

#[test]
fn invalid_preflight_operation_keeps_code_three_and_json_stdout() {
    let output = Command::new(env!("CARGO_BIN_EXE_screamless"))
        .args([
            "preflight",
            "--server",
            "web01",
            "--operation",
            "migrate",
            "--json",
        ])
        .output()
        .expect("run invalid preflight operation");

    assert_eq!(output.status.code(), Some(3));
    assert!(String::from_utf8_lossy(&output.stderr).contains("Unknown operation"));
    let result: Value = serde_json::from_slice(&output.stdout).expect("stdout is JSON only");
    assert_eq!(result["status"], "invalid_invocation");
    assert_eq!(result["exit_code"], 3);
}
