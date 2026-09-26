use serde_json::Value;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

#[test]
fn infrastructure_json_is_stdout_only_and_uses_ordered_host_array() {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let db_path = std::env::temp_dir().join(format!(
        "screamless-cli-json-{}-{nonce}.db",
        std::process::id()
    ));

    let output = Command::new(env!("CARGO_BIN_EXE_screamless"))
        .args([
            "--db",
            db_path.to_str().unwrap(),
            "infrastructure",
            "--servers",
            "node-a,node-b",
            "--format",
            "json",
        ])
        .output()
        .expect("run infrastructure JSON command");

    for suffix in ["", "-wal", "-shm"] {
        let path = format!("{}{suffix}", db_path.display());
        let _ = std::fs::remove_file(path);
    }

    assert!(
        output.status.success(),
        "command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        output.stderr.is_empty(),
        "unexpected stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let json: Value = serde_json::from_slice(&output.stdout).expect("stdout must be JSON only");
    assert_eq!(json["schema_version"], "1.0");
    assert_eq!(json["hosts"].as_array().unwrap().len(), 2);
    assert_eq!(json["hosts"][0]["hostname"], "node-a");
    assert_eq!(json["hosts"][1]["hostname"], "node-b");
    assert!(
        json.get("analyses").is_none(),
        "analysis payload should not be duplicated"
    );
}
