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
            "node-a,node-b,NODE-A.,node-b",
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
    assert_eq!(json["schema_version"], "3.1");
    assert_eq!(json["servers_analyzed"], 2);
    assert_eq!(
        json["observation_window"]["hosts_requested"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    assert_eq!(json["hosts"].as_array().unwrap().len(), 2);
    assert_eq!(json["hosts"][0]["hostname"], "node-a");
    assert_eq!(json["hosts"][1]["hostname"], "node-b");
    assert!(
        json.get("analyses").is_none(),
        "analysis payload should not be duplicated"
    );
}

#[test]
fn report_json_is_versioned_and_stdout_only() {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let db_path = std::env::temp_dir().join(format!(
        "screamless-report-json-{}-{nonce}.db",
        std::process::id()
    ));

    let output = Command::new(env!("CARGO_BIN_EXE_screamless"))
        .args([
            "--db",
            db_path.to_str().unwrap(),
            "report",
            "--format",
            "json",
        ])
        .output()
        .expect("run report JSON command");

    for suffix in ["", "-wal", "-shm"] {
        let path = format!("{}{suffix}", db_path.display());
        let _ = std::fs::remove_file(path);
    }

    assert!(
        output.status.success(),
        "command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty(), "unexpected stderr");
    let json: Value = serde_json::from_slice(&output.stdout).expect("stdout must be JSON only");
    assert_eq!(json["schema_version"], "2.2");
    assert!(json["host_identity"].is_object());
    assert!(json["host_identity"].get("interface_addresses").is_some());
    assert_eq!(json["collector_version"], env!("CARGO_PKG_VERSION"));
    assert!(json["generated_at"].as_str().is_some());
    assert!(json["observation_period"].is_object());
}

#[test]
fn preflight_json_keeps_insufficient_evidence_blocking_after_impact_ack() {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let db_path = std::env::temp_dir().join(format!(
        "screamless-preflight-json-{}-{nonce}.db",
        std::process::id()
    ));

    let output = Command::new(env!("CARGO_BIN_EXE_screamless"))
        .args([
            "--db",
            db_path.to_str().unwrap(),
            "preflight",
            "--server",
            "node-a",
            "--operation",
            "restart",
            "--json",
            "--acknowledge-impact",
        ])
        .output()
        .expect("run preflight JSON command");

    for suffix in ["", "-wal", "-shm"] {
        let path = format!("{}{suffix}", db_path.display());
        let _ = std::fs::remove_file(path);
    }

    assert_eq!(output.status.code(), Some(4));
    let json: Value = serde_json::from_slice(&output.stdout).expect("stdout must be JSON only");
    assert_eq!(json["schema_version"], "1.1");
    assert_eq!(json["status"], "insufficient_evidence");
    assert_eq!(json["exit_code"], 4);
    assert_eq!(json["impact_acknowledged"], false);
    assert_eq!(json["total_snapshots"], 0);
    assert_eq!(json["fleet_scope_complete"], false);
    assert_eq!(json["observation_coverage"]["fleet_scope_complete"], false);
    assert!(json["observation_coverage"]["remaining_unknowns"]
        .as_array()
        .unwrap()
        .iter()
        .any(|unknown| unknown
            .as_str()
            .is_some_and(|message| message.contains("expected fleet inventory is not attested"))));
    assert_eq!(json["observation_window_hours"], 168);
    assert!(json["observation_coverage"].is_object());
    assert!(json["observation_coverage"]["remaining_unknowns"].is_array());
    assert_eq!(json["inbound_dependencies"], 0);
    assert_eq!(json["inbound_dependency_evidence"], serde_json::json!([]));
    assert!(json["probe_statuses"].is_object());
    assert_eq!(json["fleet_scope_complete"], false);
}

#[test]
fn preflight_requires_evidence_for_every_operator_supplied_fleet_host() {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let db_path = std::env::temp_dir().join(format!(
        "screamless-preflight-fleet-{}-{nonce}.db",
        std::process::id()
    ));
    let roster_path = std::env::temp_dir().join(format!(
        "screamless-preflight-fleet-{}-{nonce}.txt",
        std::process::id()
    ));
    std::fs::write(&roster_path, "node-a\nnode-b\n").unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_screamless"))
        .args([
            "--db",
            db_path.to_str().unwrap(),
            "preflight",
            "--server",
            "node-a",
            "--operation",
            "restart",
            "--json",
            "--fleet-inventory",
            roster_path.to_str().unwrap(),
        ])
        .output()
        .expect("run preflight with expected fleet roster");

    for suffix in ["", "-wal", "-shm"] {
        let path = format!("{}{suffix}", db_path.display());
        let _ = std::fs::remove_file(path);
    }
    std::fs::remove_file(roster_path).unwrap();

    assert_eq!(output.status.code(), Some(4));
    let json: Value = serde_json::from_slice(&output.stdout).expect("stdout must be JSON only");
    assert_eq!(json["observation_coverage"]["fleet_hosts_expected"], 2);
    assert_eq!(json["observation_coverage"]["fleet_scope_complete"], false);
    assert!(json["observation_coverage"]["remaining_unknowns"]
        .as_array()
        .unwrap()
        .iter()
        .any(|unknown| unknown
            .as_str()
            .is_some_and(|message| message.contains("node-a") && message.contains("node-b"))));
}

#[test]
fn invalid_preflight_json_uses_same_schema_with_unknowns_as_null() {
    let output = Command::new(env!("CARGO_BIN_EXE_screamless"))
        .args([
            "preflight",
            "--server",
            "node-a",
            "--operation",
            "invalid",
            "--json",
        ])
        .output()
        .expect("run invalid preflight JSON command");

    assert_eq!(output.status.code(), Some(3));
    let json: Value = serde_json::from_slice(&output.stdout).expect("stdout must be JSON only");
    assert_eq!(json["schema_version"], "1.1");
    assert_eq!(json["status"], "invalid_invocation");
    for field in [
        "total_snapshots",
        "observation_window_hours",
        "observation_coverage",
        "outbound_dependencies",
        "inbound_dependencies",
        "inbound_dependency_evidence",
        "probe_statuses",
        "fleet_scope_complete",
    ] {
        assert!(json[field].is_null(), "{field} should be unknown");
    }
}
