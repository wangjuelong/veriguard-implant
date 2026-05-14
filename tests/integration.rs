//! Integration tests for the veriguard-implant CLI.
//!
//! These tests build and invoke the actual binary to exercise the full
//! execution path including CLI parsing, payload dispatch, and NDJSON output.

use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde_json::Value;
use std::fs;
use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::process::Command;
use tempfile::tempdir;

/// Path to the compiled binary under test.
fn binary() -> PathBuf {
    let mut p = std::env::current_exe()
        .unwrap()
        .parent()
        .unwrap()
        .to_owned();
    // Cargo puts integration test binaries in deps/; move up one level.
    if p.ends_with("deps") {
        p.pop();
    }
    p.join("veriguard-implant")
}

/// Read all NDJSON lines from a file path.
fn read_ndjson(path: &std::path::Path) -> Vec<Value> {
    let f = fs::File::open(path).expect("result file should exist");
    BufReader::new(f)
        .lines()
        .map(|l| serde_json::from_str(&l.unwrap()).expect("valid json line"))
        .collect()
}

/// Create a regular file to act as the "pipe" for tests (no real FIFO needed).
fn make_result_file(dir: &std::path::Path, name: &str) -> PathBuf {
    let p = dir.join(name);
    fs::write(&p, b"").unwrap();
    p
}

#[test]
#[cfg(unix)]
fn test_cli_command_payload_echo_ok() {
    let dir = tempdir().unwrap();
    let pipe = make_result_file(dir.path(), "pipe.ndjson");
    let cmd_json = serde_json::json!({
        "executor": "sh",
        "content": STANDARD.encode("echo hello_integration")
    });
    let payload_b64 = STANDARD.encode(cmd_json.to_string());

    let status = Command::new(binary())
        .args([
            "--task-id",
            "IT-001",
            "--payload-type",
            "Command",
            "--payload-b64",
            &payload_b64,
            "--result-pipe",
            pipe.to_str().unwrap(),
            "--timeout",
            "10s",
        ])
        .status()
        .expect("binary should run");

    assert_eq!(status.code(), Some(0), "exit code should be 0");

    let events = read_ndjson(&pipe);
    assert!(
        events.len() >= 2,
        "should have at least started + result_final"
    );

    let started = events
        .iter()
        .find(|e| e["event_type"] == "started")
        .unwrap();
    assert_eq!(started["task_id"], "IT-001");

    let final_ev = events
        .iter()
        .find(|e| e["event_type"] == "result_final")
        .expect("result_final must be present");
    assert_eq!(final_ev["status"], "completed");
    assert_eq!(final_ev["exit_code"], 0);
}

#[test]
#[cfg(unix)]
fn test_cli_command_payload_nonzero_exit() {
    let dir = tempdir().unwrap();
    let pipe = make_result_file(dir.path(), "pipe2.ndjson");
    let cmd_json = serde_json::json!({
        "executor": "sh",
        "content": STANDARD.encode("exit 42")
    });
    let payload_b64 = STANDARD.encode(cmd_json.to_string());

    let status = Command::new(binary())
        .args([
            "--task-id",
            "IT-002",
            "--payload-type",
            "Command",
            "--payload-b64",
            &payload_b64,
            "--result-pipe",
            pipe.to_str().unwrap(),
            "--timeout",
            "10s",
        ])
        .status()
        .expect("binary should run");

    // exit code 1 means task failed
    assert_eq!(status.code(), Some(1));

    let events = read_ndjson(&pipe);
    let final_ev = events
        .iter()
        .find(|e| e["event_type"] == "result_final")
        .expect("result_final required");
    assert_eq!(final_ev["status"], "failed");
}

#[test]
#[cfg(unix)]
fn test_cli_bad_payload_type_exits_2() {
    let dir = tempdir().unwrap();
    let pipe = make_result_file(dir.path(), "pipe3.ndjson");

    let status = Command::new(binary())
        .args([
            "--task-id",
            "IT-003",
            "--payload-type",
            "Unknown",
            "--payload-b64",
            &STANDARD.encode(b"{}"),
            "--result-pipe",
            pipe.to_str().unwrap(),
        ])
        .status()
        .expect("binary should run");

    assert_eq!(status.code(), Some(2));
}

#[test]
#[cfg(unix)]
fn test_cli_bad_base64_exits_2() {
    let dir = tempdir().unwrap();
    let pipe = make_result_file(dir.path(), "pipe4.ndjson");

    let status = Command::new(binary())
        .args([
            "--task-id",
            "IT-004",
            "--payload-type",
            "Command",
            "--payload-b64",
            "!!!not-base64!!!",
            "--result-pipe",
            pipe.to_str().unwrap(),
        ])
        .status()
        .expect("binary should run");

    assert_eq!(status.code(), Some(2));
}

#[test]
#[cfg(unix)]
fn test_cli_filedrop_writes_file() {
    let dir = tempdir().unwrap();
    let pipe = make_result_file(dir.path(), "pipe5.ndjson");
    let dest = dir.path().join("dropped.txt");
    let content = b"EICAR test content";

    let payload_json = serde_json::json!({
        "data_b64": STANDARD.encode(content),
        "dest_path": dest.to_str().unwrap()
    });
    let payload_b64 = STANDARD.encode(payload_json.to_string());

    let status = Command::new(binary())
        .args([
            "--task-id",
            "IT-005",
            "--payload-type",
            "FileDrop",
            "--payload-b64",
            &payload_b64,
            "--result-pipe",
            pipe.to_str().unwrap(),
            "--timeout",
            "5s",
        ])
        .status()
        .expect("binary should run");

    assert_eq!(status.code(), Some(0));
    assert!(dest.exists(), "dropped file should exist");
    assert_eq!(fs::read(&dest).unwrap(), content);

    let events = read_ndjson(&pipe);
    let final_ev = events
        .iter()
        .find(|e| e["event_type"] == "result_final")
        .unwrap();
    assert_eq!(final_ev["status"], "completed");
}

#[test]
#[cfg(unix)]
fn test_cli_dns_resolution() {
    let dir = tempdir().unwrap();
    let pipe = make_result_file(dir.path(), "pipe6.ndjson");
    let payload_json = serde_json::json!({ "hostnames": ["localhost"] });
    let payload_b64 = STANDARD.encode(payload_json.to_string());

    let status = Command::new(binary())
        .args([
            "--task-id",
            "IT-006",
            "--payload-type",
            "DnsResolution",
            "--payload-b64",
            &payload_b64,
            "--result-pipe",
            pipe.to_str().unwrap(),
            "--timeout",
            "10s",
        ])
        .status()
        .expect("binary should run");

    // localhost always resolves; exit code 0
    assert_eq!(status.code(), Some(0));

    let events = read_ndjson(&pipe);
    let final_ev = events
        .iter()
        .find(|e| e["event_type"] == "result_final")
        .unwrap();
    assert_eq!(final_ev["status"], "completed");
}

#[test]
#[cfg(unix)]
fn test_result_final_is_last_event() {
    let dir = tempdir().unwrap();
    let pipe = make_result_file(dir.path(), "pipe7.ndjson");
    let cmd_json = serde_json::json!({
        "executor": "sh",
        "content": STANDARD.encode("echo done")
    });
    let payload_b64 = STANDARD.encode(cmd_json.to_string());

    Command::new(binary())
        .args([
            "--task-id",
            "IT-007",
            "--payload-type",
            "Command",
            "--payload-b64",
            &payload_b64,
            "--result-pipe",
            pipe.to_str().unwrap(),
            "--timeout",
            "10s",
        ])
        .status()
        .expect("binary should run");

    let events = read_ndjson(&pipe);
    assert!(!events.is_empty());
    assert_eq!(
        events.last().unwrap()["event_type"],
        "result_final",
        "last event must be result_final"
    );
}
