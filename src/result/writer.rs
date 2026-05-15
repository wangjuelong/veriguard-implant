//! NDJSON result writer: opens a named pipe and streams structured events.
//!
//! Each line is a self-contained JSON object (\n-terminated, UTF-8, ≤ 64 KB).
//! The last event written is always a `result_final` event, which marks task
//! completion.  stdout/stderr captured from a child process are accumulated
//! in memory; if the total exceeds 1 MiB the buffer is truncated and
//! `truncated: true` is set on the `result_final` event.
//!
//! # Example
//!
//! ```no_run
//! use veriguard_implant::result::writer::{ResultWriter, FinalStatus};
//!
//! let mut w = ResultWriter::open("/tmp/veriguard-implant-pipe-T-001").unwrap();
//! w.write_started("T-001").unwrap();
//! w.write_final("T-001", FinalStatus::Completed, 0, b"hello\n", b"", None).unwrap();
//! ```

use base64::{engine::general_purpose::STANDARD, Engine as _};
use chrono::Utc;
use serde::Serialize;
use serde_json::json;
use std::fs::OpenOptions;
use std::io::{self, BufWriter, Write};
use std::path::Path;

/// Maximum in-memory stdout or stderr buffer before truncation.
const MAX_OUTPUT_BYTES: usize = 1024 * 1024; // 1 MiB

/// Maximum bytes for a single NDJSON line (64 KiB).
const MAX_LINE_BYTES: usize = 64 * 1024;

/// Maximum bytes for a single chunk's data payload (32 KiB).
const MAX_CHUNK_BYTES: usize = 32 * 1024;

/// Terminal status for a `result_final` event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FinalStatus {
    Completed,
    Failed,
    Timeout,
    Crashed,
}

/// A writer that streams NDJSON events to a named pipe (or any writable path).
pub struct ResultWriter {
    writer: BufWriter<std::fs::File>,
    started_at: String,
}

impl ResultWriter {
    /// Open the path for writing.  On POSIX the open blocks until a reader
    /// connects to the other end of a FIFO; that is intentional — the agent
    /// opens the read end first.
    pub fn open(pipe_path: impl AsRef<Path>) -> io::Result<Self> {
        let file = OpenOptions::new()
            .write(true)
            .create(false)
            .open(pipe_path)?;
        Ok(Self {
            writer: BufWriter::new(file),
            started_at: Utc::now().to_rfc3339(),
        })
    }

    /// Write the `started` event.
    pub fn write_started(&mut self, task_id: &str) -> io::Result<()> {
        let event = json!({
            "event_type": "started",
            "task_id": task_id,
            "started_at": self.started_at,
        });
        self.write_line(&event.to_string())
    }

    /// Write a `progress` event.
    pub fn write_progress(
        &mut self,
        task_id: &str,
        stage: &str,
        note: Option<&str>,
    ) -> io::Result<()> {
        let mut event = json!({
            "event_type": "progress",
            "task_id": task_id,
            "at": Utc::now().to_rfc3339(),
            "stage": stage,
        });
        if let Some(n) = note {
            event["note"] = json!(n);
        }
        self.write_line(&event.to_string())
    }

    /// Stream raw stdout bytes as one or more `stdout_chunk` events.
    pub fn write_stdout_chunks(&mut self, task_id: &str, data: &[u8]) -> io::Result<()> {
        self.write_chunks(task_id, "stdout_chunk", data)
    }

    /// Stream raw stderr bytes as one or more `stderr_chunk` events.
    pub fn write_stderr_chunks(&mut self, task_id: &str, data: &[u8]) -> io::Result<()> {
        self.write_chunks(task_id, "stderr_chunk", data)
    }

    /// Write the terminal `result_final` event.
    ///
    /// The inline `stdout_b64` / `stderr_b64` fields are limited to
    /// [`MAX_CHUNK_BYTES`] each so the entire JSON event stays within the
    /// 64 KiB NDJSON line limit.  Large outputs must be streamed beforehand
    /// using [`Self::write_stdout_chunks`] / [`Self::write_stderr_chunks`];
    /// the inline copies in `result_final` are just a convenience summary.
    ///
    /// If either buffer is larger than [`MAX_OUTPUT_BYTES`] **or** requires
    /// truncation to fit the line limit, `truncated: true` is set.
    pub fn write_final(
        &mut self,
        task_id: &str,
        status: FinalStatus,
        exit_code: i32,
        stdout: &[u8],
        stderr: &[u8],
        error_message: Option<&str>,
    ) -> io::Result<()> {
        // First truncate to the in-memory accumulation limit.
        let (stdout_mem, mem_truncated_out) = maybe_truncate(stdout);
        let (stderr_mem, mem_truncated_err) = maybe_truncate(stderr);

        // Then further truncate to fit inline in the NDJSON line.
        let (stdout_inline, inline_truncated_out) = maybe_truncate_to(stdout_mem, MAX_CHUNK_BYTES);
        let (stderr_inline, inline_truncated_err) = maybe_truncate_to(stderr_mem, MAX_CHUNK_BYTES);

        let truncated =
            mem_truncated_out || mem_truncated_err || inline_truncated_out || inline_truncated_err;

        let mut event = json!({
            "event_type": "result_final",
            "task_id": task_id,
            "status": status,
            "exit_code": exit_code,
            "started_at": self.started_at,
            "finished_at": Utc::now().to_rfc3339(),
            "stdout_b64": STANDARD.encode(stdout_inline),
            "stderr_b64": STANDARD.encode(stderr_inline),
        });

        if truncated {
            event["truncated"] = json!(true);
        }
        if let Some(msg) = error_message {
            event["error_message"] = json!(msg);
        }

        self.write_line(&event.to_string())
    }

    /// Flush and close the underlying writer.
    pub fn close(mut self) -> io::Result<()> {
        self.writer.flush()
    }

    /// Create a `ResultWriter` backed by a regular file for use in tests.
    ///
    /// Do not call from production code.
    #[cfg(test)]
    pub fn open_file_for_test(path: impl AsRef<std::path::Path>) -> io::Result<Self> {
        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)?;
        Ok(Self {
            writer: BufWriter::new(file),
            started_at: "2026-01-01T00:00:00Z".to_string(),
        })
    }

    // -- private helpers --

    fn write_line(&mut self, line: &str) -> io::Result<()> {
        let bytes = line.as_bytes();
        if bytes.len() > MAX_LINE_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "NDJSON line too large: {} bytes (max {MAX_LINE_BYTES})",
                    bytes.len()
                ),
            ));
        }
        self.writer.write_all(bytes)?;
        self.writer.write_all(b"\n")?;
        self.writer.flush()
    }

    fn write_chunks(&mut self, task_id: &str, event_type: &str, data: &[u8]) -> io::Result<()> {
        for (seq, chunk) in data.chunks(MAX_CHUNK_BYTES).enumerate() {
            let event = json!({
                "event_type": event_type,
                "task_id": task_id,
                "seq": seq,
                "data_b64": STANDARD.encode(chunk),
            });
            self.write_line(&event.to_string())?;
        }
        Ok(())
    }
}

/// Truncate a byte slice to [`MAX_OUTPUT_BYTES`] if needed.
/// Returns `(slice, was_truncated)`.
fn maybe_truncate(data: &[u8]) -> (&[u8], bool) {
    maybe_truncate_to(data, MAX_OUTPUT_BYTES)
}

/// Truncate a byte slice to `limit` bytes if needed.
/// Returns `(slice, was_truncated)`.
fn maybe_truncate_to(data: &[u8], limit: usize) -> (&[u8], bool) {
    if data.len() > limit {
        (&data[..limit], true)
    } else {
        (data, false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader};
    use tempfile::NamedTempFile;

    fn open_tmp_writer() -> (ResultWriter, NamedTempFile) {
        let tmp = NamedTempFile::new().unwrap();
        // Re-open the same path for writing using a regular file (tests don't
        // use a real FIFO so we open the file directly).
        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(tmp.path())
            .unwrap();
        let writer = ResultWriter {
            writer: BufWriter::new(file),
            started_at: "2026-01-01T00:00:00Z".to_string(),
        };
        (writer, tmp)
    }

    fn read_lines(tmp: &NamedTempFile) -> Vec<serde_json::Value> {
        let file = std::fs::File::open(tmp.path()).unwrap();
        BufReader::new(file)
            .lines()
            .map(|l| serde_json::from_str(&l.unwrap()).unwrap())
            .collect()
    }

    #[test]
    fn test_write_started_produces_valid_ndjson() {
        let (mut w, tmp) = open_tmp_writer();
        w.write_started("T-001").unwrap();
        drop(w.writer);

        let lines = read_lines(&tmp);
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0]["event_type"], "started");
        assert_eq!(lines[0]["task_id"], "T-001");
        assert!(lines[0].get("started_at").is_some());
    }

    #[test]
    fn test_write_progress_includes_stage() {
        let (mut w, tmp) = open_tmp_writer();
        w.write_progress("T-002", "executing", Some("running sh"))
            .unwrap();
        drop(w.writer);

        let lines = read_lines(&tmp);
        assert_eq!(lines[0]["event_type"], "progress");
        assert_eq!(lines[0]["stage"], "executing");
        assert_eq!(lines[0]["note"], "running sh");
    }

    #[test]
    fn test_write_final_no_truncation() {
        let (mut w, tmp) = open_tmp_writer();
        w.write_final("T-003", FinalStatus::Completed, 0, b"ok\n", b"", None)
            .unwrap();
        drop(w.writer);

        let lines = read_lines(&tmp);
        assert_eq!(lines[0]["event_type"], "result_final");
        assert_eq!(lines[0]["status"], "completed");
        assert_eq!(lines[0]["exit_code"], 0);
        assert!(lines[0].get("truncated").is_none());
        // decode stdout_b64 should equal "ok\n"
        let stdout_b64 = lines[0]["stdout_b64"].as_str().unwrap();
        let decoded = STANDARD.decode(stdout_b64).unwrap();
        assert_eq!(decoded, b"ok\n");
    }

    #[test]
    fn test_write_final_truncates_large_stdout() {
        let (mut w, tmp) = open_tmp_writer();
        // A buffer larger than MAX_OUTPUT_BYTES triggers truncation.
        let big = vec![b'A'; MAX_OUTPUT_BYTES + 1];
        w.write_final("T-004", FinalStatus::Failed, 1, &big, b"", Some("too big"))
            .unwrap();
        drop(w.writer);

        let lines = read_lines(&tmp);
        assert_eq!(lines[0]["truncated"], true);
        assert_eq!(lines[0]["error_message"], "too big");
        // Inline stdout_b64 in result_final is capped to MAX_CHUNK_BYTES.
        let stdout_b64 = lines[0]["stdout_b64"].as_str().unwrap();
        let decoded = STANDARD.decode(stdout_b64).unwrap();
        assert_eq!(decoded.len(), MAX_CHUNK_BYTES);
    }

    #[test]
    fn test_stdout_chunks_split_correctly() {
        let (mut w, tmp) = open_tmp_writer();
        // 2.5 chunks worth of data
        let data = vec![b'B'; MAX_CHUNK_BYTES * 2 + 100];
        w.write_stdout_chunks("T-005", &data).unwrap();
        drop(w.writer);

        let lines = read_lines(&tmp);
        assert_eq!(lines.len(), 3);
        assert_eq!(lines[0]["seq"], 0);
        assert_eq!(lines[1]["seq"], 1);
        assert_eq!(lines[2]["seq"], 2);
        for line in &lines {
            assert_eq!(line["event_type"], "stdout_chunk");
        }
    }

    #[test]
    fn test_write_final_timeout_status() {
        let (mut w, tmp) = open_tmp_writer();
        w.write_final("T-006", FinalStatus::Timeout, 4, b"", b"timed out\n", None)
            .unwrap();
        drop(w.writer);

        let lines = read_lines(&tmp);
        assert_eq!(lines[0]["status"], "timeout");
    }

    #[test]
    fn test_final_status_serialization() {
        assert_eq!(
            serde_json::to_string(&FinalStatus::Crashed).unwrap(),
            r#""crashed""#
        );
        assert_eq!(
            serde_json::to_string(&FinalStatus::Completed).unwrap(),
            r#""completed""#
        );
    }

    #[test]
    fn test_maybe_truncate_small() {
        let data = b"small";
        let (out, truncated) = maybe_truncate(data);
        assert!(!truncated);
        assert_eq!(out, data);
    }

    #[test]
    fn test_maybe_truncate_large() {
        let data = vec![0u8; MAX_OUTPUT_BYTES + 500];
        let (out, truncated) = maybe_truncate(&data);
        assert!(truncated);
        assert_eq!(out.len(), MAX_OUTPUT_BYTES);
    }
}
