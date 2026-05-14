//! `Executable` payload: drop a binary to disk and execute it.
//!
//! Spec: §5.1 categories — 内存注入webshell, RAT执行, 系统提权.
//!
//! # JSON spec (`--payload-b64` decoded)
//!
//! ```json
//! {
//!   "data_b64": "<base64 of binary>",
//!   "filename": "payload.sh",          // written to /tmp/<filename>
//!   "args": ["-v", "--target", "..."]  // optional argv passed to executable
//! }
//! ```

use crate::common::error_model::Error;
use crate::payload::{ExecContext, FinalStatus, Payload, PayloadResult};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde::Deserialize;
use std::fs;
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::process::{Command, Stdio};

/// Deserialised from `--payload-b64`.
#[derive(Debug, Deserialize)]
pub struct ExecutablePayload {
    /// Base64-encoded binary content.
    pub data_b64: String,
    /// Filename under `/tmp/` to write the binary.
    pub filename: String,
    /// Optional argv for the spawned process (args only, no argv[0]).
    #[serde(default)]
    pub args: Vec<String>,
}

impl Payload for ExecutablePayload {
    fn execute(&self, ctx: &mut ExecContext<'_>) -> PayloadResult {
        // Validate filename (no path traversal).
        if self.filename.contains('/') || self.filename.contains('\\') {
            return Ok((
                FinalStatus::Failed,
                3,
                vec![],
                b"filename must not contain path separators".to_vec(),
                Some("invalid filename".to_string()),
            ));
        }

        ctx.writer
            .write_progress(ctx.task_id, "decoding", Some("decoding executable payload"))
            .map_err(|e| Error::Internal(e.to_string()))?;

        let binary = STANDARD
            .decode(&self.data_b64)
            .map_err(|e| Error::Internal(format!("base64 decode error: {e}")))?;

        let dest = std::env::temp_dir().join(&self.filename);

        // Write the binary.
        {
            let mut f = fs::File::create(&dest)?;
            f.write_all(&binary)?;
        }

        // Make executable on POSIX.
        #[cfg(unix)]
        {
            let mut perms = fs::metadata(&dest)?.permissions();
            perms.set_mode(0o700);
            fs::set_permissions(&dest, perms)?;
        }

        ctx.writer
            .write_progress(ctx.task_id, "executing", Some("spawning executable"))
            .map_err(|e| Error::Internal(e.to_string()))?;

        let output = Command::new(&dest)
            .args(&self.args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output();

        // Best-effort cleanup after execution.
        let _ = fs::remove_file(&dest);

        match output {
            Ok(o) => {
                let exit_code = o.status.code().unwrap_or(-99);
                let status = if exit_code == 0 {
                    FinalStatus::Completed
                } else {
                    FinalStatus::Failed
                };
                Ok((status, exit_code, o.stdout, o.stderr, None))
            }
            Err(e) => Ok((
                FinalStatus::Failed,
                3,
                vec![],
                e.to_string().into_bytes(),
                Some("spawn failed".to_string()),
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_executable_payload_deserialize() {
        let json = r#"{"data_b64":"aGVsbG8=","filename":"test.sh","args":[]}"#;
        let p: ExecutablePayload = serde_json::from_str(json).unwrap();
        assert_eq!(p.filename, "test.sh");
        assert!(p.args.is_empty());
    }

    #[test]
    fn test_executable_payload_default_args() {
        let json = r#"{"data_b64":"aGVsbG8=","filename":"test.sh"}"#;
        let p: ExecutablePayload = serde_json::from_str(json).unwrap();
        assert!(p.args.is_empty());
    }

    /// L2 fix: call execute() with path-traversal filenames and assert
    /// the result is FinalStatus::Failed (not a successful file write).
    #[test]
    fn test_executable_payload_rejects_path_traversal() {
        use crate::payload::ExecContext;
        use crate::result::writer::ResultWriter;
        use tempfile::NamedTempFile;

        let filenames_to_reject = ["../etc/passwd", "sub/dir/file", "a\\b"];

        for fname in &filenames_to_reject {
            let payload = ExecutablePayload {
                data_b64: STANDARD.encode(b"#!/bin/sh\necho pwned"),
                filename: fname.to_string(),
                args: vec![],
            };

            // Wire up a temporary file as the "pipe" so we can call execute().
            let tmp = NamedTempFile::new().expect("temp file");
            let mut writer =
                ResultWriter::open_file_for_test(tmp.path()).expect("open writer");

            let mut ctx = ExecContext {
                task_id: "L2-test",
                timeout: std::time::Duration::from_secs(5),
                writer: &mut writer,
            };

            let result = payload.execute(&mut ctx).expect("execute returns Ok");
            assert_eq!(
                result.0,
                FinalStatus::Failed,
                "path-traversal filename {fname:?} must yield FinalStatus::Failed"
            );
        }
    }
}
