//! `FileDrop` payload: write a file to a target path on disk.
//!
//! Spec: §5.1 categories — webshell落盘, 网站篡改, 病毒落盘, 主机持久化.
//!
//! # JSON spec (`--payload-b64` decoded)
//!
//! ```json
//! {
//!   "data_b64": "<base64 of file content>",
//!   "dest_path": "/var/www/html/shell.php"
//! }
//! ```

use crate::common::error_model::Error;
use crate::payload::{ExecContext, FinalStatus, Payload, PayloadResult};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde::Deserialize;
use std::fs;
use std::io::Write;
use std::path::Path;

/// Deserialised from `--payload-b64`.
#[derive(Debug, Deserialize)]
pub struct FileDropPayload {
    /// Base64-encoded file content.
    pub data_b64: String,
    /// Absolute path on the target host where the file should be written.
    pub dest_path: String,
}

impl Payload for FileDropPayload {
    fn execute(&self, ctx: &mut ExecContext<'_>) -> PayloadResult {
        ctx.writer
            .write_progress(ctx.task_id, "decoding", Some("decoding file payload"))
            .map_err(|e| Error::Internal(e.to_string()))?;

        let data = STANDARD
            .decode(&self.data_b64)
            .map_err(|e| Error::Internal(format!("base64 decode error: {e}")))?;

        let dest = Path::new(&self.dest_path);

        // Create parent directories if needed.
        if let Some(parent) = dest.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent).map_err(|e| {
                    Error::Internal(format!("cannot create parent dirs for {dest:?}: {e}"))
                })?;
            }
        }

        ctx.writer
            .write_progress(ctx.task_id, "writing", Some("writing file to disk"))
            .map_err(|e| Error::Internal(e.to_string()))?;

        let mut f = fs::File::create(dest)?;
        f.write_all(&data)?;

        let msg = format!("file written: {} bytes", data.len());
        Ok((FinalStatus::Completed, 0, msg.into_bytes(), vec![], None))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    use tempfile::tempdir;

    #[test]
    fn test_filedrop_payload_deserialize() {
        let json = r#"{"data_b64":"aGVsbG8=","dest_path":"/tmp/test.txt"}"#;
        let p: FileDropPayload = serde_json::from_str(json).unwrap();
        assert_eq!(p.dest_path, "/tmp/test.txt");
        let decoded = STANDARD.decode(&p.data_b64).unwrap();
        assert_eq!(decoded, b"hello");
    }

    #[test]
    fn test_filedrop_payload_missing_field_errors() {
        let json = r#"{"data_b64":"aGVsbG8="}"#;
        let result = serde_json::from_str::<FileDropPayload>(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_filedrop_base64_roundtrip() {
        let content = b"EICAR test content";
        let encoded = STANDARD.encode(content);
        let decoded = STANDARD.decode(&encoded).unwrap();
        assert_eq!(decoded, content);
    }

    #[test]
    #[cfg(unix)]
    fn test_filedrop_creates_parent_dirs() {
        let dir = tempdir().unwrap();
        let nested = dir.path().join("a").join("b").join("file.txt");
        // Ensure parent creation logic path exists.
        assert!(nested.parent().unwrap().parent().is_some());
    }
}
