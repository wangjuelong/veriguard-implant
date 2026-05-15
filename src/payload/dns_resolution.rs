//! `DnsResolution` payload: resolve a list of hostnames to IP addresses.
//!
//! # JSON spec (`--payload-b64` decoded)
//!
//! ```json
//! {
//!   "hostnames": ["example.com", "attacker.internal"]
//! }
//! ```

use crate::common::error_model::Error;
use crate::payload::{ExecContext, FinalStatus, Payload, PayloadResult};
use serde::Deserialize;
use std::net::{SocketAddr, ToSocketAddrs};

/// Deserialised from `--payload-b64`.
#[derive(Debug, Deserialize)]
pub struct DnsResolutionPayload {
    /// List of hostnames to resolve.
    pub hostnames: Vec<String>,
}

impl Payload for DnsResolutionPayload {
    fn execute(&self, ctx: &mut ExecContext<'_>) -> PayloadResult {
        ctx.writer
            .write_progress(
                ctx.task_id,
                "resolving",
                Some(&format!("resolving {} hostnames", self.hostnames.len())),
            )
            .map_err(|e| Error::Internal(e.to_string()))?;

        let mut stdout_lines: Vec<String> = Vec::new();
        let mut stderr_lines: Vec<String> = Vec::new();
        let mut any_failed = false;

        for hostname in &self.hostnames {
            let addr_str = format!("{hostname}:80");
            match addr_str.to_socket_addrs() {
                Ok(addrs) => {
                    let ips: Vec<String> = addrs
                        .map(|sa| match sa {
                            SocketAddr::V4(v4) => v4.ip().to_string(),
                            SocketAddr::V6(v6) => v6.ip().to_string(),
                        })
                        .collect();
                    stdout_lines.push(format!("{hostname}: {}", ips.join(", ")));
                }
                Err(e) => {
                    stderr_lines.push(format!("{hostname}: ERROR {e}"));
                    any_failed = true;
                }
            }
        }

        let exit_code = if any_failed { 1 } else { 0 };
        let status = if any_failed {
            FinalStatus::Failed
        } else {
            FinalStatus::Completed
        };
        let stdout = stdout_lines.join("\n").into_bytes();
        let stderr = stderr_lines.join("\n").into_bytes();
        Ok((status, exit_code, stdout, stderr, None))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dns_payload_deserialize() {
        let json = r#"{"hostnames":["localhost","example.com"]}"#;
        let p: DnsResolutionPayload = serde_json::from_str(json).unwrap();
        assert_eq!(p.hostnames.len(), 2);
        assert_eq!(p.hostnames[0], "localhost");
    }

    #[test]
    fn test_dns_payload_empty_hostnames() {
        let json = r#"{"hostnames":[]}"#;
        let p: DnsResolutionPayload = serde_json::from_str(json).unwrap();
        assert!(p.hostnames.is_empty());
    }

    #[test]
    fn test_dns_payload_missing_field_errors() {
        let json = r#"{}"#;
        let result = serde_json::from_str::<DnsResolutionPayload>(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_localhost_resolves() {
        // "localhost:80" should resolve in any typical dev environment.
        let result = "localhost:80".to_socket_addrs();
        assert!(result.is_ok(), "localhost should resolve");
    }
}
