pub mod command;
pub mod dns_resolution;
pub mod executable;
pub mod filedrop;
pub mod network_traffic;

use crate::common::error_model::Error;
use crate::result::writer::ResultWriter;
use serde::Deserialize;
use std::time::Duration;

/// Terminal status from a payload execution, mirrored from `result::writer::FinalStatus`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FinalStatus {
    Completed,
    Failed,
    /// Task did not complete within the allowed timeout.
    #[allow(dead_code)]
    Timeout,
    /// Unrecoverable internal error during execution.
    #[allow(dead_code)]
    Crashed,
}

/// Payload execution result tuple type alias.
pub type PayloadResult = Result<(FinalStatus, i32, Vec<u8>, Vec<u8>, Option<String>), Error>;

/// Shared execution context passed into every payload executor.
pub struct ExecContext<'a> {
    pub task_id: &'a str,
    /// Maximum wall-clock time allowed for this payload (reserved for future
    /// timeout enforcement; current payloads respect OS-level blocking only).
    #[allow(dead_code)]
    pub timeout: Duration,
    pub writer: &'a mut ResultWriter,
}

/// Trait implemented by each of the 5 payload variants.
pub trait Payload {
    /// Execute the payload, streaming events via `ctx.writer`.
    /// Returns `(FinalStatus, exit_code, stdout, stderr, error_message)`.
    fn execute(&self, ctx: &mut ExecContext<'_>) -> PayloadResult;
}

/// Parsed from `--payload-type`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub enum PayloadType {
    Command,
    Executable,
    FileDrop,
    DnsResolution,
    NetworkTraffic,
}

impl std::str::FromStr for PayloadType {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "Command" => Ok(PayloadType::Command),
            "Executable" => Ok(PayloadType::Executable),
            "FileDrop" => Ok(PayloadType::FileDrop),
            "DnsResolution" => Ok(PayloadType::DnsResolution),
            "NetworkTraffic" => Ok(PayloadType::NetworkTraffic),
            other => Err(format!("unknown payload type: {other}")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_payload_type_from_str_all_variants() {
        let cases = [
            ("Command", PayloadType::Command),
            ("Executable", PayloadType::Executable),
            ("FileDrop", PayloadType::FileDrop),
            ("DnsResolution", PayloadType::DnsResolution),
            ("NetworkTraffic", PayloadType::NetworkTraffic),
        ];
        for (s, expected) in &cases {
            let parsed: PayloadType = s.parse().expect("should parse");
            assert_eq!(parsed, *expected);
        }
    }

    #[test]
    fn test_payload_type_from_str_unknown_errors() {
        let result = "WebAttack".parse::<PayloadType>();
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("unknown payload type"));
    }
}
