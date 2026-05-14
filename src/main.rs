//! Veriguard Implant — standalone binary that runs a single task and reports
//! results via a named pipe using NDJSON events.
//!
//! ## CLI contract (§3.3.2)
//!
//! ```text
//! veriguard-implant \
//!   --task-id   T-001 \
//!   --payload-type Command \
//!   --payload-b64 <base64-encoded JSON payload spec> \
//!   --result-pipe /tmp/veriguard-implant-pipe-T-001 \
//!   --timeout 60s \
//!   [--self-delete]
//! ```
//!
//! ## Exit codes
//!
//! | Code | Meaning |
//! |------|---------|
//! | 0    | Task completed normally |
//! | 1    | Task execution failed (command exit != 0) |
//! | 2    | Payload parse failure |
//! | 3    | Resource / permission error |
//! | 4    | Timeout |
//! | 99   | Panic / unhandled error |

use base64::{engine::general_purpose::STANDARD, Engine as _};
use clap::Parser;
use cleanup::self_delete::self_delete;
use humantime::parse_duration;
use log::error;
use payload::{
    command::CommandPayload, dns_resolution::DnsResolutionPayload, executable::ExecutablePayload,
    filedrop::FileDropPayload, network_traffic::NetworkTrafficPayload, ExecContext,
    FinalStatus as PayloadFinalStatus, Payload, PayloadType,
};
use result::writer::{FinalStatus as WriterFinalStatus, ResultWriter};
use std::panic;
use std::process::exit;
use std::time::Duration;

// Upstream modules retained from OpenAEV-Platform/implant baseline.
// They are no longer the primary execution path (replaced by NDJSON pipe
// protocol) but are kept per the fork policy (§2.6 "保留上游").
#[allow(dead_code)]
mod api;
mod cleanup;
#[allow(dead_code)]
mod common;
#[allow(dead_code)]
mod handle;
mod payload;
#[allow(dead_code)]
mod process;
mod result;

#[cfg(test)]
mod tests;

const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Maximum accepted byte length for the `--payload-b64` argument (32 MiB).
///
/// A payload larger than this is almost certainly a bug or DoS attempt; reject
/// it early before allocating memory for decoding.
pub(crate) const MAX_PAYLOAD_B64_BYTES: usize = 32 * 1024 * 1024;

#[derive(Parser, Debug)]
#[command(
    name = "veriguard-implant",
    version,
    about = "Veriguard implant — execute a single task and report via named pipe"
)]
struct Args {
    /// Unique task identifier (echoed in every event).
    #[arg(long)]
    task_id: String,

    /// Payload type: Command | Executable | FileDrop | DnsResolution | NetworkTraffic
    #[arg(long)]
    payload_type: String,

    /// Base64-encoded JSON describing the payload spec.
    #[arg(long)]
    payload_b64: String,

    /// Path to the named pipe (FIFO) where NDJSON events are written.
    #[arg(long)]
    result_pipe: String,

    /// Execution timeout (e.g. `60s`, `2m`).
    #[arg(long, default_value = "60s")]
    timeout: String,

    /// Delete the implant binary before exiting.
    #[arg(long, default_value_t = false)]
    self_delete: bool,
}

fn main() {
    // Install a panic hook that exits with code 99 so the agent can detect crashes.
    panic::set_hook(Box::new(|info| {
        let msg = info
            .payload()
            .downcast_ref::<String>()
            .map(String::as_str)
            .or_else(|| info.payload().downcast_ref::<&str>().copied())
            .unwrap_or("<unknown panic>");
        error!("implant panic: {msg}");
        exit(99);
    }));

    let args = Args::parse();
    log::info!("veriguard-implant {VERSION} task_id={}", args.task_id);

    let exit_code = run(args);
    exit(exit_code);
}

/// Core execution entry point.  Returns the process exit code.
fn run(args: Args) -> i32 {
    // Parse timeout.
    let timeout: Duration = match parse_duration(&args.timeout) {
        Ok(d) => d,
        Err(e) => {
            error!("invalid --timeout {:?}: {e}", args.timeout);
            return 2;
        }
    };

    // Parse payload type.
    let payload_type: PayloadType = match args.payload_type.parse() {
        Ok(t) => t,
        Err(e) => {
            error!("invalid --payload-type {:?}: {e}", args.payload_type);
            return 2;
        }
    };

    // Guard against oversized payloads (DoS / memory exhaustion).
    if args.payload_b64.len() > MAX_PAYLOAD_B64_BYTES {
        error!(
            "--payload-b64 exceeds max size ({} bytes, limit {} bytes)",
            args.payload_b64.len(),
            MAX_PAYLOAD_B64_BYTES
        );
        // Open writer only if possible; best-effort result_final before exit 2.
        if let Ok(mut writer) = ResultWriter::open(&args.result_pipe) {
            let msg = "payload too large";
            let _ = writer.write_final(
                &args.task_id,
                WriterFinalStatus::Failed,
                2,
                &[],
                msg.as_bytes(),
                Some(msg),
            );
        }
        return 2;
    }

    // Decode payload spec JSON.
    let payload_json = match STANDARD.decode(&args.payload_b64) {
        Ok(bytes) => bytes,
        Err(e) => {
            error!("--payload-b64 is not valid base64: {e}");
            return 2;
        }
    };

    // Open the result pipe.
    let mut writer = match ResultWriter::open(&args.result_pipe) {
        Ok(w) => w,
        Err(e) => {
            error!("cannot open result pipe {:?}: {e}", args.result_pipe);
            return 3;
        }
    };

    // Write started event.
    if let Err(e) = writer.write_started(&args.task_id) {
        error!("write started event failed: {e}");
        return 3;
    }

    // Dispatch to payload executor.
    let exit_code = execute_payload(
        &args.task_id,
        payload_type,
        &payload_json,
        timeout,
        &mut writer,
    );

    // Optional self-deletion (best-effort; does not affect exit code).
    if args.self_delete {
        if let Err(e) = self_delete() {
            error!("self_delete failed: {e}");
        }
    }

    if let Err(e) = writer.close() {
        error!("pipe close failed: {e}");
    }
    exit_code
}

/// Deserialise and run the payload, write `result_final`, return exit code.
fn execute_payload(
    task_id: &str,
    payload_type: PayloadType,
    payload_json: &[u8],
    timeout: Duration,
    writer: &mut ResultWriter,
) -> i32 {
    macro_rules! parse_or_fail {
        ($T:ty) => {
            match serde_json::from_slice::<$T>(payload_json) {
                Ok(p) => p,
                Err(e) => {
                    let msg = format!("payload parse error: {e}");
                    error!("{msg}");
                    if let Err(we) = writer.write_final(
                        task_id,
                        WriterFinalStatus::Crashed,
                        2,
                        &[],
                        msg.as_bytes(),
                        Some(&msg),
                    ) {
                        error!("pipe write result_final failed: {we}");
                    }
                    return 2;
                }
            }
        };
    }

    let result = match payload_type {
        PayloadType::Command => {
            let p = parse_or_fail!(CommandPayload);
            let mut ctx = ExecContext {
                task_id,
                timeout,
                writer,
            };
            p.execute(&mut ctx)
        }
        PayloadType::Executable => {
            let p = parse_or_fail!(ExecutablePayload);
            let mut ctx = ExecContext {
                task_id,
                timeout,
                writer,
            };
            p.execute(&mut ctx)
        }
        PayloadType::FileDrop => {
            let p = parse_or_fail!(FileDropPayload);
            let mut ctx = ExecContext {
                task_id,
                timeout,
                writer,
            };
            p.execute(&mut ctx)
        }
        PayloadType::DnsResolution => {
            let p = parse_or_fail!(DnsResolutionPayload);
            let mut ctx = ExecContext {
                task_id,
                timeout,
                writer,
            };
            p.execute(&mut ctx)
        }
        PayloadType::NetworkTraffic => {
            let p = parse_or_fail!(NetworkTrafficPayload);
            let mut ctx = ExecContext {
                task_id,
                timeout,
                writer,
            };
            p.execute(&mut ctx)
        }
    };

    match result {
        Ok((status, exit_code, stdout, stderr, err_msg)) => {
            // Stream stdout/stderr as chunks before writing final.
            if !stdout.is_empty() {
                if let Err(e) = writer.write_stdout_chunks(task_id, &stdout) {
                    error!("pipe write stdout_chunk failed: {e}");
                }
            }
            if !stderr.is_empty() {
                if let Err(e) = writer.write_stderr_chunks(task_id, &stderr) {
                    error!("pipe write stderr_chunk failed: {e}");
                }
            }
            let writer_status = match status {
                PayloadFinalStatus::Completed => WriterFinalStatus::Completed,
                PayloadFinalStatus::Failed => WriterFinalStatus::Failed,
                PayloadFinalStatus::Timeout => WriterFinalStatus::Timeout,
                PayloadFinalStatus::Crashed => WriterFinalStatus::Crashed,
            };
            if let Err(e) = writer.write_final(
                task_id,
                writer_status,
                exit_code,
                &stdout,
                &stderr,
                err_msg.as_deref(),
            ) {
                error!("pipe write result_final failed: {e}");
            }
            match status {
                PayloadFinalStatus::Completed => 0,
                PayloadFinalStatus::Failed => 1,
                PayloadFinalStatus::Timeout => 4,
                PayloadFinalStatus::Crashed => 99,
            }
        }
        Err(e) => {
            let msg = e.to_string();
            error!("payload execution error: {msg}");
            if let Err(we) = writer.write_final(
                task_id,
                WriterFinalStatus::Failed,
                1,
                &[],
                msg.as_bytes(),
                Some(&msg),
            ) {
                error!("pipe write result_final failed: {we}");
            }
            1
        }
    }
}

