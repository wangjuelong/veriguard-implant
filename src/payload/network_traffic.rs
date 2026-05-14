//! `NetworkTraffic` payload: send TCP/UDP probe traffic to a target.
//!
//! # JSON spec (`--payload-b64` decoded)
//!
//! ```json
//! {
//!   "protocol": "tcp",            // "tcp" | "udp"
//!   "target": "192.168.1.1",
//!   "port": 4444,
//!   "data_b64": "<base64>",       // optional payload bytes to send
//!   "timeout_secs": 5             // optional per-connection timeout
//! }
//! ```

use crate::common::error_model::Error;
use crate::payload::{ExecContext, FinalStatus, Payload, PayloadResult};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde::Deserialize;
use std::io::{self, Write};
use std::net::{TcpStream, UdpSocket};
use std::time::Duration;

/// Protocol selection for the network probe.
#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum NetProtocol {
    Tcp,
    Udp,
}

/// Deserialised from `--payload-b64`.
#[derive(Debug, Deserialize)]
pub struct NetworkTrafficPayload {
    pub protocol: NetProtocol,
    pub target: String,
    pub port: u16,
    /// Optional data to send (base64-encoded).
    #[serde(default)]
    pub data_b64: Option<String>,
    /// Per-connection timeout in seconds (default 5).
    #[serde(default = "default_timeout_secs")]
    pub timeout_secs: u64,
}

fn default_timeout_secs() -> u64 {
    5
}

impl Payload for NetworkTrafficPayload {
    fn execute(&self, ctx: &mut ExecContext<'_>) -> PayloadResult {
        let addr = format!("{}:{}", self.target, self.port);
        let timeout = Duration::from_secs(self.timeout_secs);

        ctx.writer
            .write_progress(
                ctx.task_id,
                "connecting",
                Some(&format!("sending {:?} traffic to {addr}", self.protocol)),
            )
            .map_err(|e| Error::Internal(e.to_string()))?;

        let data = match &self.data_b64 {
            Some(b64) => STANDARD
                .decode(b64)
                .map_err(|e| Error::Internal(format!("base64 decode error: {e}")))?,
            None => vec![],
        };

        let result = match self.protocol {
            NetProtocol::Tcp => send_tcp(&addr, &data, timeout),
            NetProtocol::Udp => send_udp(&addr, &data, timeout),
        };

        match result {
            Ok(stdout) => Ok((FinalStatus::Completed, 0, stdout, vec![], None)),
            Err(e) => Ok((
                FinalStatus::Failed,
                1,
                vec![],
                e.to_string().into_bytes(),
                Some("network error".to_string()),
            )),
        }
    }
}

fn send_tcp(addr: &str, data: &[u8], timeout: Duration) -> io::Result<Vec<u8>> {
    // Parse to SocketAddr first so we can call connect_timeout, which respects
    // the caller's --timeout flag instead of the OS default (~2 min).
    let sock_addr: std::net::SocketAddr = addr
        .parse()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    let mut stream = TcpStream::connect_timeout(&sock_addr, timeout)?;
    stream.set_write_timeout(Some(timeout))?;
    if !data.is_empty() {
        stream.write_all(data)?;
    }
    Ok(format!("TCP connection established to {addr}").into_bytes())
}

fn send_udp(addr: &str, data: &[u8], timeout: Duration) -> io::Result<Vec<u8>> {
    let socket = UdpSocket::bind("0.0.0.0:0")?;
    socket.set_write_timeout(Some(timeout))?;
    let send_data = if data.is_empty() {
        b"\x00" as &[u8]
    } else {
        data
    };
    socket.send_to(send_data, addr)?;
    Ok(format!("UDP packet sent to {addr}").into_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_network_traffic_payload_deserialize_tcp() {
        let json = r#"{"protocol":"tcp","target":"127.0.0.1","port":9999}"#;
        let p: NetworkTrafficPayload = serde_json::from_str(json).unwrap();
        assert_eq!(p.protocol, NetProtocol::Tcp);
        assert_eq!(p.port, 9999);
        assert_eq!(p.timeout_secs, 5); // default
        assert!(p.data_b64.is_none());
    }

    #[test]
    fn test_network_traffic_payload_deserialize_udp_with_data() {
        let json = r#"{"protocol":"udp","target":"10.0.0.1","port":53,"data_b64":"AAAA","timeout_secs":3}"#;
        let p: NetworkTrafficPayload = serde_json::from_str(json).unwrap();
        assert_eq!(p.protocol, NetProtocol::Udp);
        assert_eq!(p.timeout_secs, 3);
        assert!(p.data_b64.is_some());
    }

    #[test]
    fn test_network_traffic_missing_required_fields() {
        let json = r#"{"protocol":"tcp","target":"127.0.0.1"}"#;
        let result = serde_json::from_str::<NetworkTrafficPayload>(json);
        assert!(result.is_err(), "port is required");
    }

    #[test]
    fn test_default_timeout_secs() {
        assert_eq!(default_timeout_secs(), 5);
    }

    #[test]
    fn test_send_tcp_refuses_closed_port() {
        // Port 1 is almost always closed/refused.
        let result = send_tcp("127.0.0.1:1", &[], Duration::from_secs(1));
        assert!(result.is_err());
    }

    /// H1 regression: connect_timeout must return an error quickly instead of
    /// blocking for the OS default (~2 min).
    ///
    /// 192.0.2.1 is TEST-NET-1 (RFC 5737) — routable but never responds.
    /// We use a 300 ms timeout and assert the whole call finishes in < 5 s.
    #[test]
    #[ignore = "requires a network environment where 192.0.2.1 is unreachable (not a local loopback)"]
    fn test_send_tcp_connect_timeout_respected() {
        use std::time::Instant;
        let start = Instant::now();
        let result = send_tcp("192.0.2.1:9999", &[], Duration::from_millis(300));
        let elapsed = start.elapsed();
        assert!(result.is_err(), "connection to unreachable IP must fail");
        assert!(
            elapsed < Duration::from_secs(5),
            "connect_timeout must return within 5 s, took {elapsed:?}"
        );
    }

    #[test]
    fn test_send_tcp_invalid_addr_returns_err() {
        // A non-parseable address string must return Err immediately.
        let result = send_tcp("not-an-ip:port", &[], Duration::from_secs(1));
        assert!(result.is_err(), "invalid address must return Err");
    }
}
