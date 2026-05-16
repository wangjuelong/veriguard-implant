//! `NetworkTraffic` payload: send TCP/UDP probe traffic to one or more targets.
//!
//! # JSON spec (`--payload-b64` decoded)
//!
//! Single tuple (backward compatible):
//! ```json
//! {
//!   "protocol": "tcp",            // "tcp" | "udp"
//!   "target": "192.168.1.1",
//!   "port": 4444,
//!   "data_b64": "<base64>",       // optional payload bytes to send
//!   "timeout_secs": 5             // optional per-connection timeout
//! }
//! ```
//!
//! Multi-tuple (IPv6 安全验证系统 §4.4 "同一流量验证用例中包含多个端口不同的四元组"):
//! ```json
//! {
//!   "protocol": "tcp",
//!   "target": "2001:db8::2",
//!   "port": 443,
//!   "timeout_secs": 5,
//!   "extra_tuples": [
//!     { "protocol": "tcp", "target": "2001:db8::2", "port": 8080 },
//!     { "protocol": "udp", "target": "2001:db8::4", "port": 53,
//!       "data_b64": "..." }
//!   ]
//! }
//! ```
//!
//! `extra_tuples` 的每个元素都按主元组同样的逻辑发送一次；`timeout_secs` 全局共用主元组的设置。
//! 任一 tuple 失败即整体 Failed（stderr 拼接每个失败 tuple 的错误信息）；全部成功 Completed。

use crate::common::error_model::Error;
use crate::payload::{ExecContext, FinalStatus, Payload, PayloadResult};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde::Deserialize;
use std::io::{self, Write};
use std::net::{TcpStream, UdpSocket};
use std::time::Duration;

/// Protocol selection for the network probe.
#[derive(Debug, Deserialize, PartialEq, Eq, Clone, Copy)]
#[serde(rename_all = "lowercase")]
pub enum NetProtocol {
    Tcp,
    Udp,
}

/// One (protocol, target, port[, data_b64]) tuple. Used both for the primary
/// connection (flat fields on [`NetworkTrafficPayload`]) and as the element
/// type of the `extra_tuples` list (招标 §4.4 多端口四元组).
#[derive(Debug, Deserialize, Clone)]
pub struct NetworkTrafficTuple {
    pub protocol: NetProtocol,
    pub target: String,
    pub port: u16,
    /// Optional data to send (base64-encoded).
    #[serde(default)]
    pub data_b64: Option<String>,
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
    /// Additional tuples to probe in the same invocation (§4.4). Empty / absent
    /// means single-tuple legacy behaviour.
    #[serde(default)]
    pub extra_tuples: Vec<NetworkTrafficTuple>,
}

fn default_timeout_secs() -> u64 {
    5
}

impl Payload for NetworkTrafficPayload {
    fn execute(&self, ctx: &mut ExecContext<'_>) -> PayloadResult {
        let timeout = Duration::from_secs(self.timeout_secs);

        // Iterate primary tuple first, then each extra tuple. Each tuple
        // contributes its progress event + stdout line. Failure of any tuple
        // marks overall result as Failed but still attempts the remaining ones.
        let tuples = std::iter::once(NetworkTrafficTuple {
            protocol: self.protocol,
            target: self.target.clone(),
            port: self.port,
            data_b64: self.data_b64.clone(),
        })
        .chain(self.extra_tuples.iter().cloned());

        let mut stdout_acc: Vec<u8> = Vec::new();
        let mut stderr_acc: Vec<u8> = Vec::new();
        let mut any_failed = false;
        let mut last_err_summary: Option<String> = None;

        for (idx, tuple) in tuples.enumerate() {
            let addr = format!("{}:{}", tuple.target, tuple.port);
            let role = if idx == 0 {
                "primary".to_string()
            } else {
                format!("extra[{}]", idx - 1)
            };

            ctx.writer
                .write_progress(
                    ctx.task_id,
                    "connecting",
                    Some(&format!(
                        "sending {:?} traffic to {addr} ({role})",
                        tuple.protocol
                    )),
                )
                .map_err(|e| Error::Internal(e.to_string()))?;

            let data = match &tuple.data_b64 {
                Some(b64) => STANDARD
                    .decode(b64)
                    .map_err(|e| Error::Internal(format!("base64 decode error: {e}")))?,
                None => vec![],
            };

            let result = match tuple.protocol {
                NetProtocol::Tcp => send_tcp(&addr, &data, timeout),
                NetProtocol::Udp => send_udp(&addr, &data, timeout),
            };

            match result {
                Ok(line) => {
                    stdout_acc.extend_from_slice(format!("[{role}] ").as_bytes());
                    stdout_acc.extend_from_slice(&line);
                    stdout_acc.push(b'\n');
                }
                Err(e) => {
                    any_failed = true;
                    let err_line = format!("[{role}] {addr}: {e}");
                    stderr_acc.extend_from_slice(err_line.as_bytes());
                    stderr_acc.push(b'\n');
                    last_err_summary = Some(format!("{role} {addr}: network error"));
                }
            }
        }

        if any_failed {
            Ok((
                FinalStatus::Failed,
                1,
                stdout_acc,
                stderr_acc,
                last_err_summary.or_else(|| Some("network error".to_string())),
            ))
        } else {
            Ok((FinalStatus::Completed, 0, stdout_acc, stderr_acc, None))
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
    // Parse first so we can choose the matching local bind address family.
    let sock_addr: std::net::SocketAddr = addr
        .parse()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    // Bind to the unspecified address of the same family as the target.
    // Binding an IPv4 socket and then send_to-ing an IPv6 address fails with
    // "address family not supported" on most platforms.
    let local_addr = if sock_addr.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let socket = UdpSocket::bind(local_addr)?;
    socket.set_write_timeout(Some(timeout))?;
    let send_data = if data.is_empty() {
        b"\x00" as &[u8]
    } else {
        data
    };
    socket.send_to(send_data, sock_addr)?;
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
        assert!(p.extra_tuples.is_empty()); // default: single-tuple legacy
    }

    #[test]
    fn test_network_traffic_payload_deserialize_udp_with_data() {
        let json = r#"{"protocol":"udp","target":"10.0.0.1","port":53,"data_b64":"AAAA","timeout_secs":3}"#;
        let p: NetworkTrafficPayload = serde_json::from_str(json).unwrap();
        assert_eq!(p.protocol, NetProtocol::Udp);
        assert_eq!(p.timeout_secs, 3);
        assert!(p.data_b64.is_some());
        assert!(p.extra_tuples.is_empty());
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

    /// M4: send_udp with an IPv4 target must bind 0.0.0.0:0 (not fail on
    /// address-family mismatch).  We expect a send error (port closed), not a
    /// bind error.
    #[test]
    fn test_send_udp_ipv4_binds_correctly() {
        // Port 1 is almost always closed; UDP send_to itself succeeds (fire-and-forget).
        // The important thing is that bind("0.0.0.0:0") succeeds for an IPv4 target.
        let result = send_udp("127.0.0.1:1", &[], Duration::from_secs(1));
        // UDP send is fire-and-forget; it may succeed (no ICMP reply on loopback).
        // We only assert it does NOT fail with a bind error.
        match &result {
            Err(e) => assert!(
                e.kind() != std::io::ErrorKind::AddrNotAvailable,
                "IPv4 UDP must not fail with AddrNotAvailable: {e}"
            ),
            Ok(_) => {}
        }
    }

    /// M4: send_udp with an IPv6 loopback target must bind [::]:0, not
    /// 0.0.0.0:0 (which would fail with address family mismatch on most OSes).
    #[test]
    fn test_send_udp_ipv6_binds_correctly() {
        // ::1 is the IPv6 loopback — available on all platforms with IPv6.
        let result = send_udp("[::1]:1", &[], Duration::from_secs(1));
        match &result {
            Err(e) => assert!(
                e.kind() != std::io::ErrorKind::AddrNotAvailable,
                "IPv6 UDP must not fail with AddrNotAvailable: {e}"
            ),
            Ok(_) => {}
        }
    }

    #[test]
    fn test_send_udp_invalid_addr_returns_err() {
        let result = send_udp("not-an-addr", &[], Duration::from_secs(1));
        assert!(result.is_err(), "invalid address must return Err");
    }

    // ===== §4.4 multi-tuple tests =====

    /// 反序列化携带 extra_tuples 的 JSON —— 招标 §4.4 wire 形态由 platform StatusPayload 透传.
    #[test]
    fn test_deserialize_with_extra_tuples() {
        let json = r#"{
            "protocol": "tcp",
            "target": "2001:db8::2",
            "port": 443,
            "extra_tuples": [
                {"protocol": "tcp", "target": "2001:db8::2", "port": 8080},
                {"protocol": "udp", "target": "2001:db8::4", "port": 53, "data_b64": "AAAA"}
            ]
        }"#;
        let p: NetworkTrafficPayload = serde_json::from_str(json).unwrap();
        assert_eq!(p.target, "2001:db8::2");
        assert_eq!(p.port, 443);
        assert_eq!(p.extra_tuples.len(), 2);
        assert_eq!(p.extra_tuples[0].port, 8080);
        assert_eq!(p.extra_tuples[1].protocol, NetProtocol::Udp);
        assert!(p.extra_tuples[1].data_b64.is_some());
    }

    /// 旧版 JSON (无 extra_tuples key) 反序列化仍可工作 —— 向后兼容保证.
    #[test]
    fn test_deserialize_legacy_without_extra_tuples_field() {
        let json = r#"{"protocol":"tcp","target":"10.0.0.1","port":80}"#;
        let p: NetworkTrafficPayload = serde_json::from_str(json).unwrap();
        assert!(
            p.extra_tuples.is_empty(),
            "missing extra_tuples key must default to empty list, not panic"
        );
    }

    /// extra_tuples 显式为空数组 —— 也走单 tuple 路径.
    #[test]
    fn test_deserialize_extra_tuples_empty_array() {
        let json = r#"{"protocol":"tcp","target":"10.0.0.1","port":80,"extra_tuples":[]}"#;
        let p: NetworkTrafficPayload = serde_json::from_str(json).unwrap();
        assert!(p.extra_tuples.is_empty());
    }
}
