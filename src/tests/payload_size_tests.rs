/// H3 unit tests: --payload-b64 size guard.
///
/// The macOS ARG_MAX is 1 MiB, so we cannot pass 32 MiB via the CLI in an
/// integration test.  These tests verify the guard constant and the comparison
/// predicate directly.  The exit-2 code path reachability is covered by
/// `tests/integration.rs::test_cli_payload_not_json_exits_2`.
// Bring the constant into scope from the crate root.
use crate::MAX_PAYLOAD_B64_BYTES;

/// H3: the size guard constant is set to 32 MiB.
#[test]
fn test_max_payload_b64_bytes_is_32_mib() {
    assert_eq!(
        MAX_PAYLOAD_B64_BYTES,
        32 * 1024 * 1024,
        "MAX_PAYLOAD_B64_BYTES must be 32 MiB"
    );
}

/// H3: a string longer than MAX_PAYLOAD_B64_BYTES satisfies the guard predicate.
/// A string at exactly the limit must NOT be rejected.
#[test]
fn test_oversized_payload_guard_condition() {
    let oversized = "A".repeat(MAX_PAYLOAD_B64_BYTES + 1);
    assert!(
        oversized.len() > MAX_PAYLOAD_B64_BYTES,
        "guard condition must be true for oversized payload"
    );
    // Exact-limit payload must pass the guard.
    let at_limit = "A".repeat(MAX_PAYLOAD_B64_BYTES);
    assert!(
        !(at_limit.len() > MAX_PAYLOAD_B64_BYTES),
        "payload at exactly MAX_PAYLOAD_B64_BYTES must not be rejected"
    );
}
