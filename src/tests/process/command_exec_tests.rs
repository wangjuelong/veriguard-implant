#[cfg(windows)]
use crate::common::constants::EXECUTOR_CMD;
#[cfg(windows)]
use crate::common::constants::EXECUTOR_POWERSHELL;
use crate::common::constants::STATUS_ERROR;
#[cfg(windows)]
use crate::common::constants::{STATUS_COMMAND_NOT_FOUND, STATUS_SUCCESS, STATUS_WARNING};
use crate::common::execution_result::decode_output;
#[cfg(windows)]
use crate::process::command_exec::format_powershell_command;
use crate::process::command_exec::{decode_command, invoke_command};

// -- DECODE_OUTPUT --

#[test]
fn test_decode_output_with_hello() {
    let output = vec![72, 101, 108, 108, 111];
    let decoded_output = decode_output(&output);
    assert_eq!(decoded_output, "Hello");
}

#[test]
fn test_decode_output_with_special_character() {
    let output = vec![195, 169, 195, 160, 195, 168];
    let decoded_output = decode_output(&output);
    assert_eq!(decoded_output, "éàè");
}

#[test]
fn test_decode_output_with_wrong_character() {
    // the byte 130 is an invalid utf8 charater
    // and should trigger an error while decoding it using "from_utf8"
    // we are testing that this not causing any failure
    // and it is using the fallback method "from_utf8_lossy"
    let output = vec![72, 101, 108, 108, 111, 130];
    let decoded_output = decode_output(&output);
    assert_eq!(decoded_output, "Hello�");
}

// -- DECODE_COMMAND --

#[test]
fn test_decode_command_valid_base64_utf8() {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    let encoded = STANDARD.encode("echo hello");
    let result = decode_command(&encoded);
    assert!(result.is_ok(), "valid base64+UTF-8 should decode successfully");
    // The result may have #{location} substituted; the core "echo hello" text is present.
    assert!(result.unwrap().contains("echo hello"));
}

#[test]
fn test_decode_command_invalid_base64_returns_err() {
    // "!!!" is not valid base64 — must return Err, never panic.
    let result = decode_command("!!!not-base64!!!");
    assert!(
        result.is_err(),
        "invalid base64 must return Err, not panic"
    );
}

#[test]
fn test_decode_command_invalid_utf8_returns_err() {
    // Encode raw bytes that are valid base64 but not valid UTF-8 (0xFF, 0xFE).
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    let non_utf8 = STANDARD.encode([0xFF_u8, 0xFE, 0x00]);
    let result = decode_command(&non_utf8);
    assert!(
        result.is_err(),
        "non-UTF-8 payload must return Err, not panic"
    );
}

// -- H2: stderr piped --

/// Verify that stderr written by a child process is captured in
/// ExecutionResult.stderr (not leaked to the parent) and therefore available
/// for result_final.stderr_b64.
#[test]
#[cfg(unix)]
fn test_invoke_command_captures_stderr() {
    use crate::common::constants::EXECUTOR_SH;

    // "echo err 1>&2" writes "err\n" to stderr and nothing to stdout.
    let result = invoke_command(EXECUTOR_SH, "echo err 1>&2", &["-c"], false)
        .expect("invoke_command must succeed");

    assert!(
        result.stderr.contains("err"),
        "stderr must be captured, got: {:?}",
        result.stderr
    );
    assert!(
        result.stdout.is_empty() || !result.stdout.contains("err"),
        "err must not appear in stdout"
    );
}

// -- INVOKE_COMMAND --

#[ignore]
#[test]
#[cfg(windows)]
fn test_invoke_command_powershell_special_character() {
    let command = "echo Helloé";
    let formatted_cmd = format_powershell_command(command.to_string());
    let args: Vec<&str> = vec!["-c"];

    let result = invoke_command(EXECUTOR_POWERSHELL, &formatted_cmd, args.as_slice(), false)
        .expect("Failed to invoke PowerShell command");

    assert_eq!(result.stdout, "Helloé\r\n");
}

#[test]
#[cfg(windows)]
fn test_invoke_command_cmd_with_quote() {
    let command = r#"echo "Hello""#;
    let args: Vec<&str> = vec!["/V", "/C"];

    let result = invoke_command(EXECUTOR_CMD, &command, args.as_slice(), false)
        .expect("Failed to invoke CMD command");

    assert_eq!(result.stdout, "\"Hello\"\r\n");
}

// =============================================================
// Integration tests: real payload execution
// =============================================================

// -- SUCCESS scenarios --

#[test]
#[cfg(windows)]
fn test_real_cmd_echo_success() {
    let command = "echo Hello World";
    let args: Vec<&str> = vec!["/V", "/C"];

    let result = invoke_command(EXECUTOR_CMD, command, args.as_slice(), false)
        .expect("Failed to invoke CMD command");

    assert_eq!(result.status, STATUS_SUCCESS);
    assert_eq!(result.exit_code, 0);
    assert!(result.stdout.contains("Hello World"));
}

#[test]
#[cfg(windows)]
fn test_real_powershell_echo_success() {
    let command = format_powershell_command("Write-Output 'Hello World'".to_string());
    let args: Vec<&str> = vec!["-NonInteractive", "-NoProfile", "-Command"];

    let result = invoke_command(EXECUTOR_POWERSHELL, &command, args.as_slice(), false)
        .expect("Failed to invoke PowerShell command");

    assert_eq!(result.status, STATUS_SUCCESS);
    assert_eq!(result.exit_code, 0);
    assert!(result.stdout.contains("Hello World"));
}

// -- COMMAND_NOT_FOUND scenarios --

#[test]
#[cfg(windows)]
fn test_real_cmd_command_not_found() {
    let command = "this_command_does_not_exist_xyz";
    let args: Vec<&str> = vec!["/V", "/C"];

    let result = invoke_command(EXECUTOR_CMD, command, args.as_slice(), false)
        .expect("Should return result, not error");

    // CMD returns 9009 for command not found, mapped to COMMAND_NOT_FOUND
    // but some CMD versions may return 1; we accept either COMMAND_NOT_FOUND or ERROR
    assert!(result.exit_code != 0, "Expected non-zero exit code");
    assert!(
        result.status == STATUS_COMMAND_NOT_FOUND || result.status == STATUS_ERROR,
        "Expected COMMAND_NOT_FOUND or ERROR, got: {}",
        result.status
    );
}

#[test]
#[cfg(windows)]
fn test_real_powershell_command_not_found() {
    let command = format_powershell_command("this_command_does_not_exist_xyz".to_string());
    let args: Vec<&str> = vec!["-NonInteractive", "-NoProfile", "-Command"];

    let result = invoke_command(EXECUTOR_POWERSHELL, &command, args.as_slice(), false)
        .expect("Should return result, not error");

    assert_eq!(result.status, STATUS_COMMAND_NOT_FOUND);
    assert!(result.stderr.contains("CommandNotFoundException"));
}

// -- ERROR scenarios --

#[test]
#[cfg(windows)]
fn test_real_cmd_error_exit_code() {
    let command = "exit /b 42";
    let args: Vec<&str> = vec!["/V", "/C"];

    let result = invoke_command(EXECUTOR_CMD, command, args.as_slice(), false)
        .expect("Should return result, not error");

    assert_eq!(result.status, STATUS_ERROR);
    assert_eq!(result.exit_code, 42);
}

#[test]
#[cfg(windows)]
fn test_real_powershell_error_exit_code() {
    let command = format_powershell_command("throw 'Something went wrong'".to_string());
    let args: Vec<&str> = vec!["-NonInteractive", "-NoProfile", "-Command"];

    let result = invoke_command(EXECUTOR_POWERSHELL, &command, args.as_slice(), false)
        .expect("Should return result, not error");

    assert_eq!(result.status, STATUS_ERROR);
    assert_ne!(result.exit_code, 0);
    assert!(!result.stderr.is_empty());
}

// -- Executor not found (io error) --

#[test]
fn test_real_nonexistent_executor() {
    let command = "echo hello";
    let args: Vec<&str> = vec!["-c"];

    let result = invoke_command("nonexistent_shell_xyz", command, args.as_slice(), false)
        .expect("Should return result with error status");

    assert_eq!(result.status, STATUS_ERROR);
    assert_eq!(result.exit_code, -1);
    assert!(!result.stderr.is_empty());
}

// -- WARNING scenario (exit 0 but stderr not empty) --

#[test]
#[cfg(windows)]
fn test_real_powershell_warning() {
    let command = format_powershell_command(
        "[Console]::Error.WriteLine('warn'); Write-Output 'ok'".to_string(),
    );
    let args: Vec<&str> = vec!["-NonInteractive", "-NoProfile", "-Command"];

    let result = invoke_command(EXECUTOR_POWERSHELL, &command, args.as_slice(), false)
        .expect("Should return result");

    assert_eq!(result.exit_code, 0);
    assert_eq!(result.status, STATUS_WARNING);
    assert!(result.stdout.contains("ok"));
}
