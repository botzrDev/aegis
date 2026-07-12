//! AEG-18 Stage 3 consumer-proof tests — sandbox + core only.
//!
//! These prove an external host can prepare and execute a real wasip2 guest, and
//! that a read-only grant denies a write attempt cleanly (never a silent
//! success), using nothing from the Aegis orchestrator stack.

use botzr_aegis_sandbox::SandboxError;
use sandbox_consumer::scan_fixtures;

/// Happy path: the guest scans the read-only preopen and returns the three
/// checked-in fixture files.
#[test]
fn happy_path_scan_returns_findings() {
    let run =
        scan_fixtures(br#"{"scan_root":"fixtures"}"#).expect("engine builds + guest prepares");
    let bytes = run.output.expect("scan runs cleanly");
    let text = String::from_utf8(bytes).expect("findings are utf-8 json");

    // The fixture tree is alpha.txt, beta.txt, nested/gamma.txt.
    assert!(text.contains("alpha.txt"), "{text}");
    assert!(text.contains("beta.txt"), "{text}");
    assert!(text.contains("nested/gamma.txt"), "{text}");

    // The scan is trivial; it must finish well inside its 1 s wall budget.
    assert!(
        run.metrics.wall_ms < 1_000,
        "wall_ms={}",
        run.metrics.wall_ms
    );
}

/// Deny smoke: the read-only grant carries no write paths, so a guest write
/// attempt under the preopen must trap. cap-std refuses the write and the guest
/// surfaces `fs_write_denied` — proof the sandbox enforces the grant, not the
/// request.
#[test]
fn write_escape_denies_cleanly() {
    let run =
        scan_fixtures(br#"{"attack":"write_escape"}"#).expect("engine builds + guest prepares");
    match run.output {
        Err(SandboxError::Trap { message }) => {
            assert!(message.contains("fs_write_denied"), "{message}");
        }
        other => panic!("expected a write-denied trap, got {other:?}"),
    }
}
