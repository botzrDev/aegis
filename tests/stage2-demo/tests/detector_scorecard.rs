//! Stage 2 detector scorecard (MASTER PRD §8 Stage 2 / §10; design doc D10).
//!
//! Drives the real wasip2 path-detector guest through the full
//! `POLICY → CAPABILITY → SANDBOX → AUDIT` pipeline (`Runtime::execute_tool_call`,
//! Model A — never `execute_host_call`) and proves:
//!
//!   * native reference findings == wasm findings on a shared fixture tree (D10);
//!   * out-of-grant `fs.write` and `net` attempts deny cleanly, guest-level;
//!   * the epoch/wall-clock cap trips with an audit `ResourceExceeded` record;
//!   * every run emits an intent + outcome audit line.

use std::path::Path;

use aegis_stage2_demo::native::scan_native;
use botzr_aegis_audit::{insecure_dev_key, to_json_line, AuditWriter, MemoryChainSink};
use botzr_aegis_capability::{FsNeeds, PathNeed, ToolInfo, ToolKind, ToolLimits, ToolManifest};
use botzr_aegis_core::{AegisError, AuditRecord, ExecutionOutcome, ToolId};
use botzr_aegis_policy::CallAxes;
use botzr_aegis_runtime::{sha256_hex, Runtime, ToolCallRequest};
use serde_json::Value;

/// Checked-in guest component (rebuild via `./scripts/build-fixtures.sh`).
const DETECTOR_WASM: &[u8] = include_bytes!("../../fixtures/path-detector/path-detector.wasm");

/// Raw WAT component with an infinite-loop `spin` export — reused verbatim from
/// `runtime/tests/resource_orchestrator.rs` so the wall-clock cap test needs no
/// new guest export (see spec §5: "spin-style export").
const SPIN: &str = r#"
(component
  (core module $m
    (func (export "spin") (loop br 0)))
  (core instance $i (instantiate $m))
  (func (export "spin") (canon lift (core func $i "spin"))))
"#;

fn detector_info() -> ToolInfo {
    ToolInfo {
        id: ToolId::new("path-detector"),
        version: "0.1.0".into(),
        kind: ToolKind::Wasm,
    }
}

/// Register the path-detector against `dir` with a single read-only `fs` grant
/// (default-deny writes, no net) and a digest pin. `dir` is preopened at `/ro0`;
/// the guest scans `/ro0/<scan_root>` (default `"fixtures"`).
fn setup_runtime(dir: &Path) -> (Runtime, MemoryChainSink) {
    let manifest = ToolManifest::new(detector_info(), dir)
        .with_fs(FsNeeds {
            read: vec![PathNeed::recursive(".")],
            write: vec![],
        })
        .with_sha256(sha256_hex(DETECTOR_WASM));

    let (mut rt, audit) = audited_runtime();
    rt.register(manifest, DETECTOR_WASM.to_vec())
        .expect("register path-detector");
    (rt, audit)
}

/// A runtime whose audit Chain this scorecard can read back.
///
/// The default Sink is Volatile and in-memory (ADR-0012) and the writer owns
/// it, so a test that wants the bytes supplies its own `MemoryChainSink` and
/// keeps a clone — `Clone` shares the buffer.
fn audited_runtime() -> (Runtime, MemoryChainSink) {
    let store = MemoryChainSink::new();
    let rt = Runtime::new().with_audit(
        AuditWriter::with_sink(Box::new(store.clone()), insecure_dev_key())
            .expect("volatile memory sink must open"),
    );
    (rt, store)
}

/// Write a small three-file tree under `<dir>/fixtures` for the scan tests.
fn seed_fixture_tree(dir: &Path) {
    let scan = dir.join("fixtures");
    std::fs::create_dir_all(scan.join("nested")).unwrap();
    std::fs::write(scan.join("alpha.txt"), b"alpha payload\n").unwrap();
    std::fs::write(scan.join("beta.txt"), b"beta\n").unwrap();
    std::fs::write(scan.join("nested/gamma.txt"), b"gamma nested payload\n").unwrap();
}

fn audit_lines(audit: &MemoryChainSink) -> Vec<String> {
    audit
        .to_text()
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(str::to_owned)
        .collect()
}

/// Read the audit trail and return the parsed outcome record.
///
/// Schema v2 opens the file with the Session `Open` line, so a single call is
/// three lines, not two.
fn outcome(audit: &MemoryChainSink) -> AuditRecord {
    let lines = audit_lines(audit);
    assert_eq!(lines.len(), 3, "open + intent + outcome");
    assert!(lines[0].contains("\"line_type\":\"open\""));
    assert!(lines[1].contains("\"line_type\":\"intent\""));
    serde_json::from_str(&lines[2]).expect("outcome parses")
}

fn run_detector(rt: &Runtime, input: &[u8]) -> Result<Vec<u8>, AegisError> {
    let tool = ToolId::new("path-detector");
    rt.execute_tool_call(ToolCallRequest::new(
        tool.clone(),
        input,
        CallAxes::default(),
    ))
}

// --- Equivalence -------------------------------------------------------------

/// D10: the from-scratch native reference and the wasip2 guest must return the
/// identical findings JSON for the same fixture tree.
#[test]
fn equivalence_native_matches_wasm() {
    let dir = tempfile::tempdir().unwrap();
    seed_fixture_tree(dir.path());

    let (rt, _audit) = setup_runtime(dir.path());
    let out = run_detector(&rt, br#"{"scan_root":"fixtures"}"#).expect("scan runs");

    let wasm_json: Value = serde_json::from_slice(&out).expect("wasm output parses");
    let native_json = scan_native(dir.path(), "fixtures");

    assert_eq!(
        native_json, wasm_json,
        "native findings must equal wasm findings"
    );

    // Sanity: the shared tree actually produced the three files, in sorted order.
    let findings = wasm_json["findings"].as_array().expect("findings array");
    let paths: Vec<&str> = findings
        .iter()
        .map(|f| f["path"].as_str().unwrap())
        .collect();
    assert_eq!(paths, ["alpha.txt", "beta.txt", "nested/gamma.txt"]);
}

// --- Happy path audit --------------------------------------------------------

/// §10: a successful pipeline run emits exactly an intent + outcome line under
/// the Session `Open`, and the outcome records execution success.
#[test]
fn happy_path_audit_one_call_per_session() {
    let dir = tempfile::tempdir().unwrap();
    seed_fixture_tree(dir.path());

    let (rt, audit) = setup_runtime(dir.path());
    let out = run_detector(&rt, br#"{"scan_root":"fixtures"}"#).expect("scan runs");
    let json: Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(json["findings"].as_array().unwrap().len(), 3);

    let lines = audit_lines(&audit);
    assert_eq!(lines.len(), 3, "open + intent + outcome");
    assert!(lines[0].contains("\"line_type\":\"open\""));
    assert!(lines[1].contains("\"line_type\":\"intent\""));
    assert!(lines[2].contains("\"line_type\":\"outcome\""));
    assert!(lines[2].contains("\"status\":\"success\""));
}

// --- Guest-level deny cases --------------------------------------------------

/// A write under the read-only preopen must trap, never silently succeed.
#[test]
fn write_escape_denied() {
    let dir = tempfile::tempdir().unwrap();
    let (rt, audit) = setup_runtime(dir.path());

    let err = run_detector(&rt, br#"{"attack":"write_escape"}"#)
        .expect_err("write under a read-only preopen must fail");
    assert!(
        matches!(err, AegisError::Trap { .. }),
        "expected Trap, got {err:?}"
    );

    let record = outcome(&audit);
    assert!(
        !matches!(record.execution, ExecutionOutcome::Success),
        "deny must not report success"
    );
    match &record.execution {
        ExecutionOutcome::Trap { message } => {
            assert!(message.contains("fs_write_denied"), "{message}")
        }
        other => panic!("expected trap, got {other:?}"),
    }
    assert!(to_json_line(&record)
        .unwrap()
        .contains("\"status\":\"trap\""));
}

/// The Model B `http` import without a net grant must deny, never silently
/// succeed.
#[test]
fn http_probe_denied() {
    let dir = tempfile::tempdir().unwrap();
    let (rt, audit) = setup_runtime(dir.path());

    let err = run_detector(&rt, br#"{"attack":"http_probe"}"#)
        .expect_err("http without a net grant must fail");
    assert!(
        matches!(err, AegisError::Trap { .. }),
        "expected Trap, got {err:?}"
    );

    let record = outcome(&audit);
    assert!(
        !matches!(record.execution, ExecutionOutcome::Success),
        "deny must not report success"
    );
    match &record.execution {
        ExecutionOutcome::Trap { message } => {
            assert!(message.contains("no net grant"), "{message}")
        }
        other => panic!("expected trap, got {other:?}"),
    }
    assert!(to_json_line(&record)
        .unwrap()
        .contains("\"status\":\"trap\""));
}

// --- Resource cap ------------------------------------------------------------

/// §10: a tight wall-clock cap trips cleanly with an audit `ResourceExceeded`.
/// Mirrors `resource_orchestrator.rs` — reuse the WAT `spin` fixture rather than
/// add a spinning guest export.
#[test]
fn wall_clock_cap_trips() {
    let dir = tempfile::tempdir().unwrap();
    let manifest = ToolManifest::new(
        ToolInfo {
            id: ToolId::new("path-detector-spin"),
            version: "0.1.0".into(),
            kind: ToolKind::Wasm,
        },
        dir.path(),
    )
    .with_limits(ToolLimits {
        max_memory_bytes: 1 << 20,
        max_wall_ms: 50,
        ..ToolLimits::default()
    });

    let (mut rt, audit) = audited_runtime();
    rt.register_fixture(manifest, SPIN.as_bytes().to_vec(), "spin")
        .expect("register spin fixture");

    let tool = ToolId::new("path-detector-spin");
    let err = rt
        .execute_tool_call(ToolCallRequest::new(
            tool.clone(),
            b"{}",
            CallAxes::default(),
        ))
        .unwrap_err();
    assert!(
        matches!(err, AegisError::ResourceExceeded { ref kind } if kind == "wall_clock"),
        "expected ResourceExceeded(wall_clock), got {err:?}"
    );

    let record = outcome(&audit);
    assert!(
        matches!(
            record.execution,
            ExecutionOutcome::ResourceExceeded { ref kind } if kind == "wall_clock"
        ),
        "expected wall_clock resource exceeded, got {:?}",
        record.execution
    );
    let wall_ms = record.wall_ms.expect("wall_ms recorded");
    assert!(wall_ms >= 40, "wall_ms={wall_ms}");
    assert!(record.peak_memory_bytes.is_some());
}
