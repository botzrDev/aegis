//! Resource-cap trips through the full POLICY → CAPABILITY → SANDBOX → AUDIT path.

use std::path::Path;

use botzr_aegis_audit::to_json_line;
use botzr_aegis_capability::{ToolInfo, ToolKind, ToolLimits, ToolManifest};
use botzr_aegis_core::{AegisError, AuditRecord, ExecutionOutcome, ToolId};
use botzr_aegis_runtime::Runtime;

const SPIN: &str = r#"
(component
  (core module $m
    (func (export "spin") (loop br 0)))
  (core instance $i (instantiate $m))
  (func (export "spin") (canon lift (core func $i "spin"))))
"#;

#[test]
fn wall_clock_resource_exceeded_through_orchestrator() {
    let base = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/echo-tool");
    let manifest = ToolManifest::new(
        ToolInfo {
            id: ToolId::new("spin"),
            version: "0.1.0".into(),
            kind: ToolKind::Wasm,
        },
        &base,
    )
    .with_limits(ToolLimits {
        max_memory_bytes: 1 << 20,
        max_wall_ms: 50,
        ..ToolLimits::default()
    });

    let mut rt = Runtime::new();
    rt.register_fixture(manifest, SPIN.as_bytes().to_vec(), "spin")
        .expect("register spin fixture");

    let err = rt
        .execute_tool_call(ToolId::new("spin"), "deadbeef".into(), b"{}")
        .unwrap_err();
    assert!(
        matches!(err, AegisError::ResourceExceeded { ref kind } if kind == "wall_clock"),
        "expected ResourceExceeded(wall_clock), got {err:?}"
    );

    let lines: Vec<String> = std::fs::read_to_string(rt.audit().path())
        .unwrap()
        .lines()
        .map(str::to_owned)
        .collect();
    assert_eq!(lines.len(), 2, "intent + outcome");

    let record: AuditRecord = serde_json::from_str(&lines[1]).expect("outcome parses");
    assert!(matches!(
        record.execution,
        ExecutionOutcome::ResourceExceeded { ref kind } if kind == "wall_clock"
    ));
    let wall_ms = record.wall_ms.expect("wall_ms recorded");
    assert!(wall_ms >= 40, "wall_ms={wall_ms}");
    assert!(record.peak_memory_bytes.is_some());
}

#[test]
fn golden_resource_exceeded_orchestrator_shape() {
    let base = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/echo-tool");
    let manifest = ToolManifest::new(
        ToolInfo {
            id: ToolId::new("spin"),
            version: "0.1.0".into(),
            kind: ToolKind::Wasm,
        },
        &base,
    )
    .with_limits(ToolLimits {
        max_memory_bytes: 1 << 20,
        max_wall_ms: 50,
        ..ToolLimits::default()
    });

    let mut rt = Runtime::new();
    rt.register_fixture(manifest, SPIN.as_bytes().to_vec(), "spin")
        .expect("register spin fixture");

    let _ = rt
        .execute_tool_call(ToolId::new("spin"), "0badf00d".into(), b"{}")
        .unwrap_err();

    let lines: Vec<String> = std::fs::read_to_string(rt.audit().path())
        .unwrap()
        .lines()
        .map(str::to_owned)
        .collect();
    let mut record: AuditRecord = serde_json::from_str(&lines[1]).expect("outcome parses");

    // Normalize volatile / sequential fields for the schema golden (R5 contract).
    record.call_id = "call-golden-orchestrator".into();
    if let botzr_aegis_core::CapabilityOutcome::Granted { ref mut grant } = record.capability {
        grant.grant_id = "spin-1".into();
    }
    record.wall_ms = Some(50);
    record.peak_memory_bytes = Some(65536);

    let actual = to_json_line(&record).expect("serialize");
    let expected = include_str!("golden/resource_exceeded_orchestrator.json");
    assert_eq!(actual.trim(), expected.trim());
}
