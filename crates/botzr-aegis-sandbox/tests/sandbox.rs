//! Sandbox lifecycle + resource-metering tests.
//!
//! These use tiny WAT components (no `wasm32-wasip2` toolchain needed) to
//! exercise the load-bearing paths: engine/store lifecycle, grant-driven store
//! configuration, and the epoch + memory caps actually tripping.

use botzr_aegis_core::{CapabilityGrant, FsGrant, ToolId};
use botzr_aegis_sandbox::{SandboxEngine, SandboxError};

fn grant(fs: Option<FsGrant>, max_memory_bytes: u64, max_wall_ms: u64) -> CapabilityGrant {
    CapabilityGrant {
        grant_id: "test-grant".to_string(),
        tool_id: ToolId::new("test-tool"),
        fs,
        net: None,
        max_memory_bytes,
        max_wall_ms,
    }
}

const NOOP: &str = r#"
(component
  (core module $m (func (export "go")))
  (core instance $i (instantiate $m))
  (func (export "go") (canon lift (core func $i "go"))))
"#;

const SPIN: &str = r#"
(component
  (core module $m
    (func (export "spin") (loop br 0)))
  (core instance $i (instantiate $m))
  (func (export "spin") (canon lift (core func $i "spin"))))
"#;

const GROW: &str = r#"
(component
  (core module $m
    (memory 1)
    (func (export "grow") (result i32)
      i32.const 100
      memory.grow))
  (core instance $i (instantiate $m))
  (func (export "grow") (result s32) (canon lift (core func $i "grow"))))
"#;

#[test]
fn engine_builds_and_prepares_component() {
    let engine = SandboxEngine::new().expect("engine builds");
    engine
        .prepare_fixture(NOOP)
        .expect("empty-import component prepares");
}

#[test]
fn build_store_from_read_grant() {
    let dir = tempfile::tempdir().unwrap();
    let engine = SandboxEngine::new().unwrap();
    let g = grant(
        Some(FsGrant {
            read_paths: vec![dir.path().to_string_lossy().into_owned()],
            write_paths: vec![],
        }),
        1 << 20,
        1000,
    );
    engine
        .build_store(&g)
        .expect("store builds from a valid read grant");
}

#[test]
fn build_store_rejects_missing_preopen_dir() {
    let engine = SandboxEngine::new().unwrap();
    let g = grant(
        Some(FsGrant {
            read_paths: vec!["/nonexistent/aegis/test/path".to_string()],
            write_paths: vec![],
        }),
        1 << 20,
        1000,
    );
    // `Store<ToolState>` is not `Debug`, so match on the result directly.
    let result = engine.build_store(&g);
    assert!(matches!(result, Err(SandboxError::StoreConfig(_))));
}

#[tokio::test]
async fn noop_component_runs_to_completion() {
    let engine = SandboxEngine::new().unwrap();
    let tool = engine.prepare_fixture(NOOP).unwrap();
    let g = grant(None, 1 << 20, 1000);
    tool.call_unit(&engine, &g, "go")
        .await
        .expect("noop returns cleanly");
}

#[tokio::test]
async fn epoch_deadline_traps_spinning_guest() {
    let engine = SandboxEngine::new().unwrap();
    let tool = engine.prepare_fixture(SPIN).unwrap();
    // 50 ms budget; the 1 ms ticker trips the deadline on the loop back-edge.
    let g = grant(None, 1 << 20, 50);
    let err = tool
        .call_unit(&engine, &g, "spin")
        .await
        .expect_err("spinning guest must trap");
    match err {
        SandboxError::ResourceExceeded { kind } => assert_eq!(kind, "wall_clock"),
        other => panic!("expected wall_clock ResourceExceeded, got {other:?}"),
    }
}

#[tokio::test]
async fn memory_limiter_denies_growth_past_cap() {
    let engine = SandboxEngine::new().unwrap();
    let tool = engine.prepare_fixture(GROW).unwrap();
    // 128 KiB cap: the initial 64 KiB page fits, growing by 100 pages does not.
    let g = grant(None, 128 * 1024, 1000);
    let result = tool
        .call_i32(&engine, &g, "grow")
        .await
        .expect("call itself completes; growth is denied in-band");
    assert_eq!(result, -1, "memory.grow past the cap returns -1");
}

#[tokio::test]
async fn instantiation_fails_when_initial_memory_exceeds_cap() {
    let engine = SandboxEngine::new().unwrap();
    let tool = engine.prepare_fixture(GROW).unwrap();
    // 0-byte cap: even the initial linear memory page cannot be allocated.
    let g = grant(None, 0, 1000);
    let err = tool
        .call_i32(&engine, &g, "grow")
        .await
        .expect_err("initial memory over cap must fail");
    // Classified as a trap/resource failure, never a silent success.
    assert!(matches!(
        err,
        SandboxError::Trap { .. } | SandboxError::ResourceExceeded { .. }
    ));
}
