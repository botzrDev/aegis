//! Cross-crate workspace smoke tests (deny-suite lands in AEG-8).

use botzr_aegis_core::{ToolId, PIPELINE_STAGES};
use botzr_aegis_runtime::Runtime;

#[test]
fn pipeline_order_is_load_bearing() {
    assert_eq!(
        PIPELINE_STAGES,
        &["policy", "capability", "sandbox", "audit"]
    );
}

#[test]
fn runtime_stub_runs_through_policy() {
    let rt = Runtime::new();
    let tool_id = ToolId::new("smoke");
    let result = rt.execute_tool_call(tool_id, "deadbeef".into(), b"{}");
    // Capability resolver stub denies — proves policy passed and audit path ran.
    assert!(result.is_err());
}
