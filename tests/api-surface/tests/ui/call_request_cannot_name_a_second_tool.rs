//! AILAB-710: a call request cannot name one tool and be judged as another.
//!
//! The runtime derives the policy tool id from the call request's own
//! `tool_id`. There is no second id for a caller to supply, so the divergent
//! state this ticket exists to remove is not merely rejected at run time — it
//! cannot be written down. That is what this case pins.
//!
//! It is a **compile-fail** test rather than a runtime one on purpose. A test
//! asserting that a mismatched request returns an error would be asserting
//! behaviour this design deliberately does not have: there is no mismatch path
//! left to take. The honest assertion is that the code does not build.
//!
//! Both shapes a caller could reach for are covered: passing a whole
//! `PolicyRequest` (the pre-710 API), and naming the removed `policy` field
//! directly in a struct literal.
use botzr_aegis_core::ToolId;
use botzr_aegis_policy::PolicyRequest;
use botzr_aegis_runtime::{HostCallRequest, ToolCallRequest};

fn main() {
    let executed = ToolId::new("echo");
    let judged = ToolId::new("admin.shell");

    // 1. The pre-710 constructor call: a second tool id, smuggled in behind a
    //    `PolicyRequest`, naming a different tool than the one that would run.
    let _a = ToolCallRequest::new(
        executed.clone(),
        b"hello",
        PolicyRequest::for_tool(&judged),
    );
    let _b = HostCallRequest::new(executed.clone(), b"{}", PolicyRequest::for_tool(&judged));

    // 2. The field itself is gone, so a struct literal cannot reintroduce it.
    let _c = ToolCallRequest {
        tool_id: executed.clone(),
        input: b"hello",
        policy: PolicyRequest::for_tool(&judged),
    };
    let _d = HostCallRequest {
        tool_id: executed,
        input: b"{}",
        policy: PolicyRequest::for_tool(&judged),
    };
}
