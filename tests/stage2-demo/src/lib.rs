//! Stage 2 demo — native reference detector + equivalence scorecard support.
//!
//! The library half is the **native reference** implementation of the path-scan
//! detector (`native::scan_native`). The integration tests in `tests/` drive the
//! matching **wasip2 guest** through `Runtime::execute_tool_call` and assert the
//! two agree on a shared fixture tree (design doc D10 equivalence).

pub mod native;
