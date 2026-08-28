#[test]
fn public_api_surface_is_contracted() {
    let t = trybuild::TestCases::new();
    // The supported consumer path must keep compiling.
    t.pass("tests/ui/supported_consumer_path.rs");
    // Everything the AEG-45 contraction removed from the surface must not.
    t.compile_fail("tests/ui/audit_schema_version_is_sealed.rs");
    // AILAB-619 extended the same seal to the chain position and the signature.
    t.compile_fail("tests/ui/audit_chain_fields_are_sealed.rs");
    t.compile_fail("tests/ui/fixture_api_needs_test_utils.rs");
    t.compile_fail("tests/ui/policy_ast_not_exported.rs");
    t.compile_fail("tests/ui/capability_register_is_runtime_internal.rs");
    // AILAB-710: the tool identity a call request carries is the one policy
    // judges. The divergent state is unrepresentable, so the assertion that it
    // fails closed is a compile error, not a runtime error.
    t.compile_fail("tests/ui/call_request_cannot_name_a_second_tool.rs");
}
