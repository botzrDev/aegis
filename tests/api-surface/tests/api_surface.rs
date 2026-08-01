#[test]
fn public_api_surface_is_contracted() {
    let t = trybuild::TestCases::new();
    // The supported consumer path must keep compiling.
    t.pass("tests/ui/supported_consumer_path.rs");
    // Everything the AEG-45 contraction removed from the surface must not.
    t.compile_fail("tests/ui/audit_schema_version_is_sealed.rs");
    t.compile_fail("tests/ui/fixture_api_needs_test_utils.rs");
    t.compile_fail("tests/ui/policy_ast_not_exported.rs");
    t.compile_fail("tests/ui/capability_register_is_runtime_internal.rs");
}
