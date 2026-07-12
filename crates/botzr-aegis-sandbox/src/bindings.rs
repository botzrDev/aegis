//! WIT world bindings for `aegis:tool@0.1.0` and Model B host imports.

wasmtime::component::bindgen!({
    world: "tool",
    // Packaged with the crate (crates.io cannot see repo-root ../../wit).
    path: "wit/aegis/tool",
    imports: { default: async },
    exports: { default: async },
});
