// AEG-45: the raw-WASM-fixture path is gated behind `test-utils` in both the
// runtime and the sandbox. A default-features consumer build must not see any
// of it. Every type below is fully annotated so the ONLY errors are the
// missing APIs — never inference noise.
use botzr_aegis_capability::{ToolInfo, ToolKind, ToolManifest};
use botzr_aegis_core::ToolId;
use botzr_aegis_runtime::{Runtime, ToolExecutable};
use botzr_aegis_sandbox::SandboxEngine;

fn main() {
    let manifest: ToolManifest = ToolManifest::new(
        ToolInfo {
            id: ToolId::new("fixture"),
            version: "0.1.0".into(),
            kind: ToolKind::Wasm,
        },
        std::env::temp_dir(),
    );

    // Runtime half of the gate.
    let _ = ToolExecutable::WasmFixture {
        bytes: Vec::<u8>::new(),
        entry_export: String::from("go"),
    };
    let mut rt = Runtime::new();
    let _ = rt.register_fixture(manifest, Vec::<u8>::new(), "go");

    // Sandbox half of the gate.
    let engine = SandboxEngine::default();
    let _ = engine.prepare_fixture(&[0u8][..]);
}
