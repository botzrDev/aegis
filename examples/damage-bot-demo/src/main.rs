use std::path::Path;

use botzr_aegis_capability::{ToolInfo, ToolKind, ToolManifest};
use botzr_aegis_core::ToolId;
use botzr_aegis_runtime::Runtime;

fn main() -> Result<(), String> {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));

    // Load the damage-bot WASM component.
    let wasm_path = manifest_dir
        .parent()
        .unwrap()
        .join("tests/fixtures/damage-bot/damage-bot.wasm");
    let component_bytes =
        std::fs::read(&wasm_path).map_err(|e| format!("read damage-bot.wasm: {e}"))?;

    let mut rt = Runtime::new();

    // Register the adversarial tool.
    rt.register(
        ToolManifest::new(
            ToolInfo {
                id: ToolId::new("damage-bot"),
                version: "0.1.0".into(),
                kind: ToolKind::Wasm,
            },
            manifest_dir,
        ),
        component_bytes,
    )
    .map_err(|e| format!("register: {e}"))?;

    // Execute a benign call (damage-bot behaves unless told to attack).
    // AEG-42 typed surface: render the error for this demo's `String` main.
    let output = rt
        .execute_tool_call(ToolId::new("damage-bot"), "default-input".into(), b"{}")
        .map_err(|e| format!("execute: {e}"))?;
    println!("damage-bot output: {}", String::from_utf8_lossy(&output));
    println!("audit log at: {}", rt.audit().path().display());
    Ok(())
}
