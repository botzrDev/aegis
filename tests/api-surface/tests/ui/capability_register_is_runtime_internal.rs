#![deny(deprecated)]
//! AEG-45: registering a manifest without its executable is split authority.
//! External crates must go through `Runtime::register_tool`.
use botzr_aegis_capability::{CapabilityResolver, ToolInfo, ToolKind, ToolManifest};
use botzr_aegis_core::ToolId;

fn main() {
    let manifest = ToolManifest::new(
        ToolInfo {
            id: ToolId::new("t"),
            version: "0.1.0".into(),
            kind: ToolKind::Wasm,
        },
        std::env::temp_dir(),
    );
    let mut resolver = CapabilityResolver::new();
    resolver.register(manifest);
}
