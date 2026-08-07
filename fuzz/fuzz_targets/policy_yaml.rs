#![no_main]
use botzr_aegis_core::ToolId;
use botzr_aegis_policy::{PolicyEngine, PolicyRequest};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(yaml) = std::str::from_utf8(data) else {
        return;
    };
    // Cap pathological inputs so CI smoke stays bounded.
    if yaml.len() > 64 * 1024 {
        return;
    }
    if let Ok(engine) = PolicyEngine::from_yaml(yaml) {
        let tool = ToolId::new("fuzz");
        let _ = engine.evaluate(&PolicyRequest::for_tool(&tool));
    }
});
