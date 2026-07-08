wit_bindgen::generate!({
    world: "tool",
    path: "../../../wit/aegis/tool",
    with: {
        "aegis:host/http@0.1.0": generate,
        "aegis:host/log@0.1.0": generate,
    },
});

struct Echo;

impl Guest for Echo {
    fn describe() -> ToolInfo {
        ToolInfo {
            id: "echo".into(),
            version: "0.1.0".into(),
            kind: aegis::tool::tool_types::ToolKind::Wasm,
        }
    }

    fn run(input: Vec<u8>) -> Result<Vec<u8>, ToolError> {
        Ok(input)
    }
}

export!(Echo);
