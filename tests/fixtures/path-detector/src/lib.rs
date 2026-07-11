//! Stage 2 minimal path-scan detector (Model A / wasip2 guest).
//!
//! Runs through the full `POLICY → CAPABILITY → SANDBOX → AUDIT` pipeline via
//! `Runtime::execute_tool_call`. The scan is deliberately tiny: it exists to
//! prove **native ↔ wasm equivalence** (design doc D10) rather than uveddi parity.
//! The same semantics are reimplemented from scratch on the host side in
//! `tests/stage2-demo/src/native.rs` — the scorecard asserts the two agree.
//!
//! Input is a small JSON object:
//!   * `{"scan_root":"<rel>"}` — walk `<rel>` under the read-only preopen
//!     (default `"fixtures"`), emitting `{"path","size"}` per file.
//!   * `{"attack":"<mode>"}` — one boundary violation for the deny scorecard;
//!     each returns `tool-error` on refusal, never silent success.
//!
//! Read-only, no network, no writes: the guest touches WASI preopened read dirs
//! only. The single `fs.read` grant is mounted at `/ro0` (see sandbox engine).

wit_bindgen::generate!({
    world: "tool",
    path: "../../../wit/aegis/tool",
    with: {
        "aegis:host/http@0.1.0": generate,
        "aegis:host/log@0.1.0": generate,
    },
});

struct PathDetector;

/// The single read-only preopen mount point (sandbox maps `read_paths[0]` here).
const READ_PREOPEN: &str = "/ro0";

#[derive(Debug, serde::Deserialize)]
struct Request {
    /// Subdirectory of the read preopen to scan. Defaults to `"fixtures"`.
    #[serde(default)]
    scan_root: Option<String>,
    /// Optional adversarial mode for the deny scorecard.
    #[serde(default)]
    attack: Option<String>,
}

/// One scanned file. `path` is relative to the scan root, `/`-separated.
#[derive(Debug)]
struct Finding {
    path: String,
    size: u64,
}

fn err(code: &str, message: impl Into<String>) -> ToolError {
    ToolError {
        code: code.into(),
        message: message.into(),
    }
}

impl Guest for PathDetector {
    fn describe() -> ToolInfo {
        ToolInfo {
            id: "path-detector".into(),
            version: "0.1.0".into(),
            kind: aegis::tool::tool_types::ToolKind::Wasm,
        }
    }

    fn run(input: Vec<u8>) -> Result<Vec<u8>, ToolError> {
        let req: Request = serde_json::from_slice(&input)
            .map_err(|e| err("bad_input", format!("invalid json: {e}")))?;

        if let Some(mode) = req.attack.as_deref() {
            return match mode {
                "write_escape" => attack_write_escape(),
                "http_probe" => attack_http_probe(),
                other => Err(err("unknown_attack", format!("unknown attack: {other}"))),
            };
        }

        let scan_root = req.scan_root.as_deref().unwrap_or("fixtures");
        let value = scan(scan_root);
        serde_json::to_vec(&value).map_err(|e| err("encode", format!("encode findings: {e}")))
    }
}

/// Walk `<preopen>/<scan_root>` recursively and build the findings document.
/// Identical semantics to `scan_native` on the host side (D10 equivalence).
fn scan(scan_root: &str) -> serde_json::Value {
    let base = format!("{READ_PREOPEN}/{scan_root}");
    let mut findings: Vec<Finding> = Vec::new();
    walk(std::path::Path::new(&base), "", &mut findings);
    findings.sort_by(|a, b| a.path.cmp(&b.path));

    let items: Vec<serde_json::Value> = findings
        .iter()
        .map(|f| serde_json::json!({ "path": f.path, "size": f.size }))
        .collect();
    serde_json::json!({ "findings": items })
}

/// Recurse into `dir`, accumulating a `/`-separated relative path in `prefix`.
/// Directory-read or stat errors yield no findings for that entry (the host
/// reference does the same, so an unreadable tree stays equivalent).
fn walk(dir: &std::path::Path, prefix: &str, out: &mut Vec<Finding>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        let rel = if prefix.is_empty() {
            name
        } else {
            format!("{prefix}/{name}")
        };
        let Ok(meta) = entry.metadata() else {
            continue;
        };
        if meta.is_dir() {
            walk(&entry.path(), &rel, out);
        } else if meta.is_file() {
            out.push(Finding {
                path: rel,
                size: meta.len(),
            });
        }
    }
}

/// Attempt to create a file under the read-only preopen. cap-std must refuse.
#[allow(clippy::suspicious_open_options)] // deliberate adversarial write attempt
fn attack_write_escape() -> Result<Vec<u8>, ToolError> {
    std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .open(format!("{READ_PREOPEN}/pwned.txt"))
        .map_err(|e| err("fs_write_denied", format!("write refused: {e}")))?;
    Err(err(
        "fs_write_succeeded",
        "write to read-only preopen must never succeed",
    ))
}

/// Call the Model B `http.get` host import with no net grant — host denies.
fn attack_http_probe() -> Result<Vec<u8>, ToolError> {
    match aegis::host::http::get("https://example.com/probe") {
        Ok(_) => Err(err("http_succeeded", "http must deny without a net grant")),
        Err(deny) => Err(err("http_denied", deny.reason)),
    }
}

export!(PathDetector);
