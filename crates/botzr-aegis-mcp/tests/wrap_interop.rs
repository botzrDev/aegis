//! Interop AC (AILAB-625 §1.8 / §5.5): `aegis wrap` in front of a **real**,
//! unmodified stdio MCP server.
//!
//! The wrap crate's own `tests/relay.rs` drives a deliberately dumb mirror
//! child, which proves the relay's mechanics but says nothing about whether a
//! genuine MCP session survives the interposition. This test closes that gap
//! with the gateway that already ships in this repo: from wrap's point of view
//! `botzr-aegis-mcp` is just another third-party stdio server, spawned as a real
//! process with its own arguments and its own record file.
//!
//! It lives in *this* package because `CARGO_BIN_EXE_botzr-aegis-mcp` only
//! resolves for tests of the package that declares the bin. Nothing about the
//! gateway is changed or configured for wrap's benefit — that is the point.

use std::io::{Cursor, Write};
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use botzr_aegis_audit::{generate_signing_key, verify_chain_file, Verdict};
use botzr_aegis_wrap::{run_wrap_with_streams, WrapConfig, WrapStreams};
use serde_json::Value;
use tempfile::TempDir;

/// A relay that has not returned by now is a hang, and a hang is a failure —
/// never a stalled CI job. Generous against a loaded runner: wrap's own exit
/// path is bounded at 5 s of event loop plus 5 s of reap.
const HANG_GUARD: Duration = Duration::from_secs(30);

/// An in-memory `Write` sink the test reads back after the relay returns.
///
/// Cloneable so one handle can go into `WrapStreams`, which takes ownership,
/// while the test keeps another.
#[derive(Clone, Default)]
struct Sink(Arc<Mutex<Vec<u8>>>);

impl Sink {
    fn lines(&self) -> Vec<String> {
        String::from_utf8_lossy(&self.0.lock().unwrap_or_else(|e| e.into_inner()))
            .lines()
            .filter(|line| !line.trim().is_empty())
            .map(str::to_owned)
            .collect()
    }
}

impl Write for Sink {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// A record file plus the key that signs it. Neither the gateway nor wrap has a
/// dev-key fallback (AILAB-620), so both ends need one minted first.
fn sink_and_key(dir: &TempDir, name: &str) -> (PathBuf, PathBuf) {
    let audit = dir.path().join(format!("{name}-audit.jsonl"));
    let key = dir.path().join(format!("{name}-signing.key"));
    generate_signing_key(&key, false).expect("generate signing key");
    (audit, key)
}

fn arg(path: &Path) -> String {
    path.to_str().expect("utf-8 temp path").to_owned()
}

#[test]
fn wrap_relays_a_real_catalog_gateway_and_records_only_the_tools_call() {
    let dir = tempfile::tempdir().expect("temp dir");
    // Two independent Sessions: the gateway keeps the record of the call it
    // executed, wrap keeps the record of the call it carried. Pointing them at
    // one file would interleave two chains and neither would verify.
    let (wrap_audit, wrap_key) = sink_and_key(&dir, "wrap");
    let (gateway_audit, gateway_key) = sink_and_key(&dir, "gateway");

    let config = WrapConfig {
        child_argv: vec![
            env!("CARGO_BIN_EXE_botzr-aegis-mcp").to_owned(),
            "--audit".to_owned(),
            arg(&gateway_audit),
            "--signing-key".to_owned(),
            arg(&gateway_key),
        ],
        audit_path: wrap_audit.clone(),
        signing_key_path: wrap_key,
    };

    let script = [
        r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#,
        r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#,
        r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"echo","arguments":{"text":"hi-interop"}}}"#,
    ];
    let mut input = String::new();
    for line in script {
        input.push_str(line);
        input.push('\n');
    }

    let client_out = Sink::default();
    let child_err = Sink::default();
    let streams = WrapStreams {
        client_in: Box::new(Cursor::new(input.into_bytes())),
        client_out: Box::new(client_out.clone()),
        child_err: Box::new(child_err.clone()),
    };

    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(run_wrap_with_streams(&config, streams));
    });
    let result = rx
        .recv_timeout(HANG_GUARD)
        .expect("run_wrap_with_streams must return; a hang is the failure this guard catches");
    let code = result.expect("wrap ran the gateway");
    assert_eq!(code, 0, "the gateway exits 0 on client EOF");

    // The client saw the real catalog, not something wrap synthesized.
    let out = client_out.lines();
    assert_eq!(out.len(), 3, "one response per request: {out:?}");
    assert!(out[0].contains("protocolVersion"), "initialize: {out:?}");
    assert!(
        out[1].contains("echo") && out[1].contains("exfil"),
        "the child's own tool catalog must reach the client: {out:?}"
    );
    let called: Value = serde_json::from_str(&out[2]).expect("tools/call response JSON");
    assert!(out[2].contains("hi-interop"), "echo result: {out:?}");
    assert_eq!(
        called["result"]["isError"],
        serde_json::json!(false),
        "the gateway allowed its own call: {out:?}"
    );

    // Wrap's record: `initialize` and `tools/list` are relayed with zero
    // interception, so exactly one call is recorded.
    let jsonl = std::fs::read_to_string(&wrap_audit).expect("wrap audit readable");
    let rows: Vec<Value> = jsonl
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).expect("every audit row is JSON"))
        .collect();
    let line_types: Vec<&str> = rows
        .iter()
        .map(|row| row["line_type"].as_str().expect("line_type"))
        .collect();
    assert_eq!(
        line_types,
        vec!["open", "intent", "outcome", "close"],
        "{jsonl}"
    );
    let outcome = rows
        .iter()
        .find(|row| row["line_type"] == "outcome")
        .expect("an outcome row");
    assert_eq!(outcome["schema_version"], 2, "{outcome}");
    assert_eq!(outcome["tool_id"], "echo", "{outcome}");
    assert_eq!(outcome["execution"]["status"], "success", "{outcome}");

    // `Verified` needs a signed `close` as the last line, which only lands when
    // the `AuditWriter` drops — so this also asserts wrap shut down cleanly
    // rather than merely stopping.
    let verification = verify_chain_file(&wrap_audit).expect("wrap audit readable");
    assert_eq!(
        verification.verdict,
        Verdict::Verified,
        "{:?}",
        verification.verdict
    );

    // And the gateway really ran its own pipeline behind wrap: a second,
    // independent chain with its own outcome. A stub child could not produce
    // one, and wrap did not write it.
    let gateway_jsonl = std::fs::read_to_string(&gateway_audit).expect("gateway audit readable");
    assert!(
        gateway_jsonl.contains("\"line_type\":\"outcome\""),
        "the child kept its own record: {gateway_jsonl}"
    );
    assert_eq!(
        verify_chain_file(&gateway_audit)
            .expect("gateway audit readable")
            .verdict,
        Verdict::Verified,
        "wrap must not disturb the child's own chain"
    );
}
