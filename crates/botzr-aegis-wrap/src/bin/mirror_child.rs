//! **Test fixture** — a deliberately dumb stdio JSON-RPC child.
//!
//! Not an Aegis catalog server, not an MCP implementation, and not a product
//! surface. Its only job is to make relay **observable**: every method it does
//! not otherwise care about is answered with
//! `{"result":{"mirrored":"<method>","frame_len":<n>}}`, which is the ironclad
//! unknown-method probe — a client that receives `mirrored` proves wrap relayed,
//! because a local `-32601` short-circuit could not have produced it.
//!
//! `frame_len` is the byte length of the frame **as this child received it**,
//! delimiter excluded. It is how a test proves that byte-level framing survived
//! the relay: a CRLF-framed request arrives one byte longer than the same
//! request framed with a bare `\n`.
//!
//! Test hooks, keyed off either the JSON-RPC `method` or `params.name` so the
//! same behaviour is reachable from a `tools/call`-shaped request:
//!
//! | trigger               | behaviour                                             |
//! |-----------------------|-------------------------------------------------------|
//! | `test/exit`           | `exit(3)` **without answering** — child death          |
//! | `test/error`          | a JSON-RPC `error` object — the tool erred             |
//! | `test/stderr`         | a distinctive line on stderr, then a normal answer     |
//! | `test/stderr-binary`  | invalid UTF-8 on stderr, then a marker, then an answer |
//! | `test/slow`           | sleeps ~200 ms, then answers — post-EOF work           |
//! | `test/hang`           | goes silent for 8 s and never answers — grace expiry    |
//! | `test/server-request` | a server→client **request** reusing the client's id, then the real answer |
//!
//! `tools/call` echoes `params.name` back as text content. Notifications (no
//! `id`, or a null one) get no response at all. A top-level array is answered
//! with an array of the responses its elements would have got.
//!
//! Framing is byte-oriented (`read_until` + `from_slice`) for the same reason
//! the relay's is: a `lines()` loop would treat one non-UTF-8 byte as the end of
//! the stream, and then a test could not tell a fixture that gave up from a
//! relay that truncated.

use std::io::{self, BufRead, Write};
use std::time::Duration;

use serde_json::{json, Value};

/// Long enough that repeated `test/slow` calls outlast wrap's 5 s shutdown
/// grace within a test's patience; short enough not to dominate the suite.
const SLOW: Duration = Duration::from_millis(200);

/// Longer than wrap's 5 s shutdown grace, with margin for a loaded runner. A
/// `test/hang` child is **alive and silent** across the whole grace, which is
/// the state wrap must never record as "the child exited".
const HANG: Duration = Duration::from_secs(8);

fn main() {
    let mut stdin = io::stdin().lock();
    let mut stdout = io::stdout();

    loop {
        let mut frame = Vec::new();
        match stdin.read_until(b'\n', &mut frame) {
            Ok(0) | Err(_) => break,
            Ok(_) => {}
        }
        if frame.last() == Some(&b'\n') {
            frame.pop();
        }
        let frame_len = frame.len();
        let Ok(message) = serde_json::from_slice::<Value>(&frame) else {
            continue;
        };

        let out = match &message {
            // A batch: one array frame in, one array frame out.
            Value::Array(items) => {
                let responses: Vec<Value> = items
                    .iter()
                    .flat_map(|item| {
                        apply_hooks(item);
                        frames_for(item, frame_len)
                    })
                    .collect();
                if responses.is_empty() {
                    Vec::new()
                } else {
                    vec![Value::Array(responses)]
                }
            }
            _ => {
                apply_hooks(&message);
                frames_for(&message, frame_len)
            }
        };

        for value in out {
            if writeln!(stdout, "{value}").is_err() || stdout.flush().is_err() {
                return;
            }
        }
    }
}

/// Does this message trigger `hook`, by method or by `params.name`?
fn triggered(message: &Value, hook: &str) -> bool {
    message.get("method").and_then(Value::as_str) == Some(hook)
        || message.pointer("/params/name").and_then(Value::as_str) == Some(hook)
}

/// Everything a hook does *before* any frame is written.
fn apply_hooks(message: &Value) {
    // Before the id check: dying without answering is the whole point.
    if triggered(message, "test/exit") {
        std::process::exit(3);
    }
    if triggered(message, "test/stderr") {
        eprintln!("mirror-child: distinctive stderr line");
        let _ = io::stderr().flush();
    }
    if triggered(message, "test/stderr-binary") {
        // A lone 0xff/0xfe is not valid UTF-8 anywhere. A tee that decodes
        // before it forwards dies here and swallows the marker that follows.
        let mut stderr = io::stderr();
        let _ = stderr.write_all(b"mirror-child: \xff\xfe binary stderr\n");
        let _ = stderr.write_all(b"mirror-child: stderr survived the invalid byte\n");
        let _ = stderr.flush();
    }
    if triggered(message, "test/slow") {
        std::thread::sleep(SLOW);
    }
    if triggered(message, "test/hang") {
        // Alive, silent, and not reading: stdin EOF cannot be noticed from in
        // here, so wrap's grace has to expire on its own.
        std::thread::sleep(HANG);
    }
}

/// The frames this child emits for one message, in order.
///
/// More than one is possible: `test/server-request` emits a server→client
/// *request* before the response, which is what a real MCP server does when it
/// asks the client for sampling or elicitation mid-call.
fn frames_for(message: &Value, frame_len: usize) -> Vec<Value> {
    let method = message.get("method").and_then(Value::as_str).unwrap_or("");
    let name = message
        .pointer("/params/name")
        .and_then(Value::as_str)
        .unwrap_or("");

    let Some(id) = message.get("id").filter(|id| !id.is_null()) else {
        return Vec::new();
    };
    if triggered(message, "test/hang") {
        // The point of the hook: the call is never answered at all.
        return Vec::new();
    }

    let mut frames = Vec::new();

    if triggered(message, "test/server-request") {
        // Deliberately the **client's own id**. Server-initiated requests are
        // numbered from the server's id space, which shares no namespace with
        // the client's, so a collision is ordinary rather than adversarial —
        // and an interposer that matches on `id` alone completes the wrong
        // call here.
        frames.push(json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "sampling/createMessage",
            "params": {}
        }));
    }

    frames.push(if triggered(message, "test/error") {
        json!({
            "jsonrpc": "2.0",
            "id": id,
            "error": { "code": -32000, "message": "mirror child tool error" }
        })
    } else if method == "tools/call" {
        json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": { "content": [{ "type": "text", "text": name }] }
        })
    } else {
        json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": { "mirrored": method, "frame_len": frame_len }
        })
    });

    frames
}
