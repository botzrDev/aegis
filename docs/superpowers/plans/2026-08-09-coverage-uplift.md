# Coverage Uplift Implementation Plan (87.3% → ≥92%)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Raise total workspace line coverage from 87.26% (3980/4561) to ≥92% by testing the measured gaps, then ratchet `coverage/baseline.json` up.

**Architecture:** Tests only — no production code changes. Five uncovered hot spots identified from `cargo llvm-cov` annotated output (2026-08-09 run): `botzr-aegis-mcp/src/main.rs` (0%, 83 lines), `botzr-aegis-cli/src/lib.rs` (67%, 91 missed), `botzr-aegis-policy/src/engine.rs` (76%, 37 missed), `botzr-aegis-core/src/error.rs` + `grant.rs` (21 missed combined), `botzr-aegis-mcp/src/mcp.rs`/`bridge.rs` (~40 missed). Binary entrypoints are covered by spawning the instrumented binary from integration tests (`CARGO_BIN_EXE_*` — cargo-llvm-cov collects child-process profiles; `run_echo.rs` proves this works in this repo).

**Tech Stack:** Rust 1.86, `cargo test`, `cargo-llvm-cov 0.6.21`, `tempfile` (already a dev-dependency of every crate that needs it).

## Global Constraints

- `unsafe_code = forbid` workspace-wide; MSRV 1.86.
- Gates before handoff: `cargo fmt --all`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace`.
- **Commit gate:** do NOT run `git add` / `git commit` / `git push`. At each "Commit" step, show the diff and a proposed message; Austin runs the commit.
- No new dependencies. No production API added just to make code testable (repo anti-pattern).
- Keep `assert!` failure-message strings on one line where practical — multi-line failure formats count as uncovered lines in llvm-cov and erode the gain.
- Expected math: ~+250 covered lines → (3980+250)/4561 ≈ 92.7%. Task-level estimates below; if the final number lands ≥92%, the plan succeeded.

---

### Task 1: Core quick wins — `AegisError` Display + `CapabilityGrant::deny_all`

~21 missed lines. Pure unit tests, no I/O.

**Files:**
- Modify: `crates/botzr-aegis-core/src/error.rs` (append `#[cfg(test)]` mod; file currently has none, ends at line 55)
- Modify: `crates/botzr-aegis-core/src/grant.rs` (append `#[cfg(test)]` mod; file currently ends at line 55)

**Interfaces:**
- Consumes: `AegisError` (8 variants, `Display` at `error.rs:34-52`), `CapabilityGrant::deny_all(tool_id: ToolId, grant_id: impl Into<String>) -> Self` (`grant.rs:44`), `ToolId::new` from `crate::tool`.
- Produces: nothing used by later tasks.

- [ ] **Step 1: Append tests to `error.rs`**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_covers_every_variant() {
        let cases = [
            (AegisError::PolicyDenied { reason: "r".into() }, "policy denied: r"),
            (AegisError::RateLimited { reason: "r".into() }, "rate limited: r"),
            (AegisError::PendingApproval { approval_id: "apr-1".into() }, "pending approval: apr-1"),
            (
                AegisError::CapabilityDenied { reason: "r".into(), denied_capability: Some("fs".into()) },
                "capability denied: r",
            ),
            (AegisError::Trap { message: "m".into() }, "trap: m"),
            (AegisError::ResourceExceeded { kind: "memory".into() }, "resource exceeded: memory"),
            (AegisError::HostDenied { reason: "r".into() }, "host denied: r"),
            (AegisError::Audit { message: "m".into() }, "audit error: m"),
        ];
        for (err, expected) in cases {
            assert_eq!(err.to_string(), expected);
        }
    }
}
```

- [ ] **Step 2: Append tests to `grant.rs`**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deny_all_grants_nothing() {
        let g = CapabilityGrant::deny_all(ToolId::new("t"), "grant-0");
        assert_eq!(g.grant_id, "grant-0");
        assert_eq!(g.tool_id, ToolId::new("t"));
        assert!(g.fs.is_none());
        assert!(g.net.is_none());
        assert_eq!(g.max_memory_bytes, 0);
        assert_eq!(g.max_wall_ms, 0);
        assert_eq!(g.max_output_bytes, 0);
    }
}
```

- [ ] **Step 3: Run and verify pass**

Run: `cargo test -p botzr-aegis-core`
Expected: all pass, including `display_covers_every_variant` and `deny_all_grants_nothing`. If a Display string mismatches, fix the *test* to match the code (the wire text is shipped behavior — do not change production strings).

- [ ] **Step 4: Commit gate**

Show `git diff crates/botzr-aegis-core` and propose message `test(core): cover AegisError Display and CapabilityGrant::deny_all`. Austin commits.

---

### Task 2: `PolicyEngine` file I/O paths — `load`, `reload_from_file`, `Default`, `Debug`

~37 missed lines in `crates/botzr-aegis-policy/src/engine.rs` (lines 72-81, 212-222, 226-228, 232-237).

**Files:**
- Modify: `crates/botzr-aegis-policy/src/engine.rs` (append `#[cfg(test)]` mod at end; note `snapshot()` at line 88 is already `#[cfg(test)]`)

**Interfaces:**
- Consumes: `PolicyEngine::{load, allow_all, active_digest, reload_from_file, default}`, `ReloadOutcome { old_digest, new_digest, source }`, `ReloadSource::File`, `PolicyError::Io { path, reason }` (from `crate::error`), `tempfile` (already a dev-dependency).
- Produces: nothing used by later tasks.

- [ ] **Step 1: Append tests to `engine.rs`**

Use a policy document in the shape the repo already uses (`crates/botzr-aegis-cli/tests/run_echo.rs:12-22`) — one deny rule — rather than guessing whether `rules: []` parses.

```rust
#[cfg(test)]
mod tests {
    use super::*;

    const ALLOW_WITH_RULE: &str = r#"
version: 1
default: allow
rules:
  - id: deny-echo
    action: deny
    tool: echo
    reason: "engine test"
"#;

    const DENY_DEFAULT: &str = r#"
version: 1
default: deny
rules:
  - id: deny-echo
    action: deny
    tool: echo
    reason: "engine test"
"#;

    fn write_policy(yaml: &str) -> tempfile::NamedTempFile {
        let f = tempfile::NamedTempFile::new().expect("temp policy");
        std::fs::write(f.path(), yaml).expect("write policy");
        f
    }

    #[test]
    fn load_reads_file_and_remembers_source_path() {
        let f = write_policy(ALLOW_WITH_RULE);
        let engine = PolicyEngine::load(f.path()).expect("load");
        assert_eq!(engine.source_path.as_deref(), Some(f.path()));
    }

    #[test]
    fn load_missing_file_is_io_error() {
        let err = PolicyEngine::load("/nonexistent/aegis-engine-test.yaml").unwrap_err();
        assert!(matches!(err, PolicyError::Io { .. }));
    }

    #[test]
    fn reload_from_file_swaps_active_digest() {
        let f = write_policy(ALLOW_WITH_RULE);
        let engine = PolicyEngine::load(f.path()).expect("load");
        let old = engine.active_digest();
        std::fs::write(f.path(), DENY_DEFAULT).expect("rewrite policy");
        let outcome = engine.reload_from_file().expect("reload");
        assert_eq!(outcome.old_digest, old);
        assert_ne!(outcome.new_digest, old);
        assert_eq!(outcome.source, ReloadSource::File);
        assert_eq!(engine.active_digest(), outcome.new_digest);
    }

    #[test]
    fn reload_without_source_path_is_io_error() {
        let engine = PolicyEngine::allow_all();
        let err = engine.reload_from_file().unwrap_err();
        assert!(matches!(err, PolicyError::Io { .. }));
    }

    #[test]
    fn default_is_allow_all_and_debug_prints_digest() {
        let engine = PolicyEngine::default();
        let dbg = format!("{engine:?}");
        assert!(dbg.contains("PolicyEngine"), "debug output: {dbg}");
        assert!(dbg.contains("active_digest"), "debug output: {dbg}");
    }
}
```

- [ ] **Step 2: Run and verify pass**

Run: `cargo test -p botzr-aegis-policy engine`
Expected: 5 new tests pass. If `PolicyError::Io` is not the variant name, check `crates/botzr-aegis-policy/src/error.rs` and match the real variant — do not change production error types.

- [ ] **Step 3: Commit gate**

Show `git diff crates/botzr-aegis-policy` and propose `test(policy): cover PolicyEngine file load/reload and Default/Debug`. Austin commits.

---

### Task 3: CLI parse branches, `usage_text`, `dispatch`, and binary error path

~97 missed lines: `crates/botzr-aegis-cli/src/lib.rs` (flag branches at 125-146, `usage_text` 168-189, `dispatch` Ready/Help arms 283-302, error arms 309-317) plus `crates/botzr-aegis-cli/src/main.rs` (error path, lines 10-15).

**Files:**
- Modify: `crates/botzr-aegis-cli/src/lib.rs` (extend existing `#[cfg(test)] mod tests`, lines 323-366)
- Modify: `crates/botzr-aegis-cli/tests/run_echo.rs` (add binary-level cases)

**Interfaces:**
- Consumes: `parse_args(&[String]) -> Result<Command, String>`, `Command::{Ready, Run, Help}`, `RunArgs` (fields at `lib.rs:23-33`), `usage_text() -> String`, `dispatch(Command) -> ExitCode`, echo fixture at `tests/fixtures/echo-tool/echo.wasm`, `env!("CARGO_BIN_EXE_aegis")`.
- Produces: nothing used by later tasks.
- Gotcha: `std::process::ExitCode` implements `Debug` but not `PartialEq` — compare with `format!("{code:?}")`.

- [ ] **Step 1: Extend the unit test mod in `lib.rs`**

Add inside the existing `mod tests`:

```rust
    fn sv(args: &[&str]) -> Vec<String> {
        args.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn parse_run_all_optional_flags() {
        let args = sv(&[
            "aegis", "run", "--wasm", "e.wasm", "--tool-id", "echo",
            "--input-file", "in.txt", "--base-dir", "/tmp/base",
            "--sha256", "abc123", "--version", "9.9.9",
            "--policy", "p.yaml", "--audit", "a.jsonl",
        ]);
        match parse_args(&args).unwrap() {
            Command::Run(r) => {
                assert_eq!(r.component, PathBuf::from("e.wasm"));
                assert_eq!(r.id, "echo");
                assert_eq!(r.input, None);
                assert_eq!(r.input_file, Some(PathBuf::from("in.txt")));
                assert_eq!(r.base_dir, Some(PathBuf::from("/tmp/base")));
                assert_eq!(r.sha256.as_deref(), Some("abc123"));
                assert_eq!(r.version, "9.9.9");
                assert_eq!(r.policy, Some(PathBuf::from("p.yaml")));
                assert_eq!(r.audit, Some(PathBuf::from("a.jsonl")));
            }
            other => panic!("expected Run, got {other:?}"),
        }
    }

    #[test]
    fn parse_errors_and_help_paths() {
        // top-level help forms
        for args in [sv(&["aegis", "--help"]), sv(&["aegis", "-h"]), sv(&["aegis", "help"])] {
            assert_eq!(parse_args(&args).unwrap(), Command::Help);
        }
        // run --help
        assert_eq!(parse_args(&sv(&["aegis", "run", "--help"])).unwrap(), Command::Help);
        // no args → ready with defaults
        assert_eq!(
            parse_args(&sv(&["aegis"])).unwrap(),
            Command::Ready { policy: None, audit: None }
        );
        // unknown command / unknown flags / missing values
        assert!(parse_args(&sv(&["aegis", "frobnicate"])).unwrap_err().contains("unknown command"));
        assert!(parse_args(&sv(&["aegis", "--bogus"])).unwrap_err().contains("unknown flag"));
        assert!(parse_args(&sv(&["aegis", "run", "--bogus"])).unwrap_err().contains("unknown flag"));
        assert!(parse_args(&sv(&["aegis", "--policy"])).unwrap_err().contains("needs a value"));
        assert!(parse_args(&sv(&["aegis", "run", "--input-file"])).unwrap_err().contains("needs a value"));
        // exclusive inputs
        let err = parse_args(&sv(&[
            "aegis", "run", "--component", "e.wasm", "--id", "e",
            "--input", "x", "--input-file", "f",
        ]))
        .unwrap_err();
        assert!(err.contains("only one of"));
        // missing required flags
        assert!(parse_args(&sv(&["aegis", "run", "--id", "e"])).unwrap_err().contains("--component"));
        assert!(parse_args(&sv(&["aegis", "run", "--component", "e.wasm"])).unwrap_err().contains("--id"));
    }

    #[test]
    fn usage_text_names_every_flag() {
        let usage = usage_text();
        for flag in ["--component", "--id", "--input", "--input-file", "--policy", "--audit", "--base-dir", "--sha256", "--version"] {
            assert!(usage.contains(flag), "usage missing {flag}");
        }
    }

    #[test]
    fn dispatch_help_and_ready_paths() {
        let success = format!("{:?}", ExitCode::SUCCESS);
        assert_eq!(format!("{:?}", dispatch(Command::Help)), success);
        // Default runtime: allow-all policy, temp audit — builds cleanly.
        assert_eq!(
            format!("{:?}", dispatch(Command::Ready { policy: None, audit: None })),
            success
        );
        // Bad policy path → error arm.
        let failure = format!("{:?}", ExitCode::from(1));
        assert_eq!(
            format!(
                "{:?}",
                dispatch(Command::Ready {
                    policy: Some(PathBuf::from("/nonexistent/policy.yaml")),
                    audit: None,
                })
            ),
            failure
        );
    }
```

- [ ] **Step 2: Run unit tests**

Run: `cargo test -p botzr-aegis-cli --lib`
Expected: all pass. If an error-message substring assert fails, align the assert with the real string from `lib.rs` (they are all defined in this file).

- [ ] **Step 3: Add binary-level cases to `tests/run_echo.rs`**

These cover `main.rs:10-15` (error print + usage) and `execute_run`'s `--input-file` path:

```rust
#[test]
fn aegis_unknown_command_prints_usage_and_fails() {
    let output = Command::new(env!("CARGO_BIN_EXE_aegis"))
        .args(["frobnicate"])
        .output()
        .expect("spawn aegis");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("unknown command"), "stderr: {stderr}");
    assert!(stderr.contains("Usage:"), "stderr: {stderr}");
}

#[test]
fn aegis_run_reads_input_file() {
    let audit = NamedTempFile::new().expect("temp audit");
    let input = NamedTempFile::new().expect("temp input");
    std::fs::write(input.path(), b"from-file").expect("write input");

    let output = Command::new(env!("CARGO_BIN_EXE_aegis"))
        .args([
            "run",
            "--component",
            echo_wasm().to_str().unwrap(),
            "--id",
            "echo",
            "--input-file",
            input.path().to_str().unwrap(),
            "--audit",
            audit.path().to_str().unwrap(),
        ])
        .output()
        .expect("spawn aegis");

    assert!(output.status.success(), "stderr={}", String::from_utf8_lossy(&output.stderr));
    assert_eq!(output.stdout, b"from-file");
}

#[test]
fn aegis_run_missing_component_fails() {
    let output = Command::new(env!("CARGO_BIN_EXE_aegis"))
        .args(["run", "--component", "/nonexistent/tool.wasm", "--id", "ghost"])
        .output()
        .expect("spawn aegis");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("read component"), "stderr: {stderr}");
}
```

- [ ] **Step 4: Run integration tests**

Run: `cargo test -p botzr-aegis-cli --test run_echo`
Expected: 5 tests pass (2 existing + 3 new).

- [ ] **Step 5: Commit gate**

Show `git diff crates/botzr-aegis-cli` and propose `test(cli): cover parse branches, usage, dispatch, and binary error paths`. Austin commits.

---

### Task 4: MCP stdio gateway binary — end-to-end over stdin/stdout

`crates/botzr-aegis-mcp/src/main.rs` is 0% (83 lines). Cover it by driving the instrumented binary over stdio, exactly like `scripts/mcp-stdio-smoke.sh` does manually. Child-process coverage is collected by cargo-llvm-cov (proven by `run_echo.rs` → `dispatch` coverage).

**Files:**
- Create: `crates/botzr-aegis-mcp/tests/stdio_gateway.rs`

**Interfaces:**
- Consumes: `env!("CARGO_BIN_EXE_botzr-aegis-mcp")` (bin name declared at `Cargo.toml:37`), MCP subset from `src/mcp.rs` (`initialize`, `ping`, `tools/list`, `tools/call`; catalog `echo` allowed, `exfil` policy-denied by default), `tempfile` (already a dev-dependency).
- Produces: nothing used by later tasks.
- Gotchas: responses are newline-delimited JSON on stdout; banner/logs go to stderr. Notifications (no `id`) get no response — do not read a line after sending one. Close stdin to end the session loop; the binary then exits 0.

- [ ] **Step 1: Write the E2E test**

```rust
//! E2E: drive the botzr-aegis-mcp binary over stdio (covers src/main.rs).

use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};

use tempfile::NamedTempFile;

fn spawn_gateway(extra_args: &[&str]) -> std::process::Child {
    Command::new(env!("CARGO_BIN_EXE_botzr-aegis-mcp"))
        .args(extra_args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn botzr-aegis-mcp")
}

#[test]
fn stdio_session_initialize_list_call_and_deny() {
    let audit = NamedTempFile::new().expect("temp audit");
    let mut child = spawn_gateway(&["--audit", audit.path().to_str().unwrap()]);
    let mut stdin = child.stdin.take().expect("stdin");
    let stdout = child.stdout.take().expect("stdout");
    let mut lines = BufReader::new(stdout).lines();

    let mut send_and_recv = |req: &str| -> String {
        writeln!(stdin, "{req}").expect("write request");
        lines.next().expect("response line").expect("read response")
    };

    let init = send_and_recv(r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#);
    assert!(init.contains("protocolVersion"), "init: {init}");

    let list = send_and_recv(r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#);
    assert!(list.contains("echo") && list.contains("exfil"), "list: {list}");

    // Notification (no id): acknowledged by silence — send, do not read.
    writeln!(stdin, r#"{{"jsonrpc":"2.0","method":"notifications/initialized"}}"#).unwrap();

    let echoed = send_and_recv(
        r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"echo","arguments":{"text":"hi-e2e"}}}"#,
    );
    assert!(echoed.contains("hi-e2e"), "echo: {echoed}");

    let denied = send_and_recv(
        r#"{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"exfil","arguments":{"text":"secrets"}}}"#,
    );
    assert!(denied.contains("isError"), "deny: {denied}");

    let parse_err = send_and_recv("this is not json");
    assert!(parse_err.contains("-32700"), "parse error: {parse_err}");

    drop(stdin); // EOF ends the session loop
    let status = child.wait().expect("wait");
    assert!(status.success(), "gateway exit: {status:?}");

    let jsonl = std::fs::read_to_string(audit.path()).expect("audit readable");
    assert!(jsonl.contains("\"phase\":\"outcome\""), "audit: {jsonl}");
}

#[test]
fn help_flag_exits_zero_with_usage() {
    let out = Command::new(env!("CARGO_BIN_EXE_botzr-aegis-mcp"))
        .arg("--help")
        .output()
        .expect("spawn");
    assert!(out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("Usage: botzr-aegis-mcp"), "stderr: {stderr}");
}

#[test]
fn bad_flags_exit_nonzero() {
    for args in [&["--bogus"][..], &["--policy"][..], &["--audit"][..]] {
        let out = Command::new(env!("CARGO_BIN_EXE_botzr-aegis-mcp"))
            .args(args)
            .output()
            .expect("spawn");
        assert!(!out.status.success(), "expected failure for {args:?}");
    }
}

#[test]
fn unreadable_policy_exits_nonzero() {
    let out = Command::new(env!("CARGO_BIN_EXE_botzr-aegis-mcp"))
        .args(["--policy", "/nonexistent/policy.yaml"])
        .output()
        .expect("spawn");
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("error:"), "stderr: {stderr}");
}
```

- [ ] **Step 2: Run it**

Run: `cargo test -p botzr-aegis-mcp --test stdio_gateway`
Expected: 4 tests pass. If the echo/deny assertions fail, print the raw response and align with the actual `tools/call` result shape in `src/mcp.rs:120-160` — adjust the test, not the gateway.

- [ ] **Step 3: Commit gate**

Show `git diff crates/botzr-aegis-mcp/tests` and propose `test(mcp): e2e stdio session covering the gateway binary`. Austin commits.

---

### Task 5: MCP unit gaps — `handle_line` edges and `call_tool` unknown-tool

~30 remaining missed lines in `crates/botzr-aegis-mcp/src/mcp.rs` (parse-error response 26-34, notification silence 41, method-not-found 52, error envelope 57-62, unknown tool 120-123) and `bridge.rs` (unknown tool 87-89, `policy_file` arm 51). The `error_code` arms for RateLimited/Trap/etc. (`mcp.rs:153-159`) are unreachable without inducing those runtime errors — leave them; they are 7 lines.

**Files:**
- Modify: `crates/botzr-aegis-mcp/src/mcp.rs` (extend existing `#[cfg(test)] mod` at bottom)
- Modify: `crates/botzr-aegis-mcp/src/bridge.rs` (extend existing `#[cfg(test)] mod` at bottom)

**Interfaces:**
- Consumes: `handle_line(rt: &Runtime, line: &str) -> Option<String>`, `build_runtime(policy_path: Option<&Path>, audit_path: Option<&Path>) -> Result<Runtime, String>`, `call_tool(rt: &Runtime, tool_id: &str, text: &str) -> Result<Vec<u8>, AegisError>`, `DEFAULT_DENY_EXFIL_POLICY` const. Existing tests in these files already construct a runtime — reuse their helper if one exists; otherwise `build_runtime(None, Some(tempfile path))`.
- Produces: nothing used by later tasks.

- [ ] **Step 1: Add `handle_line` edge tests to `mcp.rs` tests mod**

```rust
    #[test]
    fn handle_line_edges() {
        let audit = tempfile::NamedTempFile::new().expect("temp audit");
        let rt = crate::bridge::build_runtime(None, Some(audit.path())).expect("runtime");

        // Empty input and notifications (no id / null id): silence.
        assert_eq!(handle_line(&rt, ""), None);
        assert_eq!(handle_line(&rt, "   "), None);
        assert_eq!(handle_line(&rt, r#"{"jsonrpc":"2.0","method":"x"}"#), None);
        assert_eq!(handle_line(&rt, r#"{"jsonrpc":"2.0","id":null,"method":"x"}"#), None);

        // Parse error → -32700 with null id.
        let parse = handle_line(&rt, "{not json").expect("parse error response");
        assert!(parse.contains("-32700"), "parse: {parse}");

        // Unknown method → -32601.
        let nf = handle_line(&rt, r#"{"jsonrpc":"2.0","id":7,"method":"nope"}"#).expect("resp");
        assert!(nf.contains("-32601"), "not found: {nf}");

        // Ping → empty result object.
        let pong = handle_line(&rt, r#"{"jsonrpc":"2.0","id":8,"method":"ping"}"#).expect("resp");
        assert!(pong.contains("\"result\""), "ping: {pong}");

        // tools/call with unknown tool name → isError content, not a JSON-RPC error.
        let unk = handle_line(
            &rt,
            r#"{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"ghost","arguments":{"text":"x"}}}"#,
        )
        .expect("resp");
        assert!(unk.contains("unknown tool") && unk.contains("isError"), "unknown: {unk}");
    }
```

- [ ] **Step 2: Add `bridge.rs` tests**

```rust
    #[test]
    fn call_tool_rejects_non_catalog_ids() {
        let audit = tempfile::NamedTempFile::new().expect("temp audit");
        let rt = build_runtime(None, Some(audit.path())).expect("runtime");
        let err = call_tool(&rt, "ghost", "x").unwrap_err();
        assert!(matches!(err, AegisError::HostDenied { .. }), "got: {err:?}");
    }

    #[test]
    fn build_runtime_accepts_policy_file() {
        let policy = tempfile::NamedTempFile::new().expect("temp policy");
        std::fs::write(policy.path(), DEFAULT_DENY_EXFIL_POLICY).expect("write policy");
        let audit = tempfile::NamedTempFile::new().expect("temp audit");
        let rt = build_runtime(Some(policy.path()), Some(audit.path())).expect("runtime");
        // Same deny policy as the default: exfil still refused at the policy station.
        let err = call_tool(&rt, EXFIL_TOOL_ID, "secrets").unwrap_err();
        assert!(matches!(err, AegisError::PolicyDenied { .. }), "got: {err:?}");
    }
```

- [ ] **Step 3: Run and verify pass**

Run: `cargo test -p botzr-aegis-mcp --lib`
Expected: all pass. If existing tests in these mods already define a runtime helper with a different name, reuse it instead of duplicating.

- [ ] **Step 4: Commit gate**

Show `git diff crates/botzr-aegis-mcp/src` and propose `test(mcp): cover handle_line edges and bridge catalog/policy paths`. Austin commits.

---

### Task 6: Full gates, measure, and ratchet the baseline

**Files:**
- Modify: `coverage/baseline.json` (via `scripts/coverage.sh bump` only — never hand-edit upward)

**Interfaces:**
- Consumes: `scripts/coverage.sh` (`report`/`check`/`bump`), baseline at 87.2616%.
- Produces: the new committed high-water mark that CI's `coverage` job enforces.

- [ ] **Step 1: Run the standard gates**

Run: `cargo fmt --all && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace`
Expected: clean. Fix any clippy lint introduced by the new tests (common: `useless_vec`, `needless_borrow`).

- [ ] **Step 2: Measure and bump**

Run: `./scripts/coverage.sh bump`
Expected: `total line coverage: ≥92%` and `baseline written to coverage/baseline.json`. (~10 min cold, ~2 min warm.) If the total lands between 90% and 92%, check the per-file table for which task under-delivered and add the missing cases before bumping; if ≥92%, done.

- [ ] **Step 3: Verify the gate passes against the new baseline**

Run: `./scripts/coverage.sh check`
Expected: `OK: coverage is at or above the committed baseline` (this re-runs tests; warm cache makes it fast).

- [ ] **Step 4: Commit gate**

Show `git diff coverage/baseline.json` and propose `chore(coverage): ratchet baseline after test uplift`. Austin commits.

---

## Self-Review Notes

- **Spec coverage:** every measured hot spot has a task; `error_code` arms in `mcp.rs` and stdin/stdout I/O-failure arms in both `main.rs` files are documented as intentionally unreached (not fabricatable without harness tricks the repo's anti-patterns forbid).
- **Type consistency:** `ExitCode` comparison via `Debug` formatting (no `PartialEq`); `handle_line(&Runtime, &str) -> Option<String>`; `build_runtime(Option<&Path>, Option<&Path>)` in both `cli` and `mcp` — signatures copied from source on 2026-08-09.
- **Estimates:** Task 1 ~21, Task 2 ~37, Task 3 ~95, Task 4 ~75, Task 5 ~35 → ~263 lines ≈ 93.1% ceiling; ≥92% has slack for the unreachable arms.
