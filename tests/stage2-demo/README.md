# aegis-stage2-demo — minimal wasip2 detector + equivalence scorecard

Stage 2 from the MASTER PRD (§8): a **minimal path-scan detector** that runs as
a real `wasip2` component through the full Aegis pipeline
(`POLICY → CAPABILITY → SANDBOX → AUDIT`, via `Runtime::execute_tool_call` —
Model A, never `execute_host_call`).

## Reproduce

```bash
./scripts/build-fixtures.sh          # (re)builds tests/fixtures/path-detector/path-detector.wasm
cargo test -p aegis-stage2-demo
```

## What it proves (scorecard)

| Test | Claim |
|---|---|
| `equivalence_native_matches_wasm` | Native reference findings **==** wasm findings on a shared fixture tree (D10) |
| `happy_path_audit_one_call_per_session` | A successful run emits three lines — `open` + `intent` + `outcome` — with `status: success` on the outcome |
| `write_escape_denied` | An out-of-grant `fs.write` under the read-only preopen traps — never a silent success |
| `http_probe_denied` | The Model B `http` import with no net grant denies — never a silent success |
| `wall_clock_cap_trips` | A tight epoch/wall-clock cap trips with an audit `ResourceExceeded{wall_clock}` |

## The detector

Same tiny scan logic, implemented **twice** from scratch:

- **Guest (`tests/fixtures/path-detector/`)** — the `wasip2` component. Reads only
  its WASI read-only preopen (`/ro0`); walks `/ro0/<scan_root>` (default
  `"fixtures"`) and returns `{"findings":[{"path","size"},...]}` sorted by path.
- **Native reference (`src/native.rs`)** — pure host Rust, no wasmtime, identical
  semantics against a host `Path`.

### D10 equivalence criterion

The bar is: *native reference build == wasm-under-Aegis on the same fixture
input.* It is **not** "identical to native uveddi". **uveddi is a functional spec
only** — the god-object/path-scan idea is borrowed, but uveddi code is never cloned
and never added as a dependency (uveddi is CC-BY-NC-SA; this crate is MIT). The detector is
deliberately minimal: it exists to prove equivalence and clean enforcement, not
to ship rule-engine parity.
