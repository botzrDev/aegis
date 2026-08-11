# botzr-aegis-cli

CLI for Aegis. Installed binary name: `aegis`.

```
aegis 0.1.0 — research runtime for secure agent tool execution
Pipeline: policy → capability → sandbox → audit
```

## Usage

### Ready (library-style bootstrap)

```
aegis [--policy <yaml-path>] [--audit <jsonl-path>]
```

Wires `Runtime` with optional policy/audit, prints the audit path, and exits.
No tools are registered in this mode.

### `aegis run` — register + execute

```
aegis run --component <wasm> --id <tool-id> [OPTIONS]
```

Registers a `wasm32-wasip2` component and executes one call through
**POLICY → CAPABILITY → SANDBOX → AUDIT**. Tool output goes to stdout; progress
and `request_digest` go to stderr. Deny/trap paths still emit audit JSONL.

| Flag | Description |
|------|-------------|
| `--component`, `--wasm` | Path to the WASM component |
| `--id`, `--tool-id` | Tool id (policy / capability / audit) |
| `--input` | Call input bytes as text (default: empty) |
| `--input-file` | Read call input from a file |
| `--policy` | Policy YAML (default: allow-all) |
| `--audit` | Audit JSONL path (default: temp file) |
| `--base-dir` | Manifest base dir (default: component parent) |
| `--sha256` | Optional component digest pin (G10) |
| `--version` | Tool version recorded in the Manifest (default `0.1.0`) |

Example against the in-tree echo fixture:

```bash
cargo run -p botzr-aegis-cli -- \
  run \
  --component tests/fixtures/echo-tool/echo.wasm \
  --id echo \
  --input 'hello' \
  --audit /tmp/aegis-audit.jsonl
```

### `aegis verify` — read a record file, report a verdict

```
aegis verify [--key <HEX>]... [--trust-store <PATH>] <PATH>
```

Reads one Agent Action Record chain file and reports whether it verifies. The
walk itself lives in `botzr-aegis-audit`; this command is the surface over it.
No policy is loaded, no runtime is built, no tool is executed.

`<PATH>` is a positional argument and any path is accepted — the record file's
name and extension are not specified yet (AILAB-623), so examples here write
`session.<ext>`.

| Flag | Description |
|------|-------------|
| `--key <HEX>` | A public key you trust, 64 lowercase hex. Repeatable. |
| `--trust-store <PATH>` | File of the same, one key per line; blank lines and `#` comment lines are skipped |

`--key` takes the **public key** an `open` line publishes, not the `key_id`
fingerprint the report prints. The union of `--key` values and trust-store
entries is the trust slice; supply *neither* flag and the walk is unpinned.
Supplying either one is a pin, so a `--trust-store` that turns out to hold no
keys is a pin nothing can satisfy — exit 1, not a quiet `Verified (unpinned)`.
A store that got truncated or mis-mounted must not keep a gate green.

#### Exit codes

These are API — CI gates script them (ADR-0002).

| Exit | Meaning |
|------|---------|
| `0` | `Verified` |
| `1` | `Tampered` — or a usage error (bad flag, bad key hex, missing `<PATH>`) |
| `2` | Could not read the record file or the trust store |
| `3` | `Indeterminate` — a typed reason, printed |

#### Output

stdout is deterministic: the same bytes produce the same report on every run
and on every machine. No timestamps, no paths. The first line is the verdict;
then one `key_id` line per observed key, a `coverage` line, and — on exit 3 with
an unanchored tail — one `in_flight` line per Call that was in progress. Empty
sections are omitted. Read errors print `error: …` on stderr and leave stdout
empty.

```
$ aegis verify session.<ext>
Verified (unpinned)
key_id 77a2c2f5952039243c043b69e7e812a2deb69e3271adb3013b8f24d3b8ea40f6
coverage session 0 seq 3
```

```
$ aegis verify --key 3de537a06e04b2ffe1fb0558ea16d3c0f042ed99f7e392698aa5120f568d4e2c session.<ext>
Verified (pinned to 77a2c2f5952039243c043b69e7e812a2deb69e3271adb3013b8f24d3b8ea40f6)
key_id 77a2c2f5952039243c043b69e7e812a2deb69e3271adb3013b8f24d3b8ea40f6
coverage session 0 seq 3
```

#### What the two success labels claim

Per [ADR-0004](../../docs/adr/0004-embedded-key-with-labelled-trust.md), the
difference between them is the whole point, not a caveat:

- **`Verified (unpinned)`** — every signature in the file checks out against the
  key the file itself published. That is **internal consistency only**, and
  explicitly **not** a claim about provenance: an attacker who rewrites a whole
  Session signs it with their own key, publishes that key in the `open` line, and
  the walk comes out clean. Unpinned means *some* Aegis build wrote this file, and
  nothing in the file says whose.
- **`Verified (pinned to <fp>)`** — same walk, plus every `open` key in the file
  was one you supplied out of band. That is what turns the signature into a
  provenance claim, and the anchor comes from you, never from the record.

A file that rotates keys across Sessions prints `Verified (pinned)` with one
`key_id` line per fingerprint; rotation is legal, and *every* `open` key must be
in your store, not merely one of them. An `open` key that is not in a supplied
store is `Tampered`, never "unpinned".

## Status

`aegis run` lands the AEG-30 research quickstart path. `aegis verify` lands the
AILAB-621 evidence-reading path. Full admin surface / config files remain out of
scope, as do follow modes for a live record file (D3) and `aegis recheck`
(AILAB-622).

## Dependencies

- `botzr-aegis-runtime` for pipeline orchestration
- `botzr-aegis-capability` for `ToolManifest` registration
- `botzr-aegis-audit` for the chain walker behind `aegis verify`
