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
and `input_digest` go to stderr. Deny/trap paths still emit audit JSONL.

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

## Status

`aegis run` lands the AEG-30 research quickstart path. Full admin surface / config
files remain out of scope.

## Dependencies

- `botzr-aegis-runtime` for pipeline orchestration
- `botzr-aegis-capability` for `ToolManifest` registration
