# botzr-aegis-cli

CLI for Aegis. Installed binary name: `aegis`.

```
aegis 0.1.0 — research runtime for secure agent tool execution (scaffold)
Pipeline: policy → capability → sandbox → audit
```

## Usage

```
aegis [--policy <yaml-path>] [--audit <jsonl-path>]
```

| Flag | Description |
|------|-------------|
| `--policy` | Path to a policy YAML file (default: allow-all) |
| `--audit`  | Path for audit JSONL output (default: temp file) |

## Status

Scaffold — wires `Runtime::new()` with optional policy loading. Full CLI (tool registration, execution, config file) is coming in a later milestone.

## Dependencies

- `botzr-aegis-runtime` for pipeline orchestration
