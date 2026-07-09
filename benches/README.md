# Aegis benchmarks (AEG-16 / OQ-15 T5)

Library-mode **hot path only**: policy evaluation and capability resolution.
Sandbox, audit, and wasmtime are intentionally **not** timed here.

## Run

From the repository root:

```bash
cargo bench -p botzr-aegis-policy -p botzr-aegis-capability -p botzr-aegis-runtime
```

| Package | Bench target | Groups |
|---|---|---|
| `botzr-aegis-policy` | `policy_eval` | `allow_all`, `multi_rule`, `rate_limit` (info) |
| `botzr-aegis-capability` | `resolve` | `registered_tool` |
| `botzr-aegis-runtime` | `hot_path` | `allow_all`, `multi_rule` |

## Latency targets

| Scope | Group | Target (median) |
|---|---|---|
| Policy eval alone | `policy_eval/allow_all`, `policy_eval/multi_rule` | **&lt; 100 µs** |
| Combined policy + capability | `hot_path/multi_rule` | **&lt; 1 ms** |
| Rate-limit path | `policy_eval/rate_limit` | informational only (mutex) |
| Capability alone | `capability_resolve/registered_tool` | no hard gate |

Do **not** conflate the two primary targets into a single threshold.

## Hardware citation

Capture on the machine that ran the benches, then paste into
[`results/hot_path.md`](results/hot_path.md):

```bash
uname -a
lscpu | head -20    # or: sysctl -n machdep.cpu.brand_string  on macOS
rustc -Vv | head -5
```

## Published results

Committed Criterion summary tables (text only — not `target/criterion/` HTML):

- [`results/hot_path.md`](results/hot_path.md)

## Non-goals

- Do not measure full-pipeline / `Runtime::execute_tool_call` latency
- Do not add CI performance gates (publication claim only)
- Do not commit Criterion HTML reports under `target/criterion/`
