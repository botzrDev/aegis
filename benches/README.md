# Aegis benchmarks (AEG-16 / OQ-15 T5 · AEG-005 / AILAB-683)

Two independent scopes, published to two separate results files:

- **Library-mode hot path** — policy evaluation and capability resolution.
  Sandbox, audit, and wasmtime are intentionally **not** timed in the
  `hot_path` bench, and that non-goal still stands.
- **Cell + audit** — wasmtime warm/cold instantiation and audit record
  emission, added by AILAB-683 in their own bench targets.

## Run

From the repository root:

```bash
cargo bench -p botzr-aegis-policy -p botzr-aegis-capability -p botzr-aegis-runtime
cargo bench -p botzr-aegis-sandbox -p botzr-aegis-audit
```

| Package | Bench target | Groups |
|---|---|---|
| `botzr-aegis-policy` | `policy_eval` | `allow_all`, `multi_rule`, `rate_limit` (info) |
| `botzr-aegis-capability` | `resolve` | `registered_tool` |
| `botzr-aegis-runtime` | `hot_path` | `allow_all`, `multi_rule` |
| `botzr-aegis-sandbox` | `instantiation` | `warm`, `cold`, `cold_engine_only` (info), `cold_compile_only` (info) |
| `botzr-aegis-audit` | `emission` | `begin_complete`, `serialize_only` (info) |

## Latency targets

| Scope | Group | Target (median) |
|---|---|---|
| Policy eval alone | `policy_eval/allow_all`, `policy_eval/multi_rule` | **&lt; 100 µs** |
| Combined policy + capability | `hot_path/multi_rule` | **&lt; 1 ms** |
| Warm cell instantiation | `instantiation/warm` | **&lt; 0.5 ms** |
| Cold instantiation | `instantiation/cold` | **&lt; 5 ms** — *missed; target under review, see below* |
| Rate-limit path | `policy_eval/rate_limit` | informational only (mutex) |
| Capability alone | `capability_resolve/registered_tool` | no hard gate |
| Attribution splits | `instantiation/cold_engine_only`, `instantiation/cold_compile_only`, `audit_emission/serialize_only` | informational only |
| Audit emission | `audit_emission/begin_complete` | no target set (fsync-bound) |

Do **not** conflate these targets into a single threshold.

`instantiation/cold` measured **39.490 ms** against a 5 ms target. Engine
construction accounts for only ~1–2% of it and `prepare` for ~29.4 ms, so
Execution Report §7 retired the target rather than the bench being reshaped.
See [`results/cell_and_audit.md`](results/cell_and_audit.md).

`instantiation/warm` goes through `SandboxEngine::execute`, so its median also
includes a fresh per-call tokio runtime, `build_store`, and a trivial WIT `run`
on the echo fixture — it is an upper bound on warm re-instantiation, not an
isolated instantiate cost. `PreparedTool.tool_pre` is private and no
instantiate-only public API may be added to narrow it.

The compile-bound groups are noisy on the reference machine (`cold` swings
27.8–39.5 ms across runs while its components stay stable). Read the
cross-run table in the results file before treating any single median as
reproducible; the pass/fail verdicts hold in every run.

## Hardware citation

Capture on the machine that ran the benches, then paste into the matching
results file ([`results/hot_path.md`](results/hot_path.md) or
[`results/cell_and_audit.md`](results/cell_and_audit.md)):

```bash
uname -a
lscpu | head -20    # or: sysctl -n machdep.cpu.brand_string  on macOS
rustc -Vv | head -5
```

## Published results

Committed Criterion summary tables (text only — not `target/criterion/` HTML):

- [`results/hot_path.md`](results/hot_path.md) — policy + capability
- [`results/cell_and_audit.md`](results/cell_and_audit.md) — wasmtime instantiation + audit emission

## Non-goals

- Do not measure full-pipeline / `Runtime::execute_tool_call` latency
- Do not add CI performance gates (publication claim only)
- Do not commit Criterion HTML reports under `target/criterion/`
- Do not add public sandbox/audit API to make a bench possible (PRD §10)
- Do not put wasmtime or audit numbers in `results/hot_path.md` — that file's
  non-goal is measuring sandbox/audit, and `results/cell_and_audit.md` owns them
