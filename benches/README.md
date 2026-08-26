# Aegis benchmarks (AEG-16 / OQ-15 T5 · AEG-005 / AILAB-683)

Three independent scopes, published to three separate results files:

- **Library-mode hot path** ([`results/hot_path.md`](results/hot_path.md)) —
  policy evaluation and capability resolution. Sandbox, audit, and wasmtime are
  intentionally **not** timed in the `hot_path` bench, and that non-goal still
  stands.
- **Cell + audit** ([`results/cell_and_audit.md`](results/cell_and_audit.md)) —
  wasmtime warm/cold instantiation, audit record emission, and isolated ed25519
  line signing, added by AILAB-683 / AILAB-620 in their own bench targets.
- **Wrap relay** ([`results/wrap_overhead.md`](results/wrap_overhead.md)) —
  what it costs to put `aegis wrap` between an MCP client and a stdio child,
  added by AILAB-625.

All three are `{{#include}}`d verbatim into the book's
[Benchmarks](../docs/benchmarks.md) chapter, so anything added here is
published there. Keep the targets table below in sync with that page.

## Run

From the repository root:

```bash
cargo bench -p botzr-aegis-policy -p botzr-aegis-capability -p botzr-aegis-runtime
cargo bench -p botzr-aegis-sandbox -p botzr-aegis-audit
cargo bench -p botzr-aegis-wrap
```

`botzr-aegis-audit` declares two bench targets, `emission` and `sign`; the
package line above runs both. To run just the signing group — which is how
`results/cell_and_audit.md` records it, because it was measured on its own
day:

```bash
cargo bench -p botzr-aegis-audit --bench sign
```

| Package | Bench target | Groups |
|---|---|---|
| `botzr-aegis-policy` | `policy_eval` | `allow_all`, `multi_rule`, `rate_limit` (info) |
| `botzr-aegis-capability` | `resolve` | `registered_tool` |
| `botzr-aegis-runtime` | `hot_path` | `allow_all`, `multi_rule` |
| `botzr-aegis-sandbox` | `instantiation` | `warm`, `cold`, `cold_engine_only` (info), `cold_compile_only` (info) |
| `botzr-aegis-audit` | `emission` | `begin_complete`, `serialize_only` (info) |
| `botzr-aegis-audit` | `sign` | `sign_outcome_line` |
| `botzr-aegis-wrap` | `overhead` | `tools_call_recorded`, `ping_relayed_only` (info) |

## Latency targets

| Scope | Group | Target (median) |
|---|---|---|
| Policy eval alone | `policy_eval/allow_all`, `policy_eval/multi_rule` | **&lt; 100 µs** |
| Combined policy + capability | `hot_path/multi_rule` | **&lt; 1 ms** |
| Warm cell instantiation | `instantiation/warm` | **&lt; 0.5 ms** |
| Cold instantiation | `instantiation/cold` | **&lt; 5 ms** — *missed; target under review, see below* |
| ed25519 line signing | `audit_signing/sign_outcome_line` | **&lt; 50 µs** (AILAB-620) — *met at 13.765 µs* |
| Rate-limit path | `policy_eval/rate_limit` | informational only (mutex) |
| Capability alone | `capability_resolve/mint_from_manifest` | no hard gate |
| Attribution splits | `instantiation/cold_engine_only`, `instantiation/cold_compile_only`, `audit_emission/serialize_only` | informational only |
| Audit emission | `audit_emission/begin_complete` | no target set (fsync-bound) |
| Wrap relay per recorded `tools/call` | `wrap_relay/tools_call_recorded` | **0.5–2 ms** — *informational; missed at 4.371 ms, two fsyncs per call, see [`results/wrap_overhead.md`](results/wrap_overhead.md)* |

Do **not** conflate these targets into a single threshold.

`instantiation/cold` measured **39.490 ms** against a 5 ms target. Engine
construction accounts for only ~1–2% of it and `prepare` for ~29.4 ms, so
Execution Report §7 retired the target rather than the bench being reshaped.
See [`results/cell_and_audit.md`](results/cell_and_audit.md).

`instantiation/warm` goes through `SandboxEngine::execute`, so its median also
includes `build_store` and a trivial WIT `run` on the echo fixture — it is an
upper bound on warm re-instantiation, not an isolated instantiate cost. The
published median additionally carries a **fresh per-call tokio runtime**, which
is how the engine worked when it was measured; AILAB-809 amortized that runtime
into `SandboxEngine::new`, so the number is now an upper bound for that reason
too, pending AILAB-796. `PreparedTool.tool_pre` is private and no
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
