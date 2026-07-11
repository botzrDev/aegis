# Aegis benchmarks

Criterion benches for the **library-mode hot path** — the enforcement decision
path only:

```
POLICY (evaluate) → CAPABILITY (resolve_with_ceiling)
```

Sandbox, audit, and wasmtime execution are deliberately **out of scope**;
these benches never call `Runtime::execute_tool_call` — they measure only the
policy + capability stations. Satisfies **OQ-15 T5 / AEG-16** — Criterion
benchmarks published for the hot path with cited hardware/OS.

## Bench sources

| File | Groups | Gate |
|---|---|---|
| `crates/botzr-aegis-policy/benches/policy_eval.rs` | `policy_eval/allow_all`, `policy_eval/multi_rule`, `policy_eval/rate_limit` | `allow_all` + `multi_rule` **< 100 µs** median; `rate_limit` informational |
| `crates/botzr-aegis-capability/benches/resolve.rs` | `capability_resolve/registered_tool` | no hard gate (isolation / regression baseline) |
| `crates/botzr-aegis-runtime/benches/hot_path.rs` | `hot_path/allow_all`, `hot_path/multi_rule` | `multi_rule` **< 1 ms** median (combined policy+capability) |

The two latency targets are **separate and both intentional**: policy
`evaluate` alone targets < 100 µs (`policy/src/lib.rs`); the combined
policy+capability library-mode path targets < 1 ms (MASTER PRD / AEG-16). They
are never merged into one number.

## Run

```bash
cargo bench -p botzr-aegis-policy -p botzr-aegis-capability -p botzr-aegis-runtime
```

Criterion builds in `release`. HTML reports land under `target/criterion/` and
are **not** committed — only the text summary in `results/` is version-tracked.

## Capture hardware for the citation

Run these on the bench machine and paste them into `results/hot_path.md`
alongside the numbers (OQ-15 T5 requires cited hardware/OS):

```bash
uname -a
lscpu | head -20    # or `sysctl -a | grep machdep.cpu` on macOS
rustc -Vv | head -5
```

Be honest about the environment (bare metal vs. VM/WSL2, CPU governor, thermal
state). Absolute timings are only meaningful next to the hardware they ran on.

## Targets

| Scope | Target (median) | Notes |
|---|---|---|
| Policy `evaluate` (`policy_eval/allow_all`, `.../multi_rule`) | **< 100 µs** | Station 1 alone; YAML parsed once in setup, never in the iter body. |
| Combined hot path (`hot_path/multi_rule`) | **< 1 ms** | Policy decision + capability grant mint, mirroring `runtime/src/lib.rs:143–167`. |
| `policy_eval/rate_limit` | informational | Takes the `RateLimiter` mutex; **not** under the < 100 µs claim. |
| `capability_resolve/registered_tool` | no hard gate | Isolates the resolve step for regression tracking. |

These are **publication claims**, not CI gates — this ticket adds no performance
gate to CI.

## Committed numbers

See [`results/hot_path.md`](results/hot_path.md) for the pasted Criterion tables
and the hardware block they were measured on.
