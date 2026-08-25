# Hot-path Criterion results (AEG-16 / OQ-15 T5)

## Hardware / OS

```
uname -a
Linux botzrDev 6.6.87.2-microsoft-standard-WSL2 #1 SMP PREEMPT_DYNAMIC Thu Jun  5 18:30:46 UTC 2025 x86_64 x86_64 x86_64 GNU/Linux

lscpu (selected):
Architecture:                         x86_64
Model name:                           AMD Ryzen AI 5 340 w/ Radeon 840M
CPU(s):                               4
Thread(s) per core:                   2
Core(s) per socket:                   2
Hypervisor vendor:                    Microsoft
Virtualization type:                  full

rustc -Vv:
rustc 1.96.0 (ac68faa20 2026-05-25)
host: x86_64-unknown-linux-gnu
```

**Environment notes:** WSL2 / Linux; Criterion 0.5.1; Gnuplot not installed (plotters backend). Date: 2026-07-09.

## Command

```bash
cargo bench -p botzr-aegis-policy -p botzr-aegis-capability -p botzr-aegis-runtime
```

## Summary vs targets

| Group | Median (approx.) | Target | Status |
|---|---|---|---|
| `policy_eval/allow_all` | **13.4 ns** | < 100 µs | **pass** |
| `policy_eval/multi_rule` | **31.8 ns** | < 100 µs | **pass** |
| `policy_eval/rate_limit` | **183 ns** | informational (mutex) | n/a |
| `capability_resolve/registered_tool` | **2.43 µs** | no hard gate | n/a — *bench id and measured path both changed 2026-08-24; see AILAB-707 below* |
| `hot_path/allow_all` | **2.67 µs** | (floor) | n/a |
| `hot_path/multi_rule` | **2.71 µs** | < 1 ms | **pass** |

Criterion reports `[lower median upper]` as time/op; medians above are the middle sample.

## Criterion text tables

```
capability_resolve/registered_tool
                        time:   [2.3959 µs 2.4329 µs 2.4751 µs]

policy_eval/allow_all   time:   [13.240 ns 13.408 ns 13.582 ns]
policy_eval/multi_rule  time:   [31.025 ns 31.775 ns 32.898 ns]
policy_eval/rate_limit  time:   [181.31 ns 182.74 ns 184.38 ns]

hot_path/allow_all      time:   [2.6091 µs 2.6727 µs 2.7417 µs]
hot_path/multi_rule     time:   [2.6453 µs 2.7136 µs 2.7872 µs]
```

## Notes

- Combined hot path is dominated by capability grant minting (~2.4 µs alone); policy eval is tens of nanoseconds.
- Rate-limit path is ~6× multi-rule policy eval but still far below 100 µs; kept informational because it takes a `Mutex`.
- HTML reports live under `target/criterion/` and are **not** committed.

## AILAB-707 update — 2026-08-24

AILAB-707 routed both benchmarks off `CapabilityResolver::register`, which is
`#[deprecated]` as a cross-crate visibility fence. A published benchmark that
suppressed a deprecation to reach a forbidden path was the claim-integrity
defect; the suppressions are gone. The table above is **not** retroactively
edited — it records what was measured on 2026-07-09, under the ids that existed
then.

### What changed in each measured path

- **`capability_resolve/registered_tool` → `capability_resolve/mint_from_manifest`.**
  Renamed because the tool is genuinely no longer registered. `botzr-aegis-capability`
  cannot reach `Runtime::register_tool` (runtime depends on capability, so the
  reverse edge is a dependency cycle), so the bench moved to `resolve_manifest`,
  the supported one-off mint route shipped for `aegis wrap --confine`. Two pieces
  of work **left** the measured path: the `HashMap<ToolId, ToolManifest>` registry
  lookup, and the `ResourceCeiling::combine` fold. Ceiling semantics are unchanged
  — the old call passed `ResourceCeiling::default()` and the standing ceiling is
  also default, so `combine` was a no-op. The number should therefore have moved
  slightly **down**.
- **`hot_path/allow_all`, `hot_path/multi_rule` — measured work unchanged.**
  The bench lives inside `botzr-aegis-runtime`, so it now registers through
  `Runtime::register_tool` in setup and measures against `rt.capabilities()`.
  The closure still runs `evaluate` → `decision.limits` → `resolve_with_ceiling`,
  the registry is still a one-entry map, and registration is setup, never
  measured. The fixture manifest's `ToolKind` became `Host` so the handler
  matches; nothing on the production mint path branches on kind (every `ToolKind`
  in capability's `mint.rs` / `narrow.rs` is inside `#[cfg(test)]`, and policy
  never reads it). These two numbers should therefore **not** move at all.

### Measurements — and why they are not a re-baseline

Hardware / OS as above, **except the toolchain**: `rustc 1.86.0 (05f9846f8
2025-03-31)`, LLVM 19.1.7, on Linux 6.6.87.2-microsoft-standard-WSL2, AMD Ryzen
AI 5 340 (4 CPU / 2 cores), Criterion 0.5.1, plotters backend. The 2026-07-09
table above was taken on `rustc 1.96.0`, so it is **not** a valid before-value
for this change.

Medians, µs. Pre-change was measured on clean `746ae42` before any edit; runs
1–3 are three consecutive runs of the **same** post-change binary.

| Bench | pre-change | post r1 | post r2 | post r3 |
|---|---|---|---|---|
| `capability_resolve/mint_from_manifest` | 2.5731 | 2.6472 | 2.5833 | 2.6314 |
| `hot_path/allow_all` | 2.6238 | 3.6966 | 2.7764 | 2.7480 |
| `hot_path/multi_rule` | 2.7286 | 2.8755 | 3.4096 | 2.9367 |

Between those identical-code runs Criterion reported, in order: **+42%
"regressed", −20% "improved", +12% "regressed", −10% "improved", +7%
"regressed", −5.6% "improved"** — all at p < 0.05. A benchmark whose measured
work provably did not change (`hot_path/*`) swung by 42 points between runs of
the same binary.

**Conclusion: no change is attributable to the edit, because this box cannot
resolve an effect of the expected size.** The run-to-run noise floor here is
roughly ±20%, and the predicted effects are one hash lookup and three
`Option<u64>` mins. Note also that `capability_resolve` moved *up* ~2% while the
work it does strictly decreased — the sign is wrong, which is itself evidence
that noise dominates.

The published medians above are therefore **left as they are** rather than
overwritten with these runs: replacing a measurement with a noisier one, taken
on a different toolchain, would publish noise as evidence. A clean re-baseline
of the whole suite — quiet machine, pinned toolchain, all groups — is owed and
is not this ticket's scope.
