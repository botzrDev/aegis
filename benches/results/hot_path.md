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
| `hot_path/allow_all` | **2.67 µs** | (floor) | n/a — *superseded 2026-09-07; see AILAB-846 below* |
| `hot_path/multi_rule` *(stations 1–2 only — **not** the cost of a call)* | **2.71 µs** | < 1 ms | **pass** — *superseded 2026-09-07; see AILAB-846 below* |

Criterion reports `[lower median upper]` as time/op; medians above are the middle sample.

**What the last two rows are not.** `hot_path` mirrors stations 1–2 and calls
neither sandbox, audit nor wasmtime inside `b.iter` — that non-goal is
deliberate and still stands. So 2.71 µs is a **component figure**, not what an
audited call costs, and it must not be quoted as one: the same call against the
shipped Volatile sink is roughly an order of magnitude more, and against a
Durable sink a further two to three orders on top of that — a span, not a
figure, because the Durable arm did not reproduce across two sessions. Those
are the `audited_call` group
in [`cell_and_audit.md`](https://github.com/botzrDev/aegis/blob/main/benches/results/cell_and_audit.md),
which is where the end-to-end number lives.

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

---

## AILAB-846 update — canonicalizing at registration, 2026-09-07

**What changed, and which of these groups can see it.** Capability resolution
used to `std::fs::canonicalize` every path a manifest declared, on every call.
It now happens once, when the tool is registered, and resolution reuses the
result. Exactly one of the two groups below runs that code:

* `hot_path/*` registers through `Runtime::register_tool` in setup and calls
  `resolve_with_ceiling` inside `b.iter` — the changed path.
* `capability_resolve/mint_from_manifest` calls `resolve_manifest`, which mints
  from a manifest the caller already holds and has no registration to have
  prepared. That path still canonicalizes per call, deliberately: it is what
  `aegis wrap --confine` uses. **It is the control here, not the result.**

**Hardware / OS as in the block at the top of this file, with the toolchain
stated rather than inherited:** `rustc 1.86.0 (05f9846f8 2025-03-31)` — the
version `rust-toolchain.toml` pins — on Linux 6.6.87.2-microsoft-standard-WSL2,
AMD Ryzen AI 5 340 (4 CPU / 2 cores), WSL2, Criterion 0.5.1, plotters backend,
`bench` profile. The 2026-07-09 table above was taken on `rustc 1.96.0` and is
**not** a valid before-value; the before column here was measured today, from a
worktree at `9b1d484`, in the same session and on the same toolchain as the
after column.

Criterion `[lower median upper]`:

| Bench | before (`9b1d484`) | after | median delta |
|---|---|---|---|
| `hot_path/allow_all` | [2.2905 **2.3150** 2.3428] µs | [221.18 **224.61** 228.43] ns | **−90.3%** (10.3×) |
| `hot_path/multi_rule` | [2.6515 **2.7314** 2.8171] µs | [259.60 **263.44** 267.90] ns | **−90.4%** (10.4×) |
| `capability_resolve/mint_from_manifest` *(control — unchanged path)* | [2.2668 **2.2997** 2.3351] µs | [2.4060 **2.4457** 2.4908] µs | +6.3% |

**Why these are readable when AILAB-707's were not.** That section, above,
measured a predicted effect of one hash lookup and three `Option<u64>` mins
against a ±20% run-to-run noise floor, and correctly concluded nothing was attributable.
Here the effect is 10×: fifty times the noise floor, and the two arms move in
opposite directions in the way the change predicts — the group that stopped
touching the filesystem fell by an order of magnitude, and the group that still
touches it did not move outside noise. The control's +6.3% is the *wrong* sign
for a speed-up and is exactly what a control should do. The before-value is also
corroborated rather than a single sample: AILAB-707's pre-change
`hot_path/multi_rule` on this same toolchain was 2.7286 µs, against 2.7314 µs
measured today.

**What the saving is, and what it is not.** It is **2.47 µs** off stations 1–2.
Stations 1–2 are not a call — that is the label the row above carries and it
still applies. Against the end-to-end figures in
[`cell_and_audit.md`](https://github.com/botzrDev/aegis/blob/main/benches/results/cell_and_audit.md),
2.47 µs is:

* **6.6 – 7.5%** of an audited call against the shipped Volatile sink
  (32.9 – 37.4 µs)
* **0.014 – 0.086%** of an audited call against a Durable sink
  (2.86 – 17.5 ms)

So a call did not get ten times faster and no sentence here should be read that
way. The 10× is a component figure for a component that is a small and, on the
durable arm, negligible share of what a call costs. This work was queued for the
grant-id spelling gap and the process-global counter; the speed-up is a side
effect of doing it, not the case for it.

**Provisional, like everything else in this directory.** These were taken on a
box that swings ±20% on identical binaries and was doing other work at the time.
The *shape* — an order of magnitude on the changed path, noise on the control —
is what survives; the digits are not a baseline. **AILAB-796 is the ticket that
re-measures on a quiet machine.**
