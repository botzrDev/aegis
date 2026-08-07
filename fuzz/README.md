# Aegis fuzzing (AILAB-601)

`cargo-fuzz` harness for the policy YAML parse surface. This directory is a
**sibling cargo project** — excluded from the workspace (`[workspace] exclude`)
because libFuzzer needs nightly while the workspace pins `1.86` with
`unsafe_code = forbid`.

| Target | Surface | Entry point |
|---|---|---|
| `policy_yaml` | untrusted policy YAML | `PolicyEngine::from_yaml` → one `evaluate` on `Ok` |

The target gates on valid UTF-8, caps input at 64 KiB, and on a successful
parse performs exactly **one** `evaluate` call with `ToolId::new("fuzz")`
(never a loop — the rate limiter is mutex-guarded and stateful).

## Prerequisites

```bash
rustup toolchain install nightly
cargo +nightly install cargo-fuzz --locked
```

## Run

From the **repository root** (cargo-fuzz resolves the `fuzz/` subdirectory
relative to the current directory):

```bash
# CI-style smoke (~60 s, bounded)
cargo +nightly fuzz run policy_yaml -- -max_total_time=60

# Long campaign (e.g. 10 minutes; raise for overnight runs)
cargo +nightly fuzz run policy_yaml -- -max_total_time=600
```

Seed corpus lives in `fuzz/corpus/policy_yaml/` (committed): the dreamd PoC
policy fixture plus accept/reject snippets lifted verbatim from the
`botzr-aegis-policy` unit tests. libFuzzer grows the corpus in place; only the
`seed-*` files are tracked.

## Minimizing a crash

Crash inputs land under `fuzz/artifacts/policy_yaml/`. Minimize before filing:

```bash
cargo +nightly fuzz tmin policy_yaml fuzz/artifacts/policy_yaml/crash-<hash>
```

Then: commit the minimized input as a regression `#[test]` under
`crates/botzr-aegis-policy` (feed it to `PolicyEngine::from_yaml`) and open a
Linear finding issue (priority High).

## What counts as a finding

- **Finding:** panic, abort, sanitizer crash, OOM/timeout flagged by libFuzzer.
- **Not a finding:** `Err(PolicyError)` from `from_yaml` — rejecting malformed
  YAML is the parser doing its job. A campaign with no crash is a valid
  result; record it below.

## Campaign log

Cite hardware as in `benches/README.md`: duration, `uname -a`, CPU model
(`lscpu | head -20`), `rustc -Vv | head -5`.

| Date | Target | Duration | Result | Hardware |
|---|---|---|---|---|
| 2026-08-07 | policy_yaml | 10m 30s (30s smoke + 2×5m sessions) | no crash (5,893,498 campaign runs; final cov 4244, corp 2817) | Linux 6.6.87.2-microsoft-standard-WSL2 x86_64; AMD Ryzen AI 5 340 w/ Radeon 840M; rustc 1.97.0-nightly (17584a181 2026-04-13) |
