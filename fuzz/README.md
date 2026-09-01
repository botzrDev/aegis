# Aegis fuzzing (AILAB-601)

`cargo-fuzz` harness for the parse surfaces reached from untrusted bytes. This
directory is a **sibling cargo project** — excluded from the workspace
(`[workspace] exclude`) because libFuzzer needs nightly while the workspace
pins `1.86` with `unsafe_code = forbid`.

| Target | Surface | Entry point |
|---|---|---|
| `policy_yaml` | untrusted policy YAML | `PolicyEngine::from_yaml` → one `evaluate` on `Ok` |
| `jcs_canonical` | untrusted JSON reaching the RFC 8785 canonicalizer | `serde_json::from_slice` → `to_canonical_json` → `canonical_digest`, then reparse-and-compare on `Ok` |

The `policy_yaml` target gates on valid UTF-8, caps input at 64 KiB, and on a
successful parse performs exactly **one** `evaluate` call with
`ToolId::new("fuzz")` (never a loop — the rate limiter is mutex-guarded and
stateful).

`jcs_canonical` (AILAB-850) covers `to_canonical_json`, which computes the hash
input for **every signature in every Chain** and is reached from
attacker-controlled bytes at three places: the verifier walk, signature
verification, and `tail_of_lines`, which runs *before* a Session opens on an
existing file. A divergence there does not fail loudly — it invalidates every
signature and surfaces as an unexplainable hash mismatch. The target caps input
at the same 64 KiB and parses first, so it inherits `serde_json`'s recursion
limit and needs no depth guard of its own.

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
cargo +nightly fuzz run jcs_canonical -- -max_total_time=60

# Long campaign (e.g. 10 minutes; raise for overnight runs)
cargo +nightly fuzz run policy_yaml -- -max_total_time=600
cargo +nightly fuzz run jcs_canonical -- -max_total_time=600
```

Seed corpus lives in `fuzz/corpus/policy_yaml/` (committed): the dreamd PoC
policy fixture plus accept/reject snippets lifted verbatim from the
`botzr-aegis-policy` unit tests. `fuzz/corpus/jcs_canonical/` holds nine seeds:
the published test vector's canonical form, a key set spanning the UTF-16
surrogate boundary, the escape cases, the `MAX_SAFE_INTEGER` boundary, one file
per value-space refusal, and a nesting case. The surrogate-boundary seed earns
its place — it is the only shape that distinguishes UTF-16 from UTF-8 key order,
and libFuzzer will not invent it from random bytes. libFuzzer grows the corpus
in place; only the `seed-*` files are tracked.

## Minimizing a crash

Crash inputs land under `fuzz/artifacts/policy_yaml/`. Minimize before filing:

```bash
cargo +nightly fuzz tmin policy_yaml fuzz/artifacts/policy_yaml/crash-<hash>
```

Then: commit the minimized input as a regression `#[test]` under
`crates/botzr-aegis-policy` (feed it to `PolicyEngine::from_yaml`) and open a
Linear finding issue (priority High).

For a `jcs_canonical` crash the regression test belongs under
`crates/botzr-aegis-core`. **Do not fix the canonicalizer in the same change:**
its output is the hash input for every signature in the repo, so a change there
moves every published hash and every golden vector, and is its own ticket.

## What counts as a finding

- **Finding:** panic, abort, sanitizer crash, OOM/timeout flagged by libFuzzer.
- **Finding (`jcs_canonical` specifically):** a canonical form that fails to
  reparse as JSON, or that reparses to a value **not equal** to the input. That
  is a silent corruption of what a third-party verifier will hash, and it is the
  outcome this target exists to find.
- **Not a finding:** `Err(PolicyError)` from `from_yaml` — rejecting malformed
  YAML is the parser doing its job. Likewise `Err(JcsError)` from
  `to_canonical_json`: floats, negative integers, integers at or above 2^53 and
  explicit `null` are outside the JCS value space **by design**, and arbitrary
  JSON produces them constantly. Refusing them is the canonicalizer working, and
  a target that counted them as crashes would fail within seconds on correct
  behaviour. A campaign with no crash is a valid result; record it below.

## Campaign log

Cite hardware as in `benches/README.md`: duration, `uname -a`, CPU model
(`lscpu | head -20`), `rustc -Vv | head -5`.

| Date | Target | Duration | Result | Hardware |
|---|---|---|---|---|
| 2026-08-07 | policy_yaml | 10m 30s (30s smoke + 2×5m sessions) | no crash (5,893,498 campaign runs; final cov 4244, corp 2817) | Linux 6.6.87.2-microsoft-standard-WSL2 x86_64; AMD Ryzen AI 5 340 w/ Radeon 840M; rustc 1.97.0-nightly (17584a181 2026-04-13) |
| 2026-09-01 | jcs_canonical | 6m 2s (61s seedless smoke + 301s seeded campaign) | no crash (6,503,419 runs seedless; 10,373,229 runs seeded, cov 1453 to 1882, ft 10518, corp 2413/2026Kb, 34,462 exec/s) | Linux 6.6.87.2-microsoft-standard-WSL2 x86_64; AMD Ryzen AI 5 340 w/ Radeon 840M; rustc 1.97.0-nightly (17584a181 2026-04-13) |
