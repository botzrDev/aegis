# Aegis findings report

> **Status:** v0.3 findings synthesis (AILAB-606) · **Last updated:** 2026-08-07  
> **Related:** [Threat model](threat-model.md) · [Audit schema freeze](audit-schema.md) · [SECURITY.md](../SECURITY.md) · [Benchmarks](../benches/results/hot_path.md) · [Fuzz campaign log](../fuzz/README.md)

Aegis is a **research instrument**: the point is not to assert that agent tool
execution is safe, but to make isolation claims falsifiable and then attack them.
This document synthesizes what the instrument has measured so far — what the
runtime is observed to guarantee, what it explicitly does not, and the exact
commands that reproduce each observation. Everything here is **evidence, not
certification** (see [threat model §8](threat-model.md#8-evidence-artifacts-not-proof)).

---

## 1. Claim under test

The [README](../README.md) states the hypothesis:

> A **default-deny**, capability-grant-driven, **per-call** WASM sandbox with
> mandatory audit can contain an adversarial or prompt-injected tool call such that
> **no single mistake** — a forgotten host check, a malformed policy, a panicking host
> function — escalates into ambient host authority.

That is a design goal to be measured and attacked, not a guarantee. The
[threat model](threat-model.md) defines the scope, the two trust models, and the
named non-goals against which every finding below should be read.

---

## 2. What we guarantee (measured)

Within the stated threat model, the following behaviors are enforced by the
pipeline and exercised by in-repo tests:

- **Pipeline order.** Every tool call walks
  `POLICY → CAPABILITY → SANDBOX → AUDIT`, with audit wrapping the inner three
  stations. A policy or capability denial never reaches sandbox instantiation.
- **Default-deny capability resolution.** Unregistered tools, undeclared
  capabilities, and unresolvable needs are refused before any effect; a grant is
  minted only from a registered manifest.
- **Model A containment.** WASM tool logic runs inside wasmtime with cap-std
  preopens wired from the grant — `..` traversal, symlink escape, and writes
  under a read-only grant are refused at the WASI/cap-std boundary.
- **Model B is a grant check plus audit — not sandbox isolation.** Host-function
  effects execute with host privileges; the runtime enforces the grant before
  context-owned effects and audits the outcome, nothing more.
- **Audit on every exit path.** Denials, traps, resource caps, and panics all
  produce schema-versioned records ([audit schema](audit-schema.md)); there is
  no silent exit.
- **Resource ceilings per call.** Epoch-based wall-clock deadline and a memory
  limiter are configured per call from the grant; tripping either produces a
  `ResourceExceeded` audit outcome.

---

## 3. What we do not guarantee

Explicit gaps, stated so a reviewer does not have to discover them:

- **Model B is not isolation.** A host-function bug is a full host-privilege
  effect. See [threat model §3](threat-model.md#3-trust-boundaries-model-a-vs-model-b)
  and §6.
- **A passing stress run is not a formal proof.** The exactly-once audit result
  below holds for the schedules the scoped threads happened to produce, not for
  all possible interleavings.
- **A no-crash fuzz campaign is not exhaustive.** It bounds the surface explored
  in the recorded time on the recorded hardware, nothing stronger.
- **Two planned fuzz surfaces were dropped, not deferred — because they do not
  exist.** Early planning named three parse surfaces to fuzz. Host-argument
  decoding (the `get_string` OOB class) is not one Aegis has: the sandbox is
  component-model-native, so wasmtime lifts host-import arguments before they
  reach Aegis and there is no pointer/length decoder in-tree. Capability-manifest
  deserialization is not one either — `ToolManifest` is a Rust builder with no
  serde implementation and no on-disk format. Policy YAML is the only one of the
  three that exists, and it is the one that is fuzzed. Read that as a statement
  about how small the parse surface is, not as evidence of thorough fuzzing:
  §4.5's limits still apply.
- **No Miri on upstream unsafe code.** The workspace forbids `unsafe`, so there
  is no first-party unsafe for Miri to check; wasmtime and cap-std own their own
  unsafe surface. We track RUSTSEC advisories via cargo-deny instead — see the
  verification posture in [SECURITY.md](../SECURITY.md).

**Supply-chain posture:** cargo-deny runs in CI (full `cargo deny check`) plus a
weekly advisory workflow; scope and the one recorded advisory ignore are in
`deny.toml`. Details in [SECURITY.md](../SECURITY.md).

**Layer 2 / governance findings are out of scope** of this runtime findings
document; `governance/` is a separate service with its own evidence trail.

---

## 4. Case studies

Each case study is one finding, the files that carry it, a copy-pasteable
command, and what you should observe. Commands run from the repository root on a
clean checkout.

### 4.1 Grant narrowing cannot broaden authority

A sub-tool grant narrowed from a parent can never carry more authority than the
parent on any axis — filesystem writes and output caps are checked by unit
tests, and the subset invariant is exercised as a property test over randomized
memory / wall-clock / output limits.

- Files: [`crates/botzr-aegis-capability/src/narrow.rs`](../crates/botzr-aegis-capability/src/narrow.rs)
  (unit tests `rejects_fs_write_escalation`, `rejects_output_cap_escalation`),
  [`crates/botzr-aegis-capability/tests/capability.rs`](../crates/botzr-aegis-capability/tests/capability.rs)
  (proptest `narrowed_grant_never_broader_than_parent`)
- Command:

  ```bash
  cargo test -p botzr-aegis-capability
  ```

  Targeted variants:

  ```bash
  cargo test -p botzr-aegis-capability rejects_fs_write_escalation
  cargo test -p botzr-aegis-capability narrowed_grant_never_broader_than_parent
  ```

- Expected observation: escalation attempts fail with
  `CapabilityError::Escalation`; the proptest passes across its generated cases.

### 4.2 Adversarial guests are refused in both trust models

A deliberately malicious `wasip2` guest (DamageBot) driven through
`Runtime::execute_tool_call` is refused on every attack it attempts: write under
a read-only grant, `..` traversal, symlink escape (Model A / cap-std), and HTTP
exfiltration without a net grant or to a disallowed host (Model B / host grant
check).

- Files: [`examples/damage-bot-demo/README.md`](../examples/damage-bot-demo/README.md)
  (case table),
  [`tests/adversarial-demo/tests/damage_bot.rs`](../tests/adversarial-demo/tests/damage_bot.rs)
  (the six acceptance tests), guest source under `tests/fixtures/damage-bot/`
- Command:

  ```bash
  ./scripts/build-fixtures.sh          # builds the adversarial guest wasm
  cargo test -p aegis-adversarial-demo
  ```

- Expected observation: all six tests pass. Five attacks are refused outright;
  the sixth (`guest_http_to_allowed_host_passes_grant_then_stubs`) is a positive
  control — a request to an allowed host passes policy and grant resolution and
  is then denied by the v1 HTTP stub. All six outcomes produce audit records.

### 4.3 Every pipeline exit path is audited; denials are first-class

The deny suite drives the full pipeline through its refusal paths and asserts
both the refusal and the audit record it produces; golden snapshots freeze the
audit wire shape so a drift in the record format is itself a test failure.

- Files: [`tests/deny-suite/`](../tests/deny-suite/) — representative tests:
  `policy_deny_is_refused_and_audited`, `unregistered_tool_is_capability_denied`,
  `memory_cap_trips_through_pipeline`, `wall_clock_cap_trips_through_pipeline`
- Command:

  ```bash
  cargo test -p aegis-deny-suite
  ```

- Expected observation: denial and resource-cap paths produce schema v1 outcome
  records; representative paths are frozen against golden snapshots (trap
  coverage lives in the adversarial demo and stress suite); no exit path is
  silent.

### 4.4 Audit emission is exactly-once under concurrency

Under mixed success, denial, trap, resource-cap, and panic-class calls fired on
scoped threads at one shared `Runtime`, each call produces exactly one intent
and exactly one outcome record — no orphan intents, no duplicate outcomes.

- Files: [`tests/stress/tests/exactly_once.rs`](../tests/stress/tests/exactly_once.rs)
  (single test `audit_is_exactly_once_under_concurrency`; plain threads, no
  async runtime)
- Command:

  ```bash
  cargo test -p aegis-stress-suite
  ```

- Expected observation: the test passes; the JSONL sink pairs every `call-N`
  intent with exactly one outcome. This is evidence over observed schedules, not
  a proof over all interleavings (§3).

### 4.5 Policy YAML parse surface survived its first fuzz campaign

The first cargo-fuzz campaign against `PolicyEngine::from_yaml` (plus one
`evaluate` on successful parse) recorded no crash. From the
[campaign log](../fuzz/README.md): 2026-08-07, target `policy_yaml`, 10m 30s
(30s smoke + 2×5m sessions), no crash across 5,893,498 campaign runs (final
coverage 4244, corpus 2817), on the hardware cited in that log.
`Err(PolicyError)` on malformed YAML is the parser doing its job, not a finding.

- Files: [`fuzz/README.md`](../fuzz/README.md) (harness, seed corpus, campaign log)
- Command (optional, bounded — requires nightly + cargo-fuzz; not part of the
  default evidence bundle):

  ```bash
  cargo +nightly fuzz run policy_yaml -- -max_total_time=60
  ```

- Expected observation: the bounded smoke completes with no crash artifacts
  under `fuzz/artifacts/policy_yaml/`.

---

## 5. How to reproduce

One command runs the bounded evidence subset and writes a stamped bundle:

```bash
./scripts/evidence-bundle.sh
```

This creates `evidence/YYYYMMDD-HHMMSS/` containing:

- `MANIFEST.txt` — commit SHA, `rustc -Vv` head, `uname -a`, timestamp
- `deny-suite.log` — `cargo test -p aegis-deny-suite`
- `adversarial-demo.log` — `cargo test -p aegis-adversarial-demo`
- `stress.log` — `cargo test -p aegis-stress-suite`
- `pointers.txt` — paths to this report, the threat model, the fuzz campaign
  log, and the benchmark results

The script exits nonzero if any required test fails — or, when
`AEGIS_EVIDENCE_FUZZ=1`, if the fuzz smoke fails. It deliberately does not
run `cargo bench` or a long fuzz campaign. Setting `AEGIS_EVIDENCE_FUZZ=1` adds
a 30-second fuzz smoke (`fuzz-smoke.log`) when nightly and cargo-fuzz are
available, and records a clean skip note otherwise. Bundle output under
`evidence/` is generated per run and not committed.

---

## 6. Hardware / versions

No raw number in this report originates here; each is a citation:

- **Latency numbers** come from [`benches/results/hot_path.md`](../benches/results/hot_path.md):
  `policy_eval/allow_all` 13.4 ns median, `policy_eval/multi_rule` 31.8 ns,
  `hot_path/multi_rule` 2.71 µs — against targets of <100 µs for policy eval
  alone and <1 ms for the combined policy + capability hot path. Recorded on the
  hardware cited in that file (WSL2 Linux, AMD Ryzen AI 5 340, rustc 1.96.0,
  Criterion 0.5.1, dated 2026-07-09).
- **Fuzz campaign numbers** come from the [`fuzz/README.md`](../fuzz/README.md)
  campaign log, which cites its own hardware and nightly rustc per row.

Numbers reproduced on different hardware will differ; the targets, not the
medians, are the claim. Fresh runs should cite their own environment the same
way (`uname -a`, CPU model, `rustc -Vv`).
