# Aegis

> **A reproducible runtime for testing what agent tool isolation actually guarantees.**

Aegis is a **research instrument** for secure agent tool execution, built in Rust on
[wasmtime](https://wasmtime.dev/). It sits *underneath* agent frameworks — it is not
an orchestrator, not a dashboard, not an LLM layer. Every tool call walks one
enforcement pipeline, and the runtime emits an audit record on every exit path.

The goal is not to assert that agent tools are safe. It is to make the isolation
claims **falsifiable**: a pipeline you can run, a malicious guest you can point at it,
benchmarks you can reproduce, and a threat model that names its own gaps.

**Docs.** The stranger-facing hub is published at
**<https://botzrdev.github.io/aegis/>**. Source lives in [`docs/`](docs/); from a
clone, `cd docs && mdbook serve`. CI builds the book on every PR and redeploys
the site on every push to `main`.

## Hypothesis

The instrument tests a single claim:

> A **default-deny**, capability-grant-driven, **per-call** WASM sandbox with
> mandatory audit can contain an adversarial or prompt-injected tool call such that
> **no single mistake** — a forgotten host check, a malformed policy, a panicking host
> function — escalates into ambient host authority.

That is a design goal to be measured and attacked, not a guarantee. See the
[threat model](docs/threat-model.md) for what is in scope, what is explicitly not,
and where the honesty boundaries are.

## The pipeline

Every tool call walks the same four stations, in this order (load-bearing — audit
wraps the inner three):

```
POLICY → CAPABILITY → SANDBOX → AUDIT
```

| Station | Role |
|---|---|
| **Policy** | Role gate, approval gate, rate limits — sync eval over a parsed-once `Arc<PolicySet>` |
| **Capability** | Default-deny manifest resolution → minted grant; a denial never reaches the sandbox |
| **Sandbox** | Configure a **per-call** wasmtime `Store` **from the grant**, then run (cap-std preopens; epoch + memory limits) |
| **Audit** | Schema-versioned record emitted on **every** exit — allow, deny, trap, resource cap, or panic — with no raw secret payloads |

## Two trust models (read this before trusting anything)

Aegis supports two execution models with **different blast radii**. Conflating them is
the primary way a sandbox becomes decorative.

- **Model A — WASM tool.** Tool logic compiles to `wasm32-wasip2` and runs *inside*
  wasmtime. The guest can only reach the outside world through WASI surfaces wired
  from the grant. **Isolation is strong** because the guest cannot express an
  un-granted effect — there is no syscall surface except what the host linked.

- **Model B — host function.** The real side effect (HTTP, DB, exec) runs in **host
  Rust**, exposed to the guest as an imported function. The sandbox isolates the
  guest's *decision logic*, but the *effect* executes with **host privileges**.
  **Model B is not sandbox isolation.** It is a capability-checking, auditing proxy.
  Every host function must enforce the grant *before* acting; if it skips that check,
  the guest gets full host authority for that effect.

Prefer Model A wherever tool logic can live in WASM. Reserve Model B for effects that
genuinely must touch the host, and keep that host-function set small and hand-audited.
Details and evidence: [threat model §3](docs/threat-model.md#3-trust-boundaries-model-a-vs-model-b).

## What ships, per platform

Every layer below is on `main` today; the [quickstart](#quickstart) exercises the
first four and `aegis wrap --policy`. **Native OS confinement is Linux-only** — that
qualifier belongs beside any sentence calling Aegis containment, not in a
footnote further down
([ADR-0010](docs/adr/0010-macos-confinement-fast-follows-m4.md)).

| Layer | Linux | macOS |
|---|---|---|
| Policy evaluation — tool id, role and capability axes, sync over a parsed-once `Arc<PolicySet>` | yes | yes |
| Capability grants — default-deny resolution, minted per call | yes | yes |
| Model A cell — a per-call wasmtime `Store` configured from the grant | yes | yes |
| Signed, hash-chained record (`schema_version: 2`), emitted on every exit path | yes | yes |
| `aegis verify` — walks a chain, labelled **pinned** or **unpinned** ([ADR-0004](docs/adr/0004-embedded-key-with-labelled-trust.md)) | yes | yes |
| `aegis recheck` — re-evaluates a record against other rules; executes nothing ([ADR-0008](docs/adr/0008-d2-re-evaluation-is-recheck-not-replay.md)) | yes | yes |
| `aegis wrap --policy` — refuses a `tools/call` with JSON-RPC `-32042` ([ADR-0015](docs/adr/0015-wrap-may-synthesize-a-refusal.md)) | yes | yes |
| `aegis wrap --confine` — Landlock filesystem scoping + a seccomp **network deny-list** | yes | **no** |

Read that last row against [`docs/wrap.md`](docs/wrap.md) before relying on it:
the filesystem half is enforced at the LSM layer, the network half is an
enumerated deny-list whose default action is *allow*, and macOS Seatbelt is
AILAB-630 and is not built.

**Not shipped on any platform**, and deliberately absent from the table:
matching on a call's `arguments` (AILAB-626, canceled — a policy rule matches
tool identity, nothing else), parking a call for human approval (AILAB-629),
pinning a tool schema by hash (AILAB-627), and Landlock `AccessNet` for the
network half (AILAB-810). If you read those in
[ADR-0010](docs/adr/0010-macos-confinement-fast-follows-m4.md), note its
**Not implemented** banner: it records a plan from 2026-08-10, not behaviour.

## Crate map

Ten crates in the workspace (`unsafe_code = forbid` workspace-wide); **eight** are on
crates.io at `0.3.0`:

| Crate | Responsibility |
|---|---|
| `botzr-aegis-core` | Pure types and traits used in enforcement decisions; zero I/O |
| `botzr-aegis-policy` | YAML policy parsed once → `Arc<PolicySet>`; sync evaluation |
| `botzr-aegis-capability` | Default-deny resolver and grant minting (core enforcement IP) |
| `botzr-aegis-sandbox` | wasmtime component-model host; cap-std preopens; resource limits |
| `botzr-aegis-audit` | Schema-versioned audit records, always emitted |
| `botzr-aegis-runtime` | Orchestrator — walks the pipeline (`Runtime::execute_tool_call`) |
| `botzr-aegis-mcp` | Phase 2 [MCP stdio gateway](crates/botzr-aegis-mcp/README.md) — Aegis's own catalog, not an interposer |
| `botzr-aegis-wrap` | Transparent stdio MCP interposer — always **records**; confines the child only with `--confine` (Linux) and evaluates policy only with `--policy`. Default wrap relays every call and blocks nothing. In-tree; not on crates.io at `0.3.0`. See [`aegis wrap`](crates/botzr-aegis-cli/README.md#aegis-wrap--interpose-and-record) |
| `botzr-aegis-confine` | Linux Landlock + seccomp derived from a grant; `UnsupportedConfiner` everywhere else. Depends on `core` only. In-tree; not on crates.io at `0.3.0` |
| `botzr-aegis-cli` | Binary `aegis` — `run`, plus `keygen` / `verify` / `recheck` / `wrap` on `main` |

`governance/` is a **separate Python (Layer 2) service** — audit ingest, narrow-only
policy proposals, drift findings, and versioned policy packs. It is not a workspace
member and never writes into the Rust runtime. See
[`governance/README.md`](governance/README.md).

## Quickstart

Requires Rust (MSRV 1.86) with the `wasm32-wasip2` target and
[`cargo-component`](https://github.com/bytecodealliance/cargo-component) for the WASM
fixtures:

```bash
rustup target add wasm32-wasip2
cargo install cargo-component
```

Run the full workspace gate:

```bash
cargo test --workspace
```

Coverage is gated by a ratchet: CI fails any change that drops total line
coverage below the committed high-water mark in
[`coverage/baseline.json`](coverage/baseline.json). Requires
[`cargo-llvm-cov`](https://github.com/taiki-e/cargo-llvm-cov):

```bash
./scripts/coverage.sh report   # measure and print totals
./scripts/coverage.sh check    # what CI runs — fail on any drop vs baseline
./scripts/coverage.sh bump     # raise the baseline after improving coverage
```

If `check` fails, the fix is normally to add tests. A drop can be legitimate —
deleting or refactoring heavily tested code — in which case the baseline is
hand-edited **in the same PR**, with a rationale; `bump` will not lower it.
[`docs/coverage-ratchet.md`](docs/coverage-ratchet.md) documents that procedure,
the float tolerance, and the provenance fields.

Execute one Model A tool call from the CLI (registers the echo fixture, walks the
full pipeline, writes audit JSONL):

```bash
# A persistent record file is signed by a key you provision — once, per host.
cargo run -p botzr-aegis-cli -- keygen --out /tmp/aegis-signing.key
# stdout: public_key <hex> / key_id <hex>

cargo run -p botzr-aegis-cli -- \
  run \
  --component tests/fixtures/echo-tool/echo.wasm \
  --id echo \
  --input 'hello' \
  --audit /tmp/aegis-audit.jsonl \
  --signing-key /tmp/aegis-signing.key
# stdout: hello
# inspect Intent + Outcome lines in /tmp/aegis-audit.jsonl
# then pin them: cargo run -p botzr-aegis-cli -- verify --key <public_key> /tmp/aegis-audit.jsonl
```

Interpose on a stdio MCP server and **refuse** one `tools/call`. This beat needs a
clone: crates.io `0.3.0` has neither `wrap` nor `keygen` (see [Status](#status)).

```bash
# From a clone of `main`. crates.io 0.3.0 cannot do this.
cargo build -p botzr-aegis-cli -p botzr-aegis-mcp --release

# A policy that denies the tool `echo` and allows everything else.
cat > /tmp/deny-echo.yaml <<'EOF'
version: 1
default: allow
rules:
  - id: deny-echo
    action: deny
    tool: echo
    reason: "632 quickstart"
EOF

./target/release/aegis keygen --out /tmp/aegis-signing.key
# stdout: public_key <hex> / key_id <hex>

# One `tools/call` named `echo`, piped into wrap. The child here is Aegis's own
# MCP gateway standing in for any stdio MCP server — substitute yours after `--`.
printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{"text":"hi"}}}' \
  | ./target/release/aegis wrap \
      --audit /tmp/wrap-audit.aarl \
      --signing-key /tmp/aegis-signing.key \
      --policy /tmp/deny-echo.yaml \
      -- ./target/release/botzr-aegis-mcp \
           --audit /tmp/gateway-audit.aarl \
           --signing-key /tmp/aegis-signing.key
# client stdout is the refusal, not the echo body:
# {"error":{"code":-32042,"data":{"aegis":{"code":"POLICY_DENIED","layer":"wrap"}},
#  "message":"aegis wrap refused this tools/call"},"id":1,"jsonrpc":"2.0"}

./target/release/aegis verify --key <public_key printed by keygen> /tmp/wrap-audit.aarl
# Verified (pinned to <key_id>)
```

Drop `--policy` and the same command relays the call and prints the `echo` result:
**default wrap records and blocks nothing**, and `--policy` is the whole opt-in.

**Two record files, on purpose.** Wrap keeps the record of the call it *carried*;
the gateway keeps the record of the call it *executed*. Pointing both at one path
would interleave two Chains and neither would verify — the invariant
[`crates/botzr-aegis-mcp/tests/wrap_interop.rs`](crates/botzr-aegis-mcp/tests/wrap_interop.rs)
holds. Here `/tmp/gateway-audit.aarl` records no call at all, because the refused
frame never reached the child. Records use the `.aarl` extension
([ADR-0014](docs/adr/0014-the-record-file-extension-is-aarl.md)).

**`aegis verify` without `--key` prints `Verified (unpinned)`** — internal
consistency only, not provenance. An attacker who rewrites a whole Session signs
it with their own key and an unpinned walk comes out clean. A bare "Verified" that
does not say which is the overclaim
[ADR-0004](docs/adr/0004-embedded-key-with-labelled-trust.md) exists to prevent.

**What this beat is not.** Wrap runs nothing inside wasmtime, so it is **not**
Model A isolation — it is closer to Model B and weaker than either, because the
effect executes in a child process wrap does not control. `--policy` matches on
**tool identity**, never on `params.arguments`, and mints no capability, so even an
allowed call records the `deny_all` pass-through grant. `--confine` is a separate
flag, Linux-only, answering a different question. A chain that abuses a
*legitimate* tool on this same server is not refused here and is not in scope
(D5). [`docs/wrap.md`](docs/wrap.md) carries the full list before you describe
wrap as a sandbox, a firewall, or a guard.

Reproduce the adversarial containment demo (a deliberately malicious `wasip2` guest
driven through the full pipeline):

```bash
./scripts/build-fixtures.sh          # builds the DamageBot guest wasm
cargo test -p aegis-adversarial-demo # write-under-readonly, .. traversal, symlink escape, http exfil — all refused
```

Reproduce the hot-path benchmarks (policy eval and capability resolution only):

```bash
cargo bench -p botzr-aegis-policy -p botzr-aegis-capability -p botzr-aegis-runtime
```

Published results, on an AMD Ryzen AI 5 340 under WSL2 with Criterion 0.5.1:
`policy_eval/multi_rule` at **31.8 ns** (rustc 1.96.0, 2026-07-09) and
`hot_path/multi_rule` at **263.4 ns** (rustc 1.86.0, 2026-09-07, after path
canonicalization moved to registration). Both figures, their toolchains and the
before/after tables are in
[`benches/results/hot_path.md`](benches/results/hot_path.md).

Quote the second one carefully: `hot_path` is **stations 1–2 only — not what a
call costs**. An audited call end to end is
[`benches/results/cell_and_audit.md`](benches/results/cell_and_audit.md) —
**32.9–37.4 µs** against the shipped Volatile sink, and **2.86–17.5 ms** against a
Durable one, published as a range because the durable arm spread 6.1× across two
sessions and has no reproducible median. Interposing has its own file,
[`benches/results/wrap_overhead.md`](benches/results/wrap_overhead.md): **4.371 ms**
per recorded `tools/call` against an informational 0.5–2 ms budget — **a ~2.19×
miss**, and the honest outcome rather than a regression, because two `sync_all`
calls cost ~4.2 ms on that filesystem on their own. A merely relayed message is
**136.05 µs**. This box swings
±20% on identical binaries, so every digit here is provisional; the quiet-machine
re-baseline is AILAB-796.

## Evidence

These in-repo artifacts support the claims above. They demonstrate specific
containment cases and measured costs — they do not certify the instrument.

| Artifact | What it shows |
|---|---|
| [Docs book](docs/) | Stranger-facing hub (mdBook). `cd docs && mdbook build` — CI fails the PR if the book does not compile |
| [Threat model](docs/threat-model.md) | Scope, trust boundaries, named non-goals, residual risks |
| [Findings report](docs/findings.md) | What isolation is measured to guarantee — and not; five reproducible case studies, bundled via [`scripts/evidence-bundle.sh`](scripts/evidence-bundle.sh) |
| [OQ-15 Part B review](https://github.com/botzrDev/aegis/issues/19) | Structured packaging peer review (solo-maintainer exception logged) |
| [Record format spec](spec/SPEC.md) | `schema_version: 2` wire contract — line types, hash chain, JCS canonical form, signatures, verdicts, Envelope boundary, non-guarantees |
| [Audit schema freeze](docs/audit-schema.md) | Superseded: the `schema_version: 1` wire contract, kept as a record |
| [`SECURITY.md`](SECURITY.md) | Private disclosure process and in-scope crates |
| [DamageBot demo](examples/damage-bot-demo/README.md) | Six adversarial cases refused through `Runtime::execute_tool_call` (Model A + Model B) |
| [Stage 2 demo](tests/stage2-demo/README.md) | A minimal `wasip2` path detector through the full pipeline; native-vs-wasm equivalence scorecard |
| [Hot-path benchmarks](benches/results/hot_path.md) | Policy ≪ 100 µs; combined hot path ≪ 1 ms, on cited hardware ([bench notes](benches/README.md)) |
| [MCP gateway](crates/botzr-aegis-mcp/README.md) | Out-of-process MCP stdio gateway (research scaffold, not a production firewall) |
| [MCP live-deny cast](docs/demos/README.md) | Watchable reproduction: an `exfil` call refused with `POLICY_DENIED`, the `schema_version: 2` record that refusal wrote, and `aegis verify` over it — [replay the cast](docs/demos/mcp-live-deny.cast) or run it live with [`scripts/mcp-live-deny-demo.sh`](scripts/mcp-live-deny-demo.sh) |

## Status

The enforcement pipeline is wired and tested end-to-end; demos, benchmarks, the threat
model, and the [findings report](docs/findings.md) are published. The current release is
[**`v0.3.0`**](https://github.com/botzrDev/aegis/releases/tag/v0.3.0) — the first
lockstep release, in which all eight crates carry the same version. It adds a fuzz
harness over the policy YAML parse surface, a stress suite proving audit exactly-once
under concurrency, and supply-chain gates. The published `0.3.0` CLI has one
subcommand, `aegis run`, for one-shot WASM execution through the pipeline.

Four more verbs exist on `main` and reach the registry with the next cut:
`aegis keygen` (mint a signing key), `aegis verify` (walk a record chain,
labelled pinned or unpinned), `aegis recheck` (re-evaluate recorded outcomes
against a different policy — it executes nothing), and `aegis wrap` (interpose
on a stdio MCP server and **record** every `tools/call`). Default wrap relays
everything and blocks nothing; `--policy <YAML>` is an opt-in under which a
denied `tools/call` is refused with JSON-RPC `-32042`
([ADR-0015](docs/adr/0015-wrap-may-synthesize-a-refusal.md)), and `--confine`
is a separate Linux-only opt-in that restricts the child process. None of them
mints a capability.

Eight crates are published on [crates.io](https://crates.io/search?q=botzr-aegis) at
`0.3.0` — `core`, `policy`, `capability`, `sandbox`, `runtime`, `audit`, `mcp`, `cli` —
and the dependency graph resolves, so the **`run`-only `0.3.0` binary** installs
directly:

```sh
cargo install botzr-aegis-cli   # the 0.3.0 binary: `aegis run`, and nothing else
```

That binary cannot `wrap`, cannot `keygen`, and writes `schema_version: 1` records
— unsigned, with no `seq` / `prev_hash` chain — so today's `aegis verify` has
nothing to check in one. The hash-chained, signed schema v2 this repository
describes arrives with the next cut, which is not dated here.

`botzr-aegis-wrap` and `botzr-aegis-confine` are in-tree and are **not** on
crates.io at `0.3.0`; both first appear on the next cut, which publishes **ten**
crates ([`docs/release-checklist.md`](docs/release-checklist.md)). Until then,
build them from [`main`](https://github.com/botzrDev/aegis) — that is what the
[wrap beat above](#quickstart) does, and `cargo install botzr-aegis-cli` is not a
substitute for it. Building from `main` or the tag is also what you want for the
in-repo demos and benchmark harnesses.

Earlier releases were a split set — `core` at 0.2.0, `sandbox` at 0.1.1, the other six at
0.1.0. From 0.3.0 the whole workspace moves as one version; see the versioning note in
the [CHANGELOG](CHANGELOG.md). A retired name, `botzr-aegis-sidecar`, is yanked:
the Phase 2 gateway is MCP over stdio, so use `botzr-aegis-mcp` instead. Do not
confuse that gateway (Aegis's own catalog) with `aegis wrap` (an interposer in
front of someone else's server).

## Contributing

Setup, the gates CI enforces, and the invariants a reviewer will check are in
[`CONTRIBUTING.md`](CONTRIBUTING.md). Participation is governed by the
[Code of Conduct](CODE_OF_CONDUCT.md).

**Security vulnerabilities do not go in the issue tracker** — follow
[`SECURITY.md`](SECURITY.md).

If you cite Aegis in published work, [`CITATION.cff`](CITATION.cff) carries the
metadata; GitHub renders it as a "Cite this repository" button in the sidebar.

## License

Dual licensed under either of

- Apache License, Version 2.0 — [`LICENSE-APACHE`](LICENSE-APACHE) or
  <http://www.apache.org/licenses/LICENSE-2.0>
- MIT license — [`LICENSE-MIT`](LICENSE-MIT)

at your option. [`LICENSE`](LICENSE) is the pointer to both. Unless you state
otherwise, any contribution you intentionally submit for inclusion in this work,
as defined in Apache-2.0, is dual licensed as above with no additional terms.

Apache-2.0 is here for its explicit patent grant, which matters most for the
[Agent Action Record spec](spec/SPEC.md) — a format nobody should have to adopt
on a handshake. See
[ADR-0011](docs/adr/0011-dual-apache-2.0-or-mit-supersedes-oq1.md).

**The `0.3.0` crates on crates.io are MIT as published** and stay that way — a
published registry tarball cannot be relicensed. The dual license applies to this
repository and to every release cut after `0.3.0`.
