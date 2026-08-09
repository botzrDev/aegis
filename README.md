# Aegis

> **A reproducible runtime for testing what agent tool isolation actually guarantees.**

Aegis is a **research instrument** for secure agent tool execution, built in Rust on
[wasmtime](https://wasmtime.dev/). It sits *underneath* agent frameworks — it is not
an orchestrator, not a dashboard, not an LLM layer. Every tool call walks one
enforcement pipeline, and the runtime emits an audit record on every exit path.

The goal is not to assert that agent tools are safe. It is to make the isolation
claims **falsifiable**: a pipeline you can run, a malicious guest you can point at it,
benchmarks you can reproduce, and a threat model that names its own gaps.

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

## Crate map

Runtime crates (Cargo workspace, `unsafe_code = forbid` workspace-wide):

| Crate | Responsibility |
|---|---|
| `botzr-aegis-core` | Pure types and traits used in enforcement decisions; zero I/O |
| `botzr-aegis-policy` | YAML policy parsed once → `Arc<PolicySet>`; sync evaluation |
| `botzr-aegis-capability` | Default-deny resolver and grant minting (core enforcement IP) |
| `botzr-aegis-sandbox` | wasmtime component-model host; cap-std preopens; resource limits |
| `botzr-aegis-audit` | Schema-versioned audit records, always emitted |
| `botzr-aegis-runtime` | Orchestrator — walks the pipeline (`Runtime::execute_tool_call`) |
| `botzr-aegis-mcp` | Phase 2 [MCP stdio gateway](crates/botzr-aegis-mcp/README.md) |
| `botzr-aegis-cli` | Binary `aegis` — `aegis run` registers a WASM tool and executes through the pipeline |

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

Execute one Model A tool call from the CLI (registers the echo fixture, walks the
full pipeline, writes audit JSONL):

```bash
cargo run -p botzr-aegis-cli -- \
  run \
  --component tests/fixtures/echo-tool/echo.wasm \
  --id echo \
  --input 'hello' \
  --audit /tmp/aegis-audit.jsonl
# stdout: hello
# inspect Intent + Outcome lines in /tmp/aegis-audit.jsonl
```

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

Published results on cited hardware: policy evaluation in tens of nanoseconds and the
combined policy + capability hot path at ~2.7 µs (well under the <1 ms target). See
[`benches/results/hot_path.md`](benches/results/hot_path.md).

## Evidence

These in-repo artifacts support the claims above. They demonstrate specific
containment cases and measured costs — they do not certify the instrument.

| Artifact | What it shows |
|---|---|
| [Threat model](docs/threat-model.md) | Scope, trust boundaries, named non-goals, residual risks |
| [Findings report](docs/findings.md) | What isolation is measured to guarantee — and not; five reproducible case studies, bundled via [`scripts/evidence-bundle.sh`](scripts/evidence-bundle.sh) |
| [OQ-15 Part B review](https://github.com/botzrDev/aegis/issues/19) | Structured packaging peer review (solo-maintainer exception logged) |
| [Audit schema freeze](docs/audit-schema.md) | `schema_version: 1` wire contract (Intent/Outcome); digests + sinks honesty |
| [`SECURITY.md`](SECURITY.md) | Private disclosure process and in-scope crates |
| [DamageBot demo](examples/damage-bot-demo/README.md) | Six adversarial cases refused through `Runtime::execute_tool_call` (Model A + Model B) |
| [Stage 2 demo](tests/stage2-demo/README.md) | A minimal `wasip2` path detector through the full pipeline; native-vs-wasm equivalence scorecard |
| [Hot-path benchmarks](benches/results/hot_path.md) | Policy ≪ 100 µs; combined hot path ≪ 1 ms, on cited hardware ([bench notes](benches/README.md)) |
| [MCP gateway](crates/botzr-aegis-mcp/README.md) | Out-of-process MCP stdio gateway (research scaffold, not a production firewall) |

## Status

The enforcement pipeline is wired and tested end-to-end; demos, benchmarks, the threat
model, and the [findings report](docs/findings.md) are published. The current release is
[**`v0.3.0`**](https://github.com/botzrDev/aegis/releases/tag/v0.3.0) — the first
lockstep release, in which all eight crates carry the same version. It adds a fuzz
harness over the policy YAML parse surface, a stress suite proving audit exactly-once
under concurrency, and supply-chain gates. The `aegis` CLI supports `aegis run` for
one-shot WASM execution through the pipeline.

Eight crates are published on [crates.io](https://crates.io/search?q=botzr-aegis) at
`0.3.0` — `core`, `policy`, `capability`, `sandbox`, `runtime`, `audit`, `mcp`, `cli` —
and the dependency graph resolves, so the CLI installs directly:

```sh
cargo install botzr-aegis-cli
```

Building from [`main`](https://github.com/botzrDev/aegis) or the tag still works, and is
what you want for the in-repo demos and benchmark harnesses.

Earlier releases were a split set — `core` at 0.2.0, `sandbox` at 0.1.1, the other six at
0.1.0. From 0.3.0 the whole workspace moves as one version; see the versioning note in
the [CHANGELOG](CHANGELOG.md). A ninth name, `botzr-aegis-sidecar`, is yanked and
retired: the Phase 2 gateway is MCP over stdio, so use `botzr-aegis-mcp` instead.

## License

MIT — see [`LICENSE`](LICENSE).
