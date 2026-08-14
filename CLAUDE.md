# CLAUDE.md

Guidance for Claude Code when working in the **Aegis** repository.

## What this project is

**Aegis** is a research instrument for secure agent tool execution (Rust, wasmtime) and — long horizon — an **execution substrate** for trustworthy autonomous software (working name **REPLAY**: debugger / simulator / security runtime). It sits *underneath* agent frameworks — not an agent framework, not a SaaS dashboard, not an LLM layer.

Near-term one-liner: *"A reproducible runtime for testing what agent tool isolation actually guarantees."*

Every tool call walks the same pipeline, in this order (load-bearing — do not reorder):

```
POLICY → CAPABILITY → SANDBOX → AUDIT (wraps all three)
```

**Status (2026-08-14):** M0–M4 complete; **`v0.3.0` published** — signed tag `e232d19`, **eight** crates on crates.io. `botzr-aegis-wrap` and `botzr-aegis-confine` landed after the tag and have **never been published**, so the next cut is their first release. Live board:

- **D3 is the critical path** — AILAB-627 (schema pinning), 629 (approval), 697 (where `EnforcedConfinement` lands in the Chain). 627 and 629 are unspecced; 697 is PM-blocked.
- **Architecture tranche AILAB-701…709** (24 pts) — decided 2026-08-14, sits ahead of D3. See `aegis-context/design/architecture-deepening-review-2026-08-13.md` § *Grill outcome*.
- **~41 REPLAY tickets (R0–R10) are parked** behind an R0 exit and an Austin pull. They are **not** sprint scope. Long-horizon vision is `aegis-context/REPLAY.prd.md` — do **not** invent sprint scope from REPLAY phases without ticketed R0+ work and an Austin direction call.

**License:** dual `Apache-2.0 OR MIT` (ADR-0011). The crates published to crates.io at `0.3.0` carry **MIT** in their registry metadata and stay MIT as published — never restate that as dual. See `LICENSE`.

## Which document wins

When two sources disagree, this is the order:

1. **The code.** `spec/SPEC.md` says so itself: *"where this document and the code disagree, the code is the defect report."*
2. **`spec/SPEC.md`** — the Agent Action Record format, schema v2. It *implements* ADR-0001…0006, so it outranks them on format questions.
3. **`docs/adr/`** — thirteen accepted decisions. An ADR that is decided-but-unbuilt carries a **Not implemented** banner above the fold and a `no` in the `docs/adr.md` table. Keep both honest; an ADR records a decision and is never quietly revised when reality disagrees.
4. **`CONTEXT.md`** — the domain glossary (Call, Policy Set, Grant, Decision Axes, Binding, Model A/B, AAR, Chain, Envelope, Session, Sink, Anchor, Coverage, Recheck, Indeterminate). Use these words exactly, and don't reach for the synonyms it lists under *Avoid*. Its *Flagged ambiguities* section carries known gaps between the vocabulary and the code — read it before asserting how something works.

`docs/` is a **flat** mdBook: `security.md`, `cli.md`, `adr.md`, `terminology.md` and friends live at `docs/` root. There is no `docs/guide/` — any spec or ticket citing that path is stale.

## Private planning context (local only)

Strategic docs live in **`aegis-context/`** — gitignored (`.gitignore:1`), never commit this folder.

Before scope, sequencing, or architecture decisions, read (locally):

| File | Role |
|---|---|
| `aegis-context/REPLAY.prd.md` | Long-horizon north star (does not schedule tickets alone) |
| `aegis-context/decisions/REPLAY-direction-2026-08-09.md` | Binding direction decisions |
| `aegis-context/AEGIS — Execution Report.md` | Near-term elevated mission (D1–D5) |
| `aegis-context/AEGIS — MASTER PRD.md` | Near-term scope + build order |
| `aegis-context/(CURRENT) Hardened Implementation Design & Anti-Patterns.md` | Crate graph, pipeline, anti-patterns |
| `aegis-context/BUILD_PLAN.md` | Sprint backlog |
| `aegis-context/design/` | Architecture reviews and proposals — **proposals, not decisions** |
| `aegis-context/assignments/` | Paired-dev-loop specs; `README.md` is the live queue |
| `aegis-context/MEMORY.md` | Agent memory index |

Session memory: `~/.claude/projects/-home-austingreen-Documents-botzr-projects-aegis/memory/MEMORY.md`

For sprint planning / Linear backlog work, invoke the **`aegis-scrum`** skill (`~/.claude/skills/aegis-scrum/`).

**Linear:** team **Botzr-AI-Labs** (key `AILAB`), project AEGIS. Legacy `AEG-*` IDs map to `AILAB-*` (e.g. AEG-44 → AILAB-135). Prefer `AILAB-*` for live issues. Two write gotchas: bodies with backticks, pipe tables or unusual glyphs get Cloudflare-blocked — use plain prose; and bare filenames autolink (`foo.rs` becomes a URL), so always cite the full repo-relative path.

## Enforcement scope (locked)

Five components carry enforcement:

1. **`botzr-aegis-sandbox`** — wasmtime 36.x, component-model-native (`wasip2`), cap-std preopens
2. **`botzr-aegis-capability`** — default-deny resolver, grant minting (core IP)
3. **`botzr-aegis-policy`** — YAML, parsed once → `Arc<PolicySet>`, sync eval (<100 µs target)
4. **`botzr-aegis-audit`** — schema-versioned records, always emitted (including deny/trap/panic)
5. **Resource accounting** — epoch + memory limiter per call

The edge crates (`mcp`, `wrap`, `confine`, `cli`) wire these up; they do not add enforcement of their own, and `wrap` deliberately depends on nothing below `audit` + `core`.

**Out of locked scope:** multi-agent orchestration, dashboards, crypto audit proofs, SaaS hosting, support for every tool/LLM. Layer 2 governance lives in-repo under `governance/` as a separate Python service (not a Cargo workspace member).

## Crate layout

```
aegis/                          # GitHub repo: botzrDev/aegis; product name: Aegis
├── Cargo.toml                  # workspace; unsafe_code = forbid; fuzz/ excluded
├── crates/
│   ├── botzr-aegis-core/       # pure types/traits, zero I/O
│   ├── botzr-aegis-policy/
│   ├── botzr-aegis-capability/
│   ├── botzr-aegis-sandbox/
│   ├── botzr-aegis-audit/
│   ├── botzr-aegis-runtime/    # orchestrator (library mode entry)
│   ├── botzr-aegis-mcp/        # MCP stdio gateway
│   ├── botzr-aegis-wrap/       # stdio interposer; depends only on audit + core
│   ├── botzr-aegis-confine/    # OS confinement (Landlock/seccomp); depends only on core
│   └── botzr-aegis-cli/        # binary name: aegis
├── spec/SPEC.md                # the AAR format — the durable asset
├── docs/                       # flat mdBook (no docs/guide/); docs/adr/ holds the ADRs
├── governance/                 # Layer 2 Python service (not a workspace member)
├── fuzz/                       # cargo-fuzz sibling (nightly); never promote to members
├── wit/aegis/tool/             # canonical WIT (+ deps); wit/deps/ is generated/ignored
└── tests/                      # deny-suite, adversarial, stress, api-surface, demos
```

**Crates.io namespace:** `botzr-aegis-*` (OQ-14 closed 2026-07-05). Do not publish unprefixed `aegis-*` crates. All crates version in lockstep from `[workspace.package]`.

Pin wasmtime in `[workspace.dependencies]` — whole workspace moves as one.

## Rust conventions

- **`unsafe_code = forbid`** workspace-wide. If a spike shows a dependency makes that impossible, escalate — do not reach for `unsafe`.
- **Default-deny** everywhere — no ambient authority
- **cap-std preopens** for fs scoping — never hand-rolled `path.starts_with`
- **Per-call `Store`** — never share mutable wasmtime state across calls
- **Host functions (Model B):** each must enforce the grant before the effect; sandbox gives zero protection for host-side effects
- **No uveddi code in this repo** — CC-BY-NC-SA; reimplement from design references only (MIT provenance)
- **Audit on every exit path** — denials and traps are first-class records
- **Fuzz targets follow shipped parse surfaces** — never add product API only to satisfy a hardening ticket
- **`test-utils` features are the gate for test-only API** (`sandbox`, `capability`, `runtime` have one). `tests/api-surface` asserts nothing in a default build enables them — the absence *is* the assertion

## Claim integrity

The strongest house norm. It governs records, docs, demos and benchmarks alike:

- **The record states what was *enforced*, not what was asked for** (ADR-0007). `e92450a` exists because `seccomp_applied: true` was recorded for a filter that denied nothing.
- **A claim ships with its evidence.** Benchmarks publish with hardware and OS cited. A demo that blocks one attack class names the classes it does **not** block, in the same breath.
- **Unbuilt decisions say so.** Present tense in docs means shipped behaviour; anything else carries a banner.
- **When a test harness builds its own version of what the product must supply, the suite is testing the harness.** Grep new test helpers for locally-defined constants that ought to come from the crate.

## Two trust models (never conflate)

- **Model A — WASM tool:** logic runs inside wasmtime; strong isolation
- **Model B — host function:** effect runs in host Rust; capability check + audit only

Docs and marketing must be blunt that Model B is not full sandbox isolation. Note the current asymmetry, tracked as AILAB-708: Model A carries no `role`/`capability` axis, so role-scoped rules silently do not apply to it.

## Development workflow

```bash
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo bench                            # Criterion — publish with hardware/OS cited
./scripts/coverage.sh                  # ratchet against coverage/baseline.json
./aegis-context/scripts/check-assignment-refs.sh   # must pass before queuing any spec
```

Deny/demo package names (not directory names): `aegis-deny-suite`, `aegis-adversarial-demo`, `aegis-stage2-demo`, `aegis-api-surface`, `aegis-stress-suite`, `aegis-integration-tests`.

A single workspace flake aborts `coverage.sh` before it prints totals, reddening the coverage job. `RUST_TEST_THREADS=1` unblocks a measurement.

Commit signing uses SSH (`id_ed25519`). If commit fails on signing, unlock with `ssh-add`.

## Commit gate

**Do not run `git commit` / `git push` / `git add` unless Austin explicitly asks for this task.** Stage changes, show the diff + proposed message; Austin runs the commit. Read-side git (`status`, `diff`, `log`) is always fine.

Never move or republish an existing tag. `v0.1.0` and `v0.3.0` are immutable.
