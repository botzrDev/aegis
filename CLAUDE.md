# CLAUDE.md

Guidance for Claude Code when working in the **Aegis** repository.

## What this project is

**Aegis** is a research instrument for testing and publishing novel discoveries in secure agent tool execution (Rust, wasmtime). It sits *underneath* agent frameworks — not an orchestrator, not a dashboard, not an LLM layer.

One-liner: *"A reproducible runtime for testing what agent tool isolation actually guarantees."*

Every tool call walks the same pipeline, in this order (load-bearing — do not reorder):

```
POLICY → CAPABILITY → SANDBOX → AUDIT (wraps all three)
```

**Status:** M1 scaffold landed (AEG-4). Pipeline is wired and tested end-to-end. CLI and sidecar are stubs.

**License:** MIT (confirmed 2026-07-05, OQ-1 closed). See `LICENSE`.

## Private planning context (local only)

Strategic docs live in **`aegis-context/`** — gitignored, never commit this folder.

Before scope, sequencing, or architecture decisions, read (locally):

| File | Role |
|---|---|
| `aegis-context/AEGIS — MASTER PRD.md` | Scope + build order |
| `aegis-context/(CURRENT) Hardened Implementation Design & Anti-Patterns.md` | Crate graph, pipeline, anti-patterns |
| `aegis-context/BUILD_PLAN.md` | Sprint backlog |
| `aegis-context/MEMORY.md` | Agent memory index |

Session memory: `~/.claude/projects/-home-austingreen-Documents-botzr-projects-aegis/memory/MEMORY.md`

For sprint planning / Linear backlog work, invoke the **`aegis-scrum`** skill (`~/.claude/skills/aegis-scrum/`).

## v1 scope (locked)

Build exactly five runtime components:

1. **`botzr-aegis-sandbox`** — wasmtime 36.x, component-model-native (`wasip2`), cap-std preopens
2. **`botzr-aegis-capability`** — default-deny resolver, grant minting (core IP)
3. **`botzr-aegis-policy`** — YAML, parsed once → `Arc<PolicySet>`, sync eval (<100 µs target)
4. **`botzr-aegis-audit`** — schema-versioned records, always emitted (including deny/trap/panic)
5. **Resource accounting** — epoch + memory limiter per call

**Out of v1:** multi-agent orchestration, dashboards, crypto audit proofs, Layer 2 governance, SaaS hosting, support for every tool/LLM.

## Planned crate layout

```
aegis/                          # GitHub repo: botzrDev/aegis; product name: Aegis
├── Cargo.toml                  # workspace; unsafe_code = forbid
├── crates/
│   ├── botzr-aegis-core/       # pure types/traits, zero I/O
│   ├── botzr-aegis-policy/
│   ├── botzr-aegis-capability/
│   ├── botzr-aegis-sandbox/
│   ├── botzr-aegis-audit/
│   ├── botzr-aegis-runtime/    # orchestrator (library mode entry)
│   ├── botzr-aegis-sidecar/    # Phase 2 — UDS gRPC/HTTP
│   └── botzr-aegis-cli/        # binary name: aegis (crates.io prefix avoids aegis-cli conflict)
├── wit/tool-world.wit
└── tests/                      # deny-suite + integration
```

**Crates.io namespace:** `botzr-aegis-*` (OQ-14 closed 2026-07-05). Do not publish unprefixed `aegis-*` crates.

Pin wasmtime in `[workspace.dependencies]` — whole workspace moves as one.

## Rust conventions

- **`unsafe_code = forbid`** workspace-wide
- **Default-deny** everywhere — no ambient authority
- **cap-std preopens** for fs scoping — never hand-rolled `path.starts_with`
- **Per-call `Store`** — never share mutable wasmtime state across calls
- **Host functions (Model B):** each must enforce the grant before the effect; sandbox gives zero protection for host-side effects
- **No uveddi code in this repo** — CC-BY-NC-SA; reimplement from design references only (MIT provenance)
- **Audit on every exit path** — denials and traps are first-class records

## Two trust models (never conflate)

- **Model A — WASM tool:** logic runs inside wasmtime; strong isolation
- **Model B — host function:** effect runs in host Rust; capability check + audit only

Docs and marketing must be blunt that Model B is not full sandbox isolation.

## Development workflow

```bash
# When the workspace exists:
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo bench   # Criterion — publish with hardware/OS cited
```

Commit signing uses SSH (`id_ed25519`). If commit fails on signing, unlock with `ssh-add`.

## Commit gate

**Do not run `git commit` / `git push` / `git add` unless Austin explicitly asks for this task.** Stage changes, show the diff + proposed message; Austin runs the commit. Read-side git (`status`, `diff`, `log`) is always fine.

## North star for planning

**Path to credible v1:** enforcement pipeline wired → one real tool E2E → published findings (reproducible demo + benchmarks + threat model). Research instrument — not a commercial product; no marketing/sales gates in the engineering track.
