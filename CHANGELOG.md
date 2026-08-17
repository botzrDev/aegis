# Changelog

All notable changes to the `botzr-aegis-*` workspace are recorded here. The
format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); the
project versions the whole workspace in lockstep (see the versioning note under
0.3.0).

Aegis is a research instrument. Entries below describe what the instrument
gained or measured, not product claims — see
[docs/findings.md](docs/findings.md) for what the evidence does and does not
support.

---

## [Unreleased]

### Added

- **Trust-store parsing is `botzr-aegis-audit` library API** (AILAB-704).
  `load_trust_store(&Path) -> Result<Vec<PublicKey>, TrustStoreError>` and its
  two-variant `TrustStoreError` (`Read`, `MalformedEntry` with a one-based line
  number) are public beside `load_signing_key`. The dialect was already
  normative — `spec/SPEC.md` § *The `aegis verify` command surface* fixes it —
  but its only implementation was a private function inside the `aegis` binary,
  so the copy under test was not reachable by anyone else and a second reader
  would have had to write a second parser against the same spec paragraph.
  **No behaviour change to `aegis verify`:** same grammar (one 64-lowercase-hex
  public key per line, blank and comment lines skipped, a note trailing a key on
  the same line still malformed), same duplicate-preserving source order, same
  stderr text, same exit codes — 2 for a store that cannot be read, 1 for a line
  that is not a key. No new exit code was added. What deliberately did **not**
  move is the trust *decision*: `load_trust_store` returns keys and nothing
  else, and whether an empty store is still a requested anchor stays a CLI fact,
  because "no anchor was asked for" and "I accept these zero keys" are different
  claims and only the caller knows which the operator made (ADR-0004). It is a
  module of its own rather than part of `keyfile.rs`: public keys and private
  seeds have opposite security properties and deliberately different formats.
  The parser-shape cases move to in-process tests in `botzr-aegis-audit`; the
  CLI suite keeps the empty-store and unreadable-store rows, *gains* a
  malformed-store row (there was none before — the exit-1 half of the mapping
  was untested at the command layer), and keeps one row where a key supplied
  *only* by the store reaches a `Verified (pinned)` label. That last row is
  load-bearing: every other trust-store test asserts a failure, so without it
  the suite stays green even if the parsed keys never reach the trust slice at
  all.
- **Chain line classifier in `botzr-aegis-core`** (AILAB-703, ADR-0013).
  `line_type_field`, `line_type_from_value` and `SessionCounter` are public
  beside `AuditLineType::from_wire`. They carry the two facts `aegis verify` and
  `aegis recheck` genuinely share — how a wire line names its type, including
  schema v1's `phase` spelling, and how Sessions are numbered within a Chain
  file — so a Coverage address printed by one verb names the same Session as a
  diff line printed by the other. **No behaviour change to either verb.** The
  two walks are *not* merged and take no strictness parameter (ADR-0013 rejects
  one for the reason ADR-0012 rejects `durable: bool`): each still owns its
  iteration, error policy and verdict types, and which classifier a walk calls
  is now the visible statement of whether it reads v1 records. `aegis verify`
  calls `line_type_field` and still treats a line with no `line_type` field as
  malformed; `aegis recheck` calls `line_type_from_value` and still reports v1
  `phase: "outcome"` records. Session boundaries continue to come from
  `line_type` alone in both walks, so an `open` line carrying a stray
  `phase: "outcome"` remains a boundary rather than a call. Session numbering
  was previously the same expression written in two files and kept in agreement
  by comments; the comments now cite the shared function instead of being the
  mechanism. AILAB-688 — whether the two walks should agree on *strictness* —
  stays open and is deliberately not answered here.
- **Docs book** — mdBook hub under `docs/` (`book.toml`, `SUMMARY.md`, and
  flat chapter files). Stranger-facing chapters for the pipeline, trust
  models, CLI, wrap (records, does not confine), and policy YAML as it
  ships. Evidence pages (threat model, findings, SPEC, ADRs) are listed in
  the book rather than copied, so their canonical paths do not move.
  Chapter files are flat and grouped only by `SUMMARY.md`;
  [`docs/README.md`](docs/README.md) is the same index for people browsing
  the folder on GitHub. CI job `docs` pins mdBook 0.5.4 and fails the PR if
  `mdbook build` fails.
- **Docs site** — the book is published at <https://botzrdev.github.io/aegis/>
  by a `Pages` workflow that reuses the same pinned mdBook tarball and digest
  as the CI gate, so the deployed site is the artifact CI proved builds.

### Changed

- **The default audit sink is in-memory and retains nothing** (AILAB-702).
  `Runtime::default()` builds a `MemoryChainSink`, which declares
  `Retention::Volatile`. Without `--audit`, `aegis`, `aegis run` and the MCP
  gateway now print `Audit: (volatile sink — records are not retained)` in place
  of a `/tmp/…/audit.jsonl` path. What this fixes: the old default was a temp
  *file* whose directory was deleted at process exit, so the banner named a file
  nobody could open afterwards — verified 2026-08-14 against the shipped `0.3.0`
  binary. The in-memory default is signed by the compiled-in dev key and is not
  retained, so it is not a production record and not evidence; a retained record
  is `--audit <PATH>` together with `--signing-key <PATH>`, and that Durable sink
  refuses the dev key. **Breaking:** `AuditWriter::open_temp` is removed, and so
  is `FileChainSink::temp` — `FileChainSink` is Durable-only. **Added:**
  `AuditWriter::retention() -> Retention`, reporting the sink's own declaration;
  it is cached at construction beside `path()`, and is for embedders and tests —
  both banners still switch on `path()`. Note that the in-memory default Chain
  is uncapped and nothing reclaims it, so a long-lived process left on the
  default holds every line in memory for its lifetime. `tempfile` is no
  longer a production dependency of `botzr-aegis-audit`: it moves to
  `[dev-dependencies]`, where the benches and tests still use it. This completes
  [ADR-0012](docs/adr/0012-the-audit-sink-is-a-seam-that-declares-retention.md),
  whose *Not implemented* banner is removed.
- **The audit sink is a seam that declares its retention** (AILAB-701).
  `botzr-aegis-audit` gains a public `ChainSink` trait, a `Retention`
  declaration (`Durable` / `Volatile`), and two adapters: `FileChainSink` (the
  synchronous append + fsync path, unchanged) and `MemoryChainSink`.
  `AuditWriter::with_sink(sink, key)` is the new constructor; `AuditWriter::open`
  is now a convenience wrapper over a `FileChainSink`. The writer keeps the
  chain rule and its single lock — only *where the bytes land* is pluggable.
  **Breaking:** `AuditWriter::path()` returns `Option<&Path>`, because a sink
  that stores nothing on disk has no path to name. **Breaking:** a Durable Sink
  paired with `insecure_dev_key` is refused at construction with the new
  `AuditError::DurableSinkNeedsProvisionedKey` — `AuditWriter::open(path,
  insecure_dev_key())` now fails, and fixtures that want a real file must supply
  a provisioned key. What this fixes: G3 durability was stated as a property of
  the crate while being a property of one hard-wired `BufWriter<File>`; a Chain
  written to a third-party sink and a Chain fsynced to disk are byte-identical,
  so the declaration is the only thing that can distinguish them. Known and
  documented limit: a sink may declare `Durable` and still report an empty tail,
  which silently unanchors later Sessions and is not detectable from here. This
  slice left the default sink alone; AILAB-702 above is the one that flipped it
  — see
  [ADR-0012](docs/adr/0012-the-audit-sink-is-a-seam-that-declares-retention.md).
- **A Model A call now carries its Decision Axes** (AILAB-708).
  `Runtime::execute_tool_call` takes a `ToolCallRequest { tool_id, input,
  policy }` — the mirror of the `HostCallRequest` Model B has always taken —
  instead of building a tool-identity-only `PolicyRequest` for itself.
  **Breaking:** every caller passes the struct. What this fixes: a rule gated
  on `role` or `capability` could not match a WASM call at all, so one policy
  file was enforced two different ways depending on the trust model, and the
  model with real sandbox isolation was the permissive one. The record
  inherited it — a Model A outcome omitted `role`, `capability` and `session`
  because none of them ever reached the request. `aegis run` and the MCP
  gateway still assert tool identity and nothing else; neither has been told
  who is calling, so the axes are supplied by library callers.
- **Relicensed to dual `Apache-2.0 OR MIT`** (AILAB-634). `[workspace.package]
  license` now reads `Apache-2.0 OR MIT`, so the eight crates published at
  `0.3.0` (and `botzr-aegis-wrap`, in-tree, unpublished until the next cut)
  express it through `license.workspace = true`; root `LICENSE-APACHE` and `LICENSE-MIT`
  hold the two texts and `LICENSE` is the either-or pointer. The Agent Action
  Record spec ([`spec/SPEC.md`](spec/SPEC.md)) carries the same terms — the
  patent grant is the point, because the format is meant to be implemented by
  people who are not us. This **supersedes OQ-1**, which closed MIT-only on
  2026-07-05; see
  [ADR-0011](docs/adr/0011-dual-apache-2.0-or-mit-supersedes-oq1.md).
  **The `0.3.0` crates on crates.io stay MIT as published** — a registry tarball
  cannot be relicensed after the fact, and none were republished or retagged. The
  dual license reaches the registry with the next release cut. No version bump,
  no runtime change.

## [0.3.0] — 2026-08-09

### Added

- **Fuzz harness for the policy YAML parse surface** (AILAB-601). `fuzz/` is a
  sibling cargo project, excluded from the workspace because libFuzzer needs
  nightly while the workspace pins 1.86 with `unsafe_code = forbid`. One target,
  `policy_yaml`, drives `PolicyEngine::from_yaml` and performs exactly one
  `evaluate` on a successful parse; 6 tracked seeds; a weekly bounded smoke run
  in `fuzz-smoke.yml`. First recorded campaign: 10m 30s, 5,893,498 runs, no
  crash — hardware and toolchain cited in [`fuzz/README.md`](fuzz/README.md).
- **Stress suite proving audit exactly-once under concurrency** (AILAB-602).
  `tests/stress` drives one shared `Runtime` from many threads across every
  outcome class and asserts the exactly-once contract by set equality on the
  JSONL sink — one intent and one outcome per call, gap-free call-id sets, every
  outcome parsing as frozen schema v1. No timing assertions.
- **Supply-chain gates** (AILAB-603). `deny.toml` with recorded scope and
  advisory ignores, SHA-pinned GitHub Actions, a weekly advisory-only workflow
  (`advisory.yml`), and an MSRV job running `cargo +1.86 check --workspace
  --locked`.
- **Findings report and evidence bundle** (AILAB-606).
  [`docs/findings.md`](docs/findings.md) synthesizes what the runtime is
  observed to guarantee and what it explicitly does not;
  `scripts/evidence-bundle.sh` reproduces the bounded evidence subset in one
  command, writing a stamped directory with a manifest and per-suite logs.
- **Release artifacts** (AILAB-608). This changelog and
  [`docs/release-checklist.md`](docs/release-checklist.md), which records the
  manual publish order and the standing rules that keep the workspace
  publishable.

### Changed

- **All eight publishable crates reconciled to a single lockstep version**
  (AILAB-608). `botzr-aegis-core` and `botzr-aegis-sandbox` no longer override
  `[workspace.package]`; both now inherit via `version.workspace = true`, and
  every `[workspace.dependencies]` entry declares `0.3.0` alongside its `path`.
- **Corrected the unfuzzed-surface statement in the findings report**
  (AILAB-608). Section 3 previously listed two fuzz surfaces as deferred. Both
  are dropped, because neither exists. Host-argument decoding (the `get_string`
  OOB class) has no in-tree decoder to fuzz — the sandbox is
  component-model-native, so wasmtime lifts host-import arguments before they
  reach Aegis. Capability-manifest deserialization has nothing to parse —
  `ToolManifest` is a Rust builder with no serde implementation and no on-disk
  format. Of the three parse surfaces named in early planning, policy YAML is
  the only one that exists, and it is fuzzed. Tracked as AILAB-604 and
  AILAB-605, both canceled.

### Versioning note

Crate versions are unified at 0.3.0. Version 0.2.0 was a partial release: only
`botzr-aegis-core` was published under it (and `botzr-aegis-sandbox` under
0.1.1), while the rest of the workspace stayed at 0.1.0. Both crates have
changed since, so 0.2.0 could not be reused. From 0.3.0 the whole workspace
moves as one version.

---

## [0.1.0] — 2026-07-16

First packaging release. The four-station enforcement pipeline — POLICY →
CAPABILITY → SANDBOX → AUDIT, with audit wrapping the inner three — wired and
tested end to end, and all eight `botzr-aegis-*` crates published to crates.io.

Note for anyone diffing the tag against the registry: the `v0.1.0` tag
(2026-07-16) predates the manifest publishability fix, so the crates were
published from a later commit (`196ada6`, 2026-07-17). The tag is left where it
is — see the standing rules in
[docs/release-checklist.md](docs/release-checklist.md).

[Unreleased]: https://github.com/botzrDev/aegis/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/botzrDev/aegis/releases/tag/v0.3.0
[0.1.0]: https://github.com/botzrDev/aegis/releases/tag/v0.1.0
