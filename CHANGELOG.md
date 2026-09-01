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

- **Async entry points for both trust models** (AILAB-809).
  `Runtime::execute_tool_call_async` (Model A) and
  `Runtime::execute_host_call_async` (Model B) run the same pipeline —
  same stations, same short-circuits, same Agent Action Record — awaited on the
  caller's tokio runtime instead of blocking on one. An embedder already inside
  a runtime now has a supported way to make a call. The sandbox gained the
  matching `SandboxEngine::execute_async` (and `execute_fixture_async` under
  `test-utils`). There is still exactly one pipeline driver and one execution
  step per trust model: the sync and async entries share both, so they cannot
  drift (AEG-41).

- **`DecisionAxes` fluent construction** (AILAB-798). Seven consuming `with_*`
  setters (`with_capability`, `with_role`, `with_session`, `with_matched_rule`,
  `with_approval_ref`, `with_fs`, `with_net`) on `botzr_aegis_core::DecisionAxes`.
  No new type, no `build()`, fields stay public, `#[non_exhaustive]` is
  unchanged. **Not a break:** assignment still compiles. **No serialized byte
  moves.** This is the recommended construction the AILAB-707 bullet below now
  describes; it is documented here so a reader skimming Added vs Breaking does
  not treat the setters as part of that break.
- **`aegis verify`'s report formatter is tested in process** (AILAB-705).
  `render` and `label` in `crates/botzr-aegis-cli/src/verify.rs` are pure
  functions of a `Verification`, and they now have a fourteen-case
  `#[cfg(test)]` suite that builds verdict values directly: the three `Verified`
  trust spellings (unpinned, pinned to one fingerprint, pinned across a
  rotation), a `Tampered` line, every `IndeterminateReason` this build can meet,
  the `key_id` / `coverage` / `in_flight` sections and their order, and the rule
  that `in_flight` appears under `UnanchoredTail` and nowhere else. Most compare
  the whole report byte for byte; the rest assert a fragment's presence or
  absence. Three of the fourteen had a subprocess counterpart before; the other
  eleven were not covered anywhere. **No behaviour change:** not a byte of the
  report moved, no exit code changed, and the walk was not touched. The
  subprocess matrix in `crates/botzr-aegis-cli/tests/verify.rs` keeps what needs
  a process — the exit code a shell sees, an empty stdout on could-not-read,
  usage errors, the trust-store exit mapping, and which *mechanism* a given
  mutation fires. One row left it: the in-flight report row, whose walker half
  is asserted in `botzr-aegis-audit`'s `verdict.rs` and whose formatter half is
  now asserted in process. Both of those fixtures were changed to feed their
  ids *descending*, because the ascending ones they had could not tell walk
  order from a sort — the property both tests name. What the split does not
  reproduce is the composition through a real binary, and the suite's header
  says so rather than implying otherwise. `botzr-aegis-audit` also gains a
  `test-utils` feature, **off by default and empty**, for parity with `sandbox`,
  `capability` and `runtime`. It gates nothing today and is not a seal:
  `Verification`, `Verdict`, `IndeterminateReason`, `TamperedReason`,
  `TrustLabel` and `Position` all keep public fields and public variants in a
  default build, so every one of them stays constructible by any consumer — the
  feature is the place a future test-only audit API would land, and saying more
  than that would describe a contraction nobody has made. It does not reopen the
  option ADR-0012 rejected: that was a `test-utils`-gated *sink seam* standing in
  for declared Retention, and Retention still ships as the answer there.
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
- **The escape suite tries a route the deny-list does not name** (AILAB-808).
  `crates/botzr-aegis-confine/tests/escape.rs` gains
  `io_uring_egress_with_no_net_grant_is_killed_by_seccomp_sigsys`, which spawns
  a confined child that assembles a network-egress primitive through io_uring —
  `io_uring_setup`, an `io_uring_register` opcode probe confirming the kernel
  advertises `IORING_OP_SOCKET` and `IORING_OP_CONNECT`, then `io_uring_enter` —
  none of which crosses `socket(2)`. It was **observed failing** on the tree
  before the AILAB-807 fix (the confined child exited 0) and passing after it
  (`SIGSYS`). **What it does not do:** put a packet on the wire. Writing the
  submission-queue entry needs `unsafe`, which this workspace forbids, so the
  case proves the ring is unreachable rather than that a connect was stopped
  mid-flight; the 2026-08-25 audit proved the packet half in throwaway C. The
  suite also refuses to run green on a host that cannot use io_uring
  unconfined, since a seccomp kill would otherwise look identical to a kernel
  that never had the feature. The `io-uring` dev dependency is optional and
  gated behind `test-utils`, so it enters no published dependency graph.

### Changed

- **`parse_http_host` refuses an authority that carries userinfo** (AILAB-863).
  **Behaviour change to published API:** the function ships in
  `botzr-aegis-core` on crates.io at `0.3.0`, and a caller outside this
  repository that passes a URL such as `https://api.example.com:8443@evil.com/x`
  now gets `None` where it previously got `api.example.com` — the text in front
  of the first colon, which is the credential half of the authority and not the
  host a client would reach. The signature is unchanged, so the break is one of
  behaviour only. A `@` in a path, query or fragment is untouched: the refusal
  reads the authority slice alone.

  **No enforcement outcome in this repository changes, and no live
  vulnerability was closed.** `http_get_allowed` reads the port-aware
  `parse_http_authority`, which has refused this form since the port allow-list
  landed, and the host-only parser has no caller anywhere in the workspace — so
  nothing in the pipeline ever consulted the wrong answer. The network effect
  behind the check is still a stub; no request is issued either way. What was
  wrong was narrower and worth fixing on its own terms: a published pure
  function in a security crate answered with a name the URL does not resolve
  to, which is the kind of guess the default-deny norm exists to forbid.

- **A call request can no longer name one tool and be judged as another**
  (AILAB-710). **Breaking:** `ToolCallRequest` and `HostCallRequest` carry
  `axes: CallAxes<'a>` in place of `policy: PolicyRequest<'a>`, and their
  `new()` constructors take `CallAxes` in the third position. A caller that
  asserted no axes passes `CallAxes::default()` where it passed
  `PolicyRequest::for_tool(&tool)`; `with_role`, `with_capability` and
  `with_session` carry over unchanged. `PolicyRequest` itself is unchanged and
  remains the input to `PolicyEngine::evaluate` and `PolicyEngine::preview`.

  What was wrong: both request types carried the tool identity **twice** — once
  as their own `tool_id`, which the registry looked up and executed, and again
  inside a caller-supplied `PolicyRequest`, which is what policy actually
  evaluated. Nothing reconciled the two. A request naming `echo` with a
  `PolicyRequest` for `admin.shell` would execute `echo` under `admin.shell`'s
  verdict, and the Agent Action Record would then carry a verdict about a tool
  that never ran. That is the same defect class as `e92450a`, where the record
  claimed an enforcement that had not happened: the record must state what was
  enforced, not what was asked for (ADR-0007).

  What now happens: the runtime derives the `PolicyRequest` from the call
  request's own `tool_id`, in one internal helper shared by all five entry
  points (Model A sync and async, Model B sync and async, and
  `execute_host_call_with`). The caller supplies only the axes it can honestly
  assert — capability, role, session. **The mismatch is not detected, it is
  unrepresentable:** there is no longer a second tool id to disagree with the
  first. A `debug_assert!` comparing the two was considered and rejected
  because it is compiled out of release builds, and an error return was
  rejected because it still lets the contradictory request be built.

- **The synchronous entry points refuse a nested tokio runtime instead of
  panicking, and Model A no longer builds a tokio runtime per call**
  (AILAB-809). **Breaking:** `AegisError` gains a `NestedRuntime { entry }`
  variant, and the enum is exhaustive — any `match` on it outside
  `botzr-aegis-core` must add an arm. (The enum is deliberately *not* marked
  `#[non_exhaustive]` here; that is a separate decision.)

  What was wrong: `SandboxEngine::execute` built a fresh current-thread tokio
  runtime for every call and blocked on it. From inside an existing runtime
  that panicked outright — `Cannot start a runtime from within a runtime` — so
  `Runtime::execute_tool_call` was unusable from any async embedder, and the
  per-call runtime construction was on the hot path for everyone else.

  What now happens: `SandboxEngine` builds **one** tokio runtime in `new()` and
  reuses it. This is not a relaxation of the per-call `Store` rule — a tokio
  runtime holds no guest state, and the wasmtime `Store` is still built per call
  from the resolved grant. `execute_tool_call`, `execute_host_call` and
  `execute_host_call_with` check `Handle::try_current()` and return
  `AegisError::NestedRuntime` **before** `CallSession::begin`, so a refusal
  writes no record: a nested runtime is an embedder integration bug, not a call
  that reached a station, and the Chain must not claim otherwise (ADR-0007). The
  refusal is deliberately not routed through `SandboxError::to_execution_outcome`,
  which would have recorded it as a guest trap. Callers inside a runtime should
  use the `*_async` entries added above.

  Also fixed in the same change: `SandboxEngine` now shuts its runtime down in
  the background on `Drop`. A tokio runtime's own `Drop` blocks to join its
  blocking pool, which tokio refuses inside an async context — so owning one
  would otherwise have traded a call-time panic for a drop-time panic for
  exactly the embedders this ticket is about.

  **What this narrows, stated plainly.** (a) The guard is
  `Handle::try_current()`, which is broader than tokio's rule: a
  `spawn_blocking` thread carries a runtime handle but is not entered as a
  driver, so a sync call from `spawn_blocking` worked at `0.3.0` and now
  refuses — route it through the async entry with
  `Handle::current().block_on(..)`. (b) The `*_async` entries are `async`, not
  non-blocking: the guest gets an epoch *trap* deadline, not an async-yield
  one, and audit's fsync is synchronous, so a call occupies its poll for up to
  `max_wall_ms` plus write latency. (c) Model B handlers now observe a tokio
  runtime context on both entries, so a handler that builds a runtime of its
  own panics where it did not before. (d) Sync calls serialize on the engine's
  runtime mutex; concurrent sync callers no longer overlap. (e) Abandoned
  `spawn_blocking` work (wasmtime-wasi's p2 file I/O, after a mid-write trap)
  is no longer joined at the end of each call, so those bytes can land after
  the record that closed the call.

- **A `tools/call` inside a JSON-RPC batch array is now recorded** (AILAB-788).
  A reader of a wrap chain can believe the file accounts for every `tools/call`
  the session carried, not only those the client sent one per frame: a batched
  call opens the same `intent` and closes with the same `outcome` a single one
  does, and the one-time stderr diagnostic that used to name the hole is gone
  because the record file is the evidence. The batch is still **one frame** on
  each wire — relayed whole and unsplit, never rewritten into per-call frames
  and never refused — so the N calls it carries share its `request_digest` and
  their outcomes share the child array's `response_digest`. That is the verbatim
  rule holding: a batched element never was a frame of its own, and a signed
  record must not commit to bytes that crossed no wire. Wrap still blocks
  nothing and still synthesizes no client-facing error.

- **`DecisionAxes` is `#[non_exhaustive]`, and the three `DEFAULT_MAX_*` grant
  ceilings all live in `botzr-aegis-core`** (AILAB-707). **Breaking:**
  `botzr_aegis_core::DecisionAxes` can no longer be built with a struct
  expression outside the crate that defines it. Note that this includes
  functional-update syntax — `DecisionAxes { role, ..Default::default() }` is
  rejected just as a bare literal is, which is the language rule and not a
  choice made here. The recommended construction is the fluent chain —
  `DecisionAxes::default().with_capability("fs.read").with_role("ops")`, one
  consuming `with_*` setter per axis (AILAB-798). Assignment from
  `DecisionAxes::default()` remains legal, because the fields are all public and
  stay public; nothing else about the type changed. Every emitter in this
  workspace was moved to the chain, and moving off the struct expression is the
  only edit the attribute forced. The reason to close construction now rather
  than at the first new axis: the set is expected to grow — a semantic risk
  score is the live candidate — and an added axis would otherwise be a breaking
  change to every consumer that had ever written one out in full. **This changes
  no serialized byte**: the attribute is a construction rule, the seven axes and
  their omit-never-null encoding are untouched, and every golden fixture on disk
  is unchanged. Separately and **not** a breaking change, `DEFAULT_MAX_WALL_MS`
  and `DEFAULT_MAX_MEMORY_BYTES` move from `botzr-aegis-capability`'s
  `manifest.rs` into `botzr-aegis-core`'s `grant.rs`, joining
  `DEFAULT_MAX_OUTPUT_BYTES` beside the three `CapabilityGrant` fields
  they default — one home, one set of values, unchanged (30 s, 64 MiB, 1 MiB).
  `botzr_aegis_capability::DEFAULT_MAX_WALL_MS` and
  `botzr_aegis_capability::DEFAULT_MAX_MEMORY_BYTES` still resolve, now as
  re-exports, so no consumer of either path breaks and no new capability surface
  is added. `botzr_aegis_core::ResourceCeiling` is documented as the canonical
  import path in `crates/botzr-aegis-core/README.md`; the `botzr-aegis-policy`
  and `botzr-aegis-capability` re-exports of it are published API and stay.
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

### Fixed

- **A confined process could reach the network through io_uring while the
  record said it could not** (AILAB-807). `botzr-aegis-confine`'s seccomp
  filter denied eighteen socket-API syscalls with a default action of *allow*.
  Since Linux 5.19 io_uring dispatches `IORING_OP_SOCKET` and
  `IORING_OP_CONNECT` from submission-queue entries in memory shared with the
  kernel, so they never cross a syscall boundary seccomp can inspect. A child
  under an empty net profile therefore made an outbound TCP connection while
  `EnforcedConfinement` reported `seccomp_network_denied: true` — the same shape
  as `e92450a`, a record asserting an enforcement that did not happen.
  `io_uring_setup`, `io_uring_enter` and `io_uring_register` are now on the
  deny-list. **Behaviour change worth reading before upgrading:** the ring is
  denied *whole*, not just its network operations, because seccomp cannot read
  submission-queue entries and no filter can separate the two. **A child that
  uses io_uring for ordinary file I/O — some databases, some async runtimes —
  will now die on `SIGSYS` under a profile with no `NetGrant`.** Grant it
  `--allow-net` or do not confine it — a second escape case holds that remedy to
  the code, so the documented way out is tested rather than asserted. The
  filesystem side was never affected:
  Landlock enforces at the LSM layer, which io_uring traverses like any other
  caller. The network claim still rests on enumeration; moving it to Landlock
  `AccessNet` is AILAB-810 and is not shipped.

### Removed

- **`botzr-aegis-core` no longer defines or re-exports `ToolKind`** (AILAB-707).
  **Breaking** for anyone importing `botzr_aegis_core::ToolKind`; migrate to
  `botzr_aegis_capability::ToolKind`. The enum was declared twice, byte for byte
  identically, in `botzr-aegis-core`'s `tool.rs` and `botzr-aegis-capability`'s
  `manifest.rs`, and the capability copy is the one every caller in this
  workspace already used — core's had no importer at all, in this repo or in the
  examples. Two identical definitions of the same two-variant enum is exactly the
  shape that lets a third variant land in one of them, and `Wasm` vs `Host` is
  the Model A / Model B split, so a divergence there is not a cosmetic one. The
  variants, their names and their meanings are unchanged; only the path is.

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
