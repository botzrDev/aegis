# Aegis

A runtime that executes untrusted agent tool calls under deterministic containment and emits a verifiable record of every call. It sits underneath agent frameworks; it is not one.

## Language

### The pipeline

**Call**:
One tool invocation travelling the full `POLICY → CAPABILITY → SANDBOX → AUDIT` pipeline.
_Avoid_: request, invocation, execution

**Policy Set**:
The parsed, immutable rule collection a Call is evaluated against, held as `Arc<PolicySet>`.
_Avoid_: policy file, ruleset, config

**Grant**:
The minted authority a Call executes under, derived by narrowing a parent grant; never ambient.
_Avoid_: permission, capability (the axis), scope

**Decision Axes**:
The inputs a policy verdict is a function of — `tool_id`, `capability`, `role`, `session`, `approval_ref`, and the **derived capability parameters** (the `fs` path, `net` host/port the runtime resolved the call to). Never the raw argument tree. Every Decision Axis lives in the Chain, because replay needs it.
_Avoid_: policy inputs, request context, arguments

**Binding**:
A per-tool declaration of which argument position supplies which capability axis — `read_file{path}` and `slurp{file_path}` both bind to `fs.read`. What lets one rule cover every tool. New manifest surface; `ToolManifest` declares static needs today, not bindings.

**Model A**:
A tool whose logic runs inside wasmtime. Strong isolation.

**Model B**:
A tool whose effect runs in host Rust. Capability check and audit only — **not** sandbox isolation, and docs must say so plainly.

**Confiner**:
The mechanism that narrows the calling process to a `ConfinementProfile` and reports what the kernel actually enforced. Linux (Landlock + seccomp) is one impl; the Unsupported one refuses every profile.
_Avoid_: backend, sandbox (that is the pipeline stage), jail

### The evidence

**Agent Action Record (AAR)**:
The signed, hash-chained record of one Call's decision and outcome. The artifact third parties emit and verify.
_Avoid_: audit log, log line, event (see Flagged ambiguities)

**Chain**:
The ordered, signed sequence of AARs whose integrity `aegis verify` checks. Publishable by construction — it carries verdicts and Decision Axes, never raw payloads.
_Avoid_: audit trail, ledger

**Envelope**:
The optional, local, content-addressed store of verbatim request bytes, keyed by `request_digest`. Never signed; authenticated transitively by the digest inside the signed Chain. **Purely forensic** — replay does not need it, because matchers target Decision Axes rather than raw arguments.
_Avoid_: payload store, blob store, sidecar

**Session**:
One writer lifetime over one Chain file — opened when the `AuditWriter` is constructed, closed on its `Drop`. Owns the chain state (`seq`, tail hash) behind the same lock as the file handle. A file may hold many Sessions.
_Avoid_: run, connection, process

**Sink**:
Where a Session's Chain bytes land, and whether they are retained — **Durable** (fsynced and still present after the process exits) or **Volatile** (the bytes die with the process). The default Sink is Volatile and in-memory: `Runtime::default()` builds a `MemoryChainSink`, so a run given no `--audit` leaves nothing behind. A Durable Sink requires a provisioned signing key; only a Volatile one may be signed by `insecure_dev_key`.
_Avoid_: backend, store, destination, output

**Anchor**:
Any signed line that proves content exists beyond a given point — a close record, a later Session's `prev_session_tail` back-reference, or a Checkpoint. Absence of an Anchor is what makes a tail undecidable.

**Coverage**:
The highest `seq` covered by a valid signature. Every verify verdict is computed from Coverage plus Anchor presence, never from "is there a close record".

**Recheck**:
Re-evaluating a recorded session's decisions against a different Policy Set and reporting the delta. Offline, deterministic, and **executes nothing** — which is why it is not called replay.
_Avoid_: replay, simulate, re-run

**Indeterminate**:
A verdict meaning the question could not be decided from the evidence — an unverified tail, a torn write, an unknown line type, a missing Envelope, a digest mismatch. A first-class outcome with a distinct typed reason per case, never folded into "unchanged" or "verified".

## Relationships

- A **Call** produces exactly one **AAR**, on every exit path including deny, trap, and panic
- An **AAR** links to at most one **Envelope** entry, by `request_digest`
- A **Session** contains many **Calls**; a Chain file contains many **Sessions**
- A **Session** writes to exactly one **Sink**; only a Durable Sink can carry an **Anchor** forward, because a later Session's `prev_session_tail` needs the earlier tail to still exist
- A **Chain** verifies *and replays* without any **Envelope**
- A **Binding** turns a tool's arguments into **Decision Axes**; without one, a call cannot be resolved to a capability
- A **Policy Set** governs a **Call**; its hash is recorded in the **AAR** so the verdict is reproducible
- **Model A** and **Model B** both emit **AARs**; only Model A is contained by the sandbox
- Every outcome line is signed, therefore an unverified tail can contain **only intent lines** plus at most one torn final line — an unsigned outcome line in the tail is tampering, not a crash

## Example dialogue

> **Dev:** "If the **Chain** carries no arguments, how does `aegis replay` re-run a path-prefix rule?"
> **Austin:** "It doesn't need the arguments. A rule matches the **Decision Axes**, and the resolved path is one of them — so `deny fs.read under ~/.ssh` is one rule that covers every tool, whether it calls the argument `path` or `file_path`. The **Envelope** is for a human reading the raw call afterwards, not for replay."
> **Dev:** "So what's ever **Indeterminate**?"
> **Austin:** "A tail we can't verify, a torn line, a line type we don't know, a policy set hash we can't account for. Never folded into 'unchanged' — a forensic tool that reports a clean diff on a session it couldn't evaluate is worse than one that refuses."

## Flagged ambiguities

- ~~**"replay" means two different operations.**~~ **Resolved:** D2's operation is **Recheck** (`aegis recheck`) — re-evaluate recorded decisions against a new Policy Set, executing nothing. Bare `replay` is reserved for REPLAY's re-execution (R2 / AILAB-677), which genuinely re-runs effects. The verb was the overclaim, not the namespace.
- ~~**`.aar` is not available as a file extension.**~~ **Resolved (AILAB-623):** the extension is **`.aarl`**, decided in ADR-0014 on 2026-08-28 and now written by every example in `spec/SPEC.md`, `docs/` and `crates/botzr-aegis-cli/README.md`. `.aar` stays ruled out — it is the Android Archive format, so editors and `file` misidentify records as zip archives. `.aarl` was checked for a pre-existing claim before it was taken and found unclaimed, and its trailing `l` reads as JSON Lines, which is what the file is. The prose name "Agent Action Record" was never in question (ADR-0008) and is unchanged; "AAR" still softly collides with *after-action report* in audit usage, which is a property of the acronym and not of the extension. Nothing parses the name: `aegis verify` and `aegis recheck` accept any path, deliberately.
- **"digest" means two different things.** `PolicySet.digest` is FNV-1a over YAML text, self-documented at `policy/src/parse.rs:213` as "not a security digest"; `input_digest` is SHA-256 over raw bytes. The `policy_set_hash` field in the AAR cannot reuse the former. Partly resolved by the proposed newtypes (`PrevHash`, `PolicySetHash`, `RequestDigest`).
- **"record" is ambiguous between line and decision.** Resolved: the **Chain** covers every appended line (intent, outcome, open, close, and the reserved checkpoint); **AAR** names the signed outcome line. `seq` is per line, not per Call.
- ~~**"Every Decision Axis lives in the Chain" is not true for Model A.**~~ **Resolved (AILAB-708):** `execute_tool_call` built its own `PolicyRequest` from the tool id, so a Model A Call carried no `capability`, `role`, or `session` — a role-scoped `deny` could not fire for a Model A Call, and a Model A AAR recorded those axes as absent, indistinguishable from "structurally unreachable". The entry point now takes a `ToolCallRequest` carrying a caller-supplied `PolicyRequest`, mirroring `HostCallRequest`, so both trust models reach the same axes and record them. The absent-axis rule (`policy/src/set.rs:62-64`) is unchanged and still correct: an axis a caller does not assert does not match. `session` remains an evidence axis only — it is not a **Matcher** field.
- ~~**"the audit path" implies retention the default Sink does not have.**~~ **Resolved (AILAB-702):** `aegis` and `aegis run` printed `Audit: <path>` for the default Volatile Sink over a directory removed when the process exited — verified 2026-08-14 against the shipped `0.3.0` binary (`Audit: /tmp/.tmpF0SEZX/audit.jsonl`, gone on exit), which pointed the operator at a file they could not read. The default Sink is now in-memory (`MemoryChainSink`) and says so: it names no path, and the banner reads `Audit: (volatile sink — records are not retained)`. A Volatile Sink names no path because its bytes are unreachable by construction; `--audit <PATH>` with `--signing-key <PATH>` is what produces a Durable one.
- **"event" belongs to REPLAY, not to Aegis today.** The REPLAY event journal (`RunStarted`, `ToolRequested`, …) is a different, larger model. Do not call an AAR an event.
