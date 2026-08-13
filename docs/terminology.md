# Terminology

Words the project uses on purpose. Using a listed *avoid* term in docs or
APIs is how two incompatible meanings collapse into one.

## The pipeline

**Call.** One tool invocation travelling the full
`POLICY → CAPABILITY → SANDBOX → AUDIT` pipeline.
*Avoid:* request, invocation, execution.

**Policy Set.** The parsed, immutable rule collection a Call is evaluated
against, held as `Arc<PolicySet>`.
*Avoid:* policy file, ruleset, config.

**Grant.** The minted authority a Call executes under, derived by narrowing
a parent grant; never ambient.
*Avoid:* permission, capability (the axis), scope.

**Decision Axes.** The inputs a policy verdict is a function of, carried
in the record's `decision_axes` object (`DecisionAxes` in
`botzr-aegis-core`). Exactly seven fields: `capability`, `role`,
`session`, `matched_rule`, `approval_ref`, and the **derived capability
parameters** `fs` and `net`. Never the raw argument tree. Every field is
optional and omitted rather than nulled, so `{}` means "this emitter
recorded no axes". Every Decision Axis lives in the Chain, because
[recheck](#recheck) needs it.

`tool_id` is **not** inside `decision_axes` — it sits on the record line
itself, next to the verdict, so it is not repeated.

`fs` and `net` are recorded today, but they describe the **grant the call
resolved under**, not a caller-supplied argument. Both follow the same
exactly-one-or-omit rule: `fs` carries the grant's single preopen root and is
omitted when a grant names more than one; `net` carries a single host and port
and is omitted when the grant holds more than one HTTP entry *or* that entry
names more than one port. An arbitrary one of N would be evidence that reads
as fact and is not.

The shipped emitter writes the same string into `path_raw` and
`path_canonical` — the pair exists because the two diverge once a caller path
is resolved *against* that root. That is a property of this emitter, not of
the format: [SPEC.md §5.3](spec.md) states them as independent fields, and its
test vector carries divergent values deliberately. *Matching* on these axes is
not shipped
([ADR-0006](adr/0006-matchers-target-derived-capability-parameters.md)).
*Avoid:* policy inputs, request context, arguments.

**Binding.** A per-tool declaration of which argument position supplies
which capability axis — `read_file{path}` and `slurp{file_path}` both bind
to `fs.read`. **Not shipped.** `ToolManifest` declares static needs today,
not bindings.

**Model A / Model B.** See [Trust models](trust-models.md). Docs must say
plainly that Model B is not sandbox isolation.

## The evidence

**Agent Action Record (AAR).** The signed, hash-chained record of one Call's
decision and outcome. The artifact third parties emit and verify. The file
extension is not specified yet (`.aar` is the Android Archive format).
*Avoid:* audit log, log line, event.

**Chain.** The ordered, signed sequence of AARs whose integrity
`aegis verify` checks. Publishable by construction — it carries verdicts
and Decision Axes, never raw payloads.
*Avoid:* audit trail, ledger.

**Envelope.** The optional, local, content-addressed store of verbatim
request bytes, keyed by `request_digest`. Never signed; authenticated
transitively by the digest inside the signed Chain. **Purely forensic** —
recheck does not need it. No Envelope code ships in this version.
*Avoid:* payload store, blob store, sidecar.

**Session.** One writer lifetime over one Chain file — opened when the
`AuditWriter` is constructed, closed on its `Drop`. A file may hold many
Sessions.
*Avoid:* run, connection, process.

**Anchor.** Any signed line that proves content exists beyond a given point
— a close record, a later Session's `prev_session_tail` back-reference, or
a Checkpoint. Absence of an Anchor is what makes a tail undecidable.

**Coverage.** The highest `seq` covered by a valid signature. Every verify
verdict is computed from Coverage plus Anchor presence, never from "is
there a close record".

<a id="recheck"></a>

**Recheck.** Re-evaluating a recorded session's decisions against a
different Policy Set and reporting the delta. Offline, deterministic, and
**executes nothing** — which is why it is not called replay. Command:
`aegis recheck`. Bare `replay` is reserved for a future re-execution
engine that genuinely re-runs effects.
*Avoid:* replay, simulate, re-run.

**Indeterminate.** A verdict meaning the question could not be decided from
the evidence — an unverified tail, a torn write, an unknown line type, a
missing Envelope, a digest mismatch. Never folded into "unchanged" or
"verified".

## Relationships

- A **Call** produces exactly one **AAR**, on every exit path including deny, trap, and panic
- An **AAR** links to at most one **Envelope** entry, by `request_digest`
- A **Session** contains many **Calls**; a Chain file contains many **Sessions**
- A **Chain** verifies and **rechecks** without any **Envelope**
- **Model A** and **Model B** both emit **AARs**; only Model A is contained by the sandbox
- Every outcome line is signed, therefore an unverified tail can contain **only intent lines** plus at most one torn final line
