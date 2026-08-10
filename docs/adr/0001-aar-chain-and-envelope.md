# Agent Action Records split into a signed Chain and an optional Envelope

**Status:** accepted (2026-08-09) · lands in AILAB-619

The Agent Action Record must satisfy two consumers with different trust audiences: `aegis verify`, run by a stranger on a record they were handed, and `aegis replay`, run by an operator on their own machine after an incident. We split the record into three tiers and put the seam between the second and third: the signed **Chain** carries integrity fields (`seq`, `prev_hash`, `policy_set_hash`, `grant_id`, outcomes, `signature`) *and* the Decision Axes (`tool_id`, `capability`, `role`, `session`, `matched_rule`, `request_digest`); verbatim request bytes live in a separate, optional, content-addressed **Envelope** keyed by `request_digest`.

This resolves a contradiction inside the Execution Report: §6.3 specifies a digest-only record, while §6.4 requires a record to carry "the request" so policy can be re-evaluated offline.

## Considered options

**Arguments inline in the signed record** — rejected on one disqualifying property: secrets in a signed record are unredactable. Once a credential lands in an argument and the record is signed, the only removal mechanism is invalidating the chain. An evidence format whose sole redaction path is destroying the evidence cannot be handed to auditors, and the format is the durable asset (report §2, thesis 2). Mechanically it also fsyncs the full payload ahead of execution — `AuditWriter::append_line` flushes and `sync_all`s every line, and `CallSession::begin` emits the intent line before the sandbox runs — against a §7 target of 50µs per record.

**Digest-only, re-scope `aegis replay`** — correct for the code as it exists and wrong one milestone later. `PolicyRequest` is four scalars with zero argument introspection today, so digest-only replay works completely; AILAB-626 then adds argument matchers and breaks the format. A format that breaks between its first two releases does not get adopted, and §10.4 makes adoption the thesis.

**Defer to AILAB-641** — inverts a dependency: 641 is Medium under R0 research, 619 is Urgent and blocks all of D2.

## Consequences

- **Today's record is already insufficient for replay for a reason unrelated to arguments.** It persists `tool_id` but not `capability`, `role`, or `session`, so a recorded deny cannot reproduce or explain its own verdict. Those three axes join the Chain in the same schema v2 bump.
- **`matched_rule` gets recorded.** It is computed in `policy/src/engine.rs`, commented "for the audit trail", and currently has zero consumers outside policy-crate tests. Recording it turns a replay diff from a verdict flip into an explanation.
- **`aegis replay` ships chain-only.** Because the Decision Axes are in the Chain, AILAB-622 can meet its acceptance criteria before the Envelope exists, and SPEC.md test vectors are replayable by third parties without shipping anyone's private paths.
- **The Envelope is conditionally required.** Whether payload is needed is a static property of the Policy Set being replayed against. Inspect it first; demand the Envelope only for Calls an argument-constraining rule could match. That set is empty today.
- **Superseded in part by [ADR-0006](./0006-matchers-target-derived-capability-parameters.md).** Matchers target *derived capability parameters*, not raw JSON, so those parameters are decision axes and live in the Chain. Replay therefore works chain-only even after AILAB-626 lands, and the Envelope is purely forensic. The conditional logic above stays correct but should almost never fire.
- **Replay needs a fourth verdict.** `Indeterminate { MissingEnvelope | EnvelopeDigestMismatch | UnknownPolicySetHash }`, never folded into "unchanged" — exhaustive `match` is what forces every future reason to be handled at compile time.
- **Envelope entries are verbatim bytes.** `request_digest` is SHA-256 over raw input (`runtime/src/pipeline.rs:65`), so an Envelope writer that pretty-prints JSON silently breaks the link. The spec must say "verbatim". This is also what makes an unsigned local Envelope trustworthy: hash on load, compare against the signed digest, and the signature transitively authenticates the payload.
- **Digest fields get newtypes.** Three bare `[u8; 32]` fields in one constructor cannot catch a transposition, and a chain that hashes the policy set into `prev_hash` verifies clean while being wrong. `PrevHash` / `PolicySetHash` / `RequestDigest` over a shared `Digest` make transposition a compile error, and retire today's `input_digest: String`.
- **REPLAY absorbs this without touching the published format.** The Envelope is the seam the event journal grows into — the journal is the Envelope made complete and always-on, and D2 records become a signed projection over it. AILAB-641 should record that rather than re-decide it.
- **Open within this decision:** whether the Chain covers `AuditIntent` lines or only outcome lines. The writer serialises concurrent calls through a `Mutex`, so intent and outcome lines for one Call are not adjacent — any chain must be per appended line with `prev_hash` computed under the same lock as the append, not per Call.
