# Approval parks the MCP request, not the audit record

**Status:** accepted (2026-08-10) · lands in AILAB-629, touches AILAB-619 and AILAB-622

A `PendingApproval` policy decision closes its audit record **immediately** — the park is an outcome line carrying `PolicyOutcome::PendingApproval`, exactly as shipped. What parks is the JSON-RPC response inside the interposer. The human verdict is a new `Decision` line, and a resumed call is a **new Call** with its own intent and outcome, cross-referenced by `approval_id`.

AILAB-629's own text anticipated this: *"If G2's reasoning still holds for the in-process runtime, the right answer may be that parking lives only in the interposer while the library keeps reject-with-token."* It does. The library keeps G2 unchanged; only the interposer parks.

## Why the alternative was rejected

The obvious reading of report §6.5 — hold the `CallSession` open across the human's decision — couples two lifetimes that have no reason to be coupled. The shipped pipeline already treats `PendingApproval` as terminal (`pipeline.rs:75`): it takes the not-allowed branch, marks capability denied and execution not-executed, completes the session, and returns `AegisError::PendingApproval` with a minted id. The evaluation is *over*. Reopening it to await a human buys nothing and costs:

- **A manufactured denial.** A held-open session that dies at process exit writes an outcome describing the runtime's lifecycle (`session ending`, `session abandoned`) rather than anything about the request.
- **A conditional `Drop` guarantee.** The exactly-once guard becomes contingent on a state machine that can outlive the process.
- **Nothing gained on timeouts.** An MCP client timeout still abandons a live session.

Under the decoupled model a client timeout discards a held response and touches no evidence. Worst case the file records a park and a decision and no execution — an accurate account of what happened.

## Consequences

- **One new line type, not two.** `Decision` — a human verdict, with no intent and no execution. "Park" is not a line type; it is an `Outcome` carrying `PendingApproval`, which has shipped since v1.
- **Two linkage kinds with different strengths**, and SPEC.md must state both:
  - `intent ↔ outcome` is a **hard invariant, Session-scoped**, guaranteed by the `Drop` guard plus the borrow that makes the writer outlive every `CallSession`. Violation inside a closed Session is a structural error.
  - `approval_id ↔ decision` is a **soft cross-reference** that may span Sessions and files. A human approving after a restart is normal.
- **Three verifier rules follow.** A `PendingApproval` outcome with no `Decision` is legal (informational). A `Decision` for an absent `approval_id` is legal (informational — parked in an earlier file). **Two `Decision` lines for one `approval_id` is a structural violation**, exit 1, same class as a chain break, because a correct emitter cannot produce it.
- **The `Decision` line records the granted scope, not just the verdict.** 629 requires the approver be shown *"what authority approval would grant"*; that authority belongs in the record. Approval without recorded scope is a blank check in the evidence. The resumed call's grant must then be a subset of the approved scope — §6.6's delegation-only-narrows rule applying to human approvals for free.
- **Unmatched-intent is a consistency cross-check, not a tamper signal.** Interior deletion is already `Tampered` via `prev_hash`. What the invariant adds is catching a buggy emitter, and catching a rewriting attacker who holds the signing key but drops an outcome sloppily. SPEC.md must not claim more.
- **AILAB-622 gains a verdict and a field.** `RecheckVerdict::NewlyParked` (written `ReplayVerdict` when this was decided; the command was renamed hours later by [ADR-0008](./0008-d2-re-evaluation-is-recheck-not-replay.md)) — replaying against a policy that newly requires approval is not "newly blocked", because a human might have approved. And `approval_ref` is a **decision input**, so under [ADR-0001](./0001-aar-chain-and-envelope.md) it belongs in the Chain; without it, replaying a resumed call cannot reconstruct why it was allowed.
- **A park timeout is required regardless.** 629's AC already demands defined timeout and denial paths. It is a feature of any answer here, not a competing one.
