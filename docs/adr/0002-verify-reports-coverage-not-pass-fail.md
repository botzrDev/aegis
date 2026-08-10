# `aegis verify` reports coverage, not pass/fail

**Status:** accepted (2026-08-10) · lands in AILAB-619 (format) and AILAB-621 (matrix)

Because only outcome lines carry signatures ([ADR-0001](./0001-aar-chain-and-envelope.md)), content beyond the last signature is unverifiable by construction, and truncating a Chain leaves an internally consistent Chain. **Truncation is therefore not detectable from the Chain alone** — it is detectable only by an *Anchor* that asserts content exists beyond a point. So `aegis verify` returns a three-state verdict computed from Coverage (the highest `seq` covered by a valid signature) plus Anchor presence: `Verified`, `Indeterminate` with a typed reason, or `Tampered`.

Exit codes pin as **0** verified, **1** tampered, **2** could-not-read, **3** indeterminate. These become API the moment anyone scripts against them.

## Why not binary

**Fail on any unverified tail** alarms on healthy systems. The obvious case is a crash, but the common one is a *live file*: the D3 interposer appends continuously, so verifying a running session always shows an uncovered tail. A gate that fires on every in-progress file is noise within a week.

**Pass with a warning on stderr** is the option to actively rule out. Exit 0 is what every CI gate and every `if aegis verify; then` actually reads; a warning is invisible to all of them. An evidence tool whose machine-readable answer is "fine" for a truncated file reproduces the report §1 critique — *logs you must trust the vendor about* — inside our own verifier.

## Consequences

- **The undecidable set is one Session, not every Session.** The Session-open line carries `prev_session_tail`, back-referencing the previous Session's final hash. Truncating any non-final Session contradicts a later signed open — that is `Tampered`, detected, with no external witness. Only the final Session's tail, with no Anchor beyond it, is undecidable. This is a materially better property to publish than "we cannot detect truncation."
- **The verdict must not be computed from "is there a close record".** Anchors are close records, later Session-opens, and (reserved) Checkpoints. Coverage-plus-Anchor generalises correctly across the crash case, the multi-Session case, and the live-file case; a close-record boolean does not.
- **The unverified tail can contain only intent lines** plus at most one torn final line, since every outcome line is signed. An **outcome line in the tail is a stripped signature — `Tampered`**, not a crash. A trailing unparseable line is a torn write — `Indeterminate`, with a reason distinct from "no close record".
- **Exit-3 output names the in-flight Calls.** The tail is always a set of Calls that were in progress; three intents for workspace reads is a shrug, one intent for `net.post` is where an operator starts looking.
- **Unknown line types cap the verdict at `Indeterminate`.** An unrecognised line still hashes — it is bytes, the Chain stays valid — but a verifier must never report `Verified` over content it does not understand, or a future emitter can smuggle anything past an old auditor. This is the format's whole extensibility story and it has to be decided at v0.1.
- **The verdict is deterministic**: same bytes, same verdict, always. Asserted as a property, not a test case.
- **D3 will need `--live` / `--allow-open-tail`.** Not scoped now — let D3 ask for it — but the verdict model has to leave room.
- **`Drop` does not run on SIGKILL.** Close-on-drop covers clean exit and unwind only. That gap is precisely what produces exit 3, and the SPEC.md threat-model section must state the tail-truncation non-guarantee plainly.
