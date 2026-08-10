# D2's re-evaluation command is `aegis recheck`, not `aegis replay`

**Status:** accepted (2026-08-10) · lands in AILAB-622 · edits Execution Report §6.4

AILAB-622 takes a recorded session plus a new policy set, re-evaluates every recorded decision, and emits a would-block diff. **It executes nothing.** That is not a replay, and calling it one promises effects that do not re-run. The command is `aegis recheck --policy new.yaml session.<ext>` — the extension is deliberately unresolved here, because `.aar` is ruled out below.

This was framed initially as a namespace collision with REPLAY's `aegis replay` (AILAB-677, R2), to be solved by nesting D2's verbs under the spec name. That was the wrong diagnosis. The two operations were never competing for one verb — one of them was wearing the other's name. REPLAY's operation genuinely is a replay; D2's is a policy what-if against a record.

## Why not namespace instead

Nesting (`aegis aar verify` / `aegis aar replay`) preserves the misnomer behind a longer path, and costs three things:

- **It splits record verbs across two levels.** `aegis verify session.<ext>` is the D4 exit criterion — the first thing a stranger types. Leaving `verify` top-level while nesting `replay` makes operation location unpredictable; moving `verify` down too lengthens the flagship command exactly where discoverability matters most.
- **It reserves the best verb for work that may never ship.** R2 is 12–24 months out and the direction decision says REPLAY phases do not become sprint scope without an explicit call. Paying UX cost in D2 to hold a name for that is speculative.
- **Its main benefit is already delivered by the file extension.** Every invocation reads `… session.<ext>`, so the format's name is taught by the filename a user types a dozen times. No verb nesting required.

Nesting also would have left two operations on one verb dispatched by file type — implicit dispatch that is surprising when it works and confusing when it does not.

## Consequences

- **This is the same overclaim discipline as the rest of D2.** Exit 0 on an unanchored file, "verified" for an internally-checked chain, an audit record claiming confinement the kernel did not apply — and a verb promising effects that do not re-run. The CLI verb is the most-read surface in the product.
- **`reeval` is the fallback** if `recheck` reads too casually for auditors. **Avoid `simulate`** — REPLAY §14 Mode E already claims it, and using it here recreates this collision one layer down. **Avoid `audit`**, already a pipeline station name.
- **Cheap now, expensive later.** 622 is unstarted and report §6.4's `aegis replay --policy new.yaml` is a one-line edit. After a published README it is a breaking rename.
- **The spec name is decoupled and stays with the PM** (report §11.4). "Agent Action Record" is a sound prose name and, critically, **vendor-neutral** — a competitor can emit Agent Action Records without endorsing us; nobody would emit "Aegis Records." That property is what §11.4 is really protecting.
- **`.aar` must not be the file extension.** It is the Android Archive format — a hard collision, because it is an extension we would be claiming. Editors and `file` will misidentify records as zip archives, GitHub's language detection is already trained on it, and searches for the format spec return Android results indefinitely. `.aarl` signals both the acronym and the JSONL shape. The prose name and the extension are separate decisions.
- **After-action report** is a soft collision — same letters, and in audit circles it denotes a human-written retrospective. Survivable in prose; noted so the pitch does not lean on the acronym alone.
