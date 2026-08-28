# The record file extension is `.aarl`

**Status:** accepted (2026-08-28) · lands in AILAB-623 · closes the question ADR-0008 left open

Agent Action Record files are written with the extension **`.aarl`**. Every example in `spec/SPEC.md`, in `docs/` and in the CLI README that previously wrote the placeholder `session.<ext>` now writes `session.aarl`.

This **closes** a question rather than overturning one, and it supersedes nothing. ADR-0008 settled the prose name and left the extension unresolved on purpose — in the same breath it ruled `.aar` out and named `.aarl` as a proposal, because the name and the extension are separate decisions and only the first was ripe. 0014 is the second half of a split 0008 made deliberately.

## Why `.aarl`

The case against `.aar` belongs to ADR-0008 and is not re-argued here: it is the Android Archive format, so claiming it means editors and `file` misidentify records as zip archives while searches for the format spec return Android results indefinitely.

What this decision adds is the diligence that argument implies but 0008 did not perform — checking that the replacement is actually free:

- **`.aarl` is unclaimed.** Searched 2026-08-28: no established format uses it. The nearest neighbour is `.arl` — one letter shorter, a different string, and itself a grab-bag with no dominant owner (Microsoft Compound File in roughly a quarter of uses, JSON and ZIP in the rest). There is no incumbent to inherit a collision from.
- **It passes the test `.aar` failed.** A search for `.aarl` returns this format rather than someone else's ecosystem. Searchability is the whole reason `.aar` was rejected, so a replacement that failed the same test would be no improvement.
- **It signals the shape.** The trailing `l` reads as JSON **L**ines, which is what §1.1 of the spec says the file is.

## The options

Only two were live, and this ADR does not manufacture a third:

- **`.aar`** — unavailable, for ADR-0008's reasons above.
- **Leave it unspecified**, which is what the `session.<ext>` placeholder encoded. Tenable on the merits, since nothing parses the name — but it leaves every example writing a placeholder and every reader inventing a spelling, which is how two incompatible conventions start. The spec's own header called the placeholder a debt due at AILAB-623.

## Consequences

- **The prose name is untouched.** "Agent Action Record" is ADR-0008's decision and stands. The soft collision with *after-action report* is a property of the acronym, not of the extension; this decision neither creates it nor fixes it.
- **The extension is a convention, not a wire fact.** Nothing in the format is carried by the filename. `aegis verify` and `aegis recheck` accept any path and validate no extension, deliberately — a verifier that rejected a record for its name would be enforcing a convention the format does not state as a MUST. That behaviour is unchanged here and should stay unchanged.
- **ADR-0008 still writes `session.<ext>`, and stays that way.** It recorded correctly that the extension was open on the day it was written. An ADR is not revised once reality moves past it, so the note under the table in `docs/adr.md` points a reader here instead — the same handling ADR-0001's stale `aegis replay` already gets.
- **Reversible until a filename ships in a release.** No committed record, golden vector or parser depends on the spelling, so changing it costs a documentation sweep and nothing else. It stops being cheap once `0.4.0` publishes examples a reader copies.
