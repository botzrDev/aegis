# Architecture decision records

Decisions that constrain the record format, the CLI verbs, and what the
docs are allowed to claim. An ADR records what was decided *when*; later
renames are noted in place rather than silently rewritten.

**An accepted ADR is a decision, not a ship receipt.** Several below are
written in the present tense and describe behaviour that does not exist
yet; "lands in AILAB-\*" means the work is ticketed, nothing more. Check
the code or the git tag, not the Status line. The **Shipped?** column
below answers for current `main` — the published `0.3.0` binary is a
narrower surface still ([CLI](cli.md)).

| ADR | Title | Shipped? |
|---|---|---|
| [0001](adr/0001-aar-chain-and-envelope.md) | Agent Action Records split into a signed Chain and an optional Envelope | partial — Chain ships; no Envelope store or I/O |
| [0002](adr/0002-verify-reports-coverage-not-pass-fail.md) | `aegis verify` reports coverage, not pass/fail | yes |
| [0003](adr/0003-jcs-json-canonical-form.md) | JCS JSON is the canonical form, over a constrained value space | yes |
| [0004](adr/0004-embedded-key-with-labelled-trust.md) | The signing key is embedded, and `aegis verify` labels its trust level | yes |
| [0005](adr/0005-approval-parks-in-the-interposer-not-the-audit-chain.md) | Approval parks the MCP request, not the audit record | partial — record half ships; no interposer park, no production caller |
| [0006](adr/0006-matchers-target-derived-capability-parameters.md) | Argument matchers target derived capability parameters, not raw JSON | **no** |
| [0007](adr/0007-confinement-via-self-restricting-re-exec.md) | Confinement applies via a self-restricting re-exec, and needs no `unsafe` | **no** |
| [0008](adr/0008-d2-re-evaluation-is-recheck-not-replay.md) | D2's re-evaluation command is `aegis recheck`, not `aegis replay` | yes |
| [0009](adr/0009-d4-reproduces-a-cross-boundary-chain.md) | D4 reproduces a cross-boundary exfiltration chain, not a same-server one | no — demo not built |
| [0010](adr/0010-macos-confinement-fast-follows-m4.md) | macOS confinement fast-follows M4; it does not gate it | **no** |
| [0011](adr/0011-dual-apache-2.0-or-mit-supersedes-oq1.md) | The workspace and the spec are dual `Apache-2.0 OR MIT`; this supersedes OQ-1 | yes — crates.io `0.3.0` metadata stays MIT |
| [0012](adr/0012-the-audit-sink-is-a-seam-that-declares-retention.md) | The audit sink is a public seam that declares its own retention | yes |
| [0013](adr/0013-verify-and-recheck-share-a-classifier-not-a-walk.md) | Verify and Recheck share a line classifier, not a walk | yes |
| [0014](adr/0014-the-record-file-extension-is-aarl.md) | The record file extension is `.aarl` | yes — every example writes it; no code parses an extension, by design |

The bold **no** rows carry an above-the-fold *Not implemented*
banner on the ADR itself. They are kept here, unedited, because an ADR is
a record of a decision — not a page that gets quietly revised once
reality disagrees with it.

ADR-0001 says `aegis replay` throughout. That command was renamed the
same day by ADR-0008. Read every `replay` in 0001 as `recheck`. Left
unedited because an ADR records what was decided when.

ADR-0008 writes `session.<ext>` three times. The extension was genuinely
open when 0008 was written, and 0008 says so in the same sentence that
rules `.aar` out. ADR-0014 later fixed it as `.aarl`. Read every
`session.<ext>` in 0008 as `session.aarl`. Left unedited for the same
reason as 0001.
