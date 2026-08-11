# Governance test fixtures — audit schema v2

Two kinds of file live here, and the difference matters when you reuse one.

## Verbatim emitter output

Byte-identical to `crates/botzr-aegis-audit/tests/golden/*.json`, in canonical
form (key-sorted, whitespace-free, SPEC §3.1). Real lines, real digests, real
signatures, a real hash chain.

| File | Contents |
|---|---|
| `intent.json` | the golden `intent` line (`call-golden-0`, `smoke`) |
| `capability_denied.json`, `pending_approval.json`, `policy_deny.json`, `rate_limit.json`, `resource_exceeded.json`, `trap.json` | one golden `outcome` each |
| `sample.jsonl` | the golden intent + 6 golden outcomes |
| `session_v2.jsonl` | a whole Session, seq 0–11: `open` → `intent` → 8 `outcome` → `decision` → `close` |

`session_v2.jsonl` is the only file here whose chain is intact end to end.
Prefer it whenever a test needs something that is genuinely what the runtime
writes.

## Synthetic

Hand-built, because no golden has the shape the test needs — a widening grant,
a repeated rate limit, a reserved or unknown line type. Field shapes are v2 and
the digests are well-formed (64 lowercase hex), but they are **placeholders**:
`prev_hash` chains to nothing, signatures sign nothing, and files start
mid-Session with no `open` line.

| File | Why it cannot be a golden |
|---|---|
| `capability_creep.jsonl` | needs one tool's grant to widen across two calls |
| `rate_spike.jsonl` | needs the same tool rate-limited three times |
| `anomalous_allow_deny.jsonl` | needs one tool allowed 3× then denied 3× |
| `unknown_line_types.jsonl` | `checkpoint` is reserved and no emitter produces one (SPEC §5.1); an unrecognised type has no emitter by definition |

**Do not use the synthetic files to test verification.** Governance never walks
a chain or checks a signature (see `../../README.md`, "Parsing is not
verifying"), which is the only reason placeholder chain values are acceptable
here. A verifier test — `aegis verify`, AILAB-621 — needs real chained output;
`session_v2.jsonl` or the Rust goldens are the sources for that.

Regenerating the verbatim files means re-copying from
`crates/botzr-aegis-audit/tests/golden/`, not editing them in place: a
hand-edited golden line is no longer emitter output, and one edited field
(a `call_id`, a digest) silently breaks the chain it sits in while still
looking real.
