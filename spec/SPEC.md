# Agent Action Record — format specification, schema version 2

**Status:** draft, tracks the code shipped by AILAB-619 · **Schema version:** `2`
**Normative source of truth:** the record types in
[`crates/botzr-aegis-core/src/audit.rs`](../crates/botzr-aegis-core/src/audit.rs),
the canonicalizer in [`crates/botzr-aegis-core/src/jcs.rs`](../crates/botzr-aegis-core/src/jcs.rs),
and the writer in [`crates/botzr-aegis-audit/src/writer.rs`](../crates/botzr-aegis-audit/src/writer.rs).
Where this document and the code disagree, the code is the defect report.

This document specifies a file format, not an implementation. A third party
should be able to write an emitter or a verifier from it. Everything stated as
MUST is checked somewhere in this repository; everything this format does *not*
guarantee is stated as plainly as everything it does. That asymmetry is
deliberate — an evidence format that overclaims is worse than no format, because
the overclaim is what gets quoted.

The decisions behind this format, with the options that were rejected and why,
are in [`docs/adr/`](../docs/adr/) — ADR-0001 through ADR-0006 are the ones this
document implements.

**Not specified by this version, deliberately:**

- The record file's name and extension (AILAB-623). Examples below write
  `session.<ext>`. Do not infer an extension from anything here.
- Key lifecycle — where a private key lives, its permissions, how it is
  generated. Deliberately **out of the format** (ADR-0004), not merely deferred:
  what a Line carries is a `key_id` and a published `public_key`, and a verifier
  needs nothing else. The implementation is specified in
  [`crates/botzr-aegis-audit/README.md`](../crates/botzr-aegis-audit/README.md).
  Rotation is the one part that *is* format surface, and it is normative in §8.4.
- Envelope reader/writer behaviour beyond the boundary in §9. No Envelope code
  ships in this version.
- Argument matchers and the Bindings that produce them (AILAB-626).

**`aegis recheck` is specified, as of AILAB-622:** `aegis recheck --policy <YAML>
<PATH>` re-evaluates every recorded outcome in `<PATH>` against the Policy Set in
`<YAML>` and prints a would-block diff, exiting `0` when every call is unchanged,
`1` when a call is newly blocked, allowed or parked, `2` when the policy or the
record could not be read, and `3` when any call is indeterminate — reading the
Chain only, opening no Envelope (§9) and executing nothing.

## The `aegis verify` command surface

Deliberately unnumbered: this is the command surface the format document pins in
full, and it sits ahead of §1 so it cannot be mistaken for a property of the
format. Sections 1–12 keep the numbers they have always had.

**`aegis verify` is specified, as of AILAB-621.** The verdict *model* stays in
§8, because it is a property of the format. The command that prints it now
ships, and its surface is fixed here because CI gates script it:

```
aegis verify [--key <HEX>]... [--trust-store <PATH>] <PATH>
```

`<PATH>` is the record file; any path is accepted, since its name and extension
are the first open question above. `--key` is repeatable and takes a **public
key** in the same 64-lowercase-hex wire form the `open` Line publishes — not a
`key_id` fingerprint. `--trust-store` names a file of those keys, one per line,
with blank lines and `#` comment lines skipped. The union of the two is the trust
slice. Supplying **neither** flag is an unpinned walk (§8.4); supplying either
one is a pin, and a `--trust-store` that yields no keys is a pin that nothing can
satisfy — the first `open` Line is `Tampered` with an untrusted-key reason. A
store that has been truncated or mis-mounted MUST NOT read as "unpinned", or the
CI gate it anchors keeps passing with its anchor gone.

Exit codes are API and there are exactly four:

| Exit | Meaning |
|------|---------|
| `0` | `Verified` |
| `1` | `Tampered`, or a usage error — an unknown flag, a `--key` that is not 64 hex, a missing `<PATH>` |
| `2` | The record file or the trust store could not be read |
| `3` | `Indeterminate`, with the typed reason printed |

stdout is deterministic — same bytes, same report, with no timestamp and no path
in it. The first line is the verdict and, on success, its trust label; then one
`key_id` line per observed key, one `coverage` line naming the Session and `seq`
of the highest position a valid signature reached (§8), and one `in_flight` line
per in-progress Call when the reason is an unanchored tail. Empty sections are
omitted. A file that cannot be read produces empty stdout, `error: …` on stderr,
and exit 2.

---

## 1. Model

A **Chain file** is a sequence of **Lines**. Each Line is one JSON object on one
line (JSON Lines). Lines are append-only; nothing in this format ever rewrites a
Line that has been written.

A **Session** is a contiguous run of Lines beginning with an `open` Line. One
process that holds one writer is one Session. A file may hold many Sessions
appended over time — a fresh Session per process start is the normal case.

A **Call** is one tool invocation. It contributes an `intent` Line before
execution and exactly one `outcome` Line on every exit path, including denial,
trap, resource exhaustion, panic and abandonment. Calls interleave: a Call's
`intent` and `outcome` are **not adjacent**, because a writer serialises
concurrent Calls through one lock and other Calls' Lines land in between.

An **Envelope** is an optional, separate, unsigned store of verbatim request
bytes, content-addressed by `request_digest` (§9). It is not part of the Chain
and no Envelope implementation ships in this version.

The Chain is the **publishable artifact**. It is what gets handed to an auditor.
Read §10 before assuming that makes it non-sensitive.

### 1.1 The record file

Storage is JSON Lines: one JSON object per line, `\n`-separated, no trailing
comma, no enclosing array. A trailing newline after the final Line is permitted;
empty lines are ignored by a verifier.

**The bytes written for each Line are its canonical form (§3).** An emitter does
not write one serialization and hash another. This removes the step where two
implementations could disagree about what was hashed, and it means a reader can
recompute a Line's hash from the bytes on disk without re-canonicalizing —
although a verifier SHOULD canonicalize anyway, so that a foreign emitter's
spacing cannot change a Line hash.

This version does not fix the file's name or extension. Write `session.<ext>`
until AILAB-623 decides one.

---

## 2. Wire types

| Wire form | Meaning |
|---|---|
| digest | 64 lowercase hex characters (SHA-256). Uppercase is **rejected, not normalized** — one digest must have exactly one spelling, or two canonical forms of the same Line hash differently and a verifier disagrees with the emitter for no visible reason. |
| public key | 64 lowercase hex characters — a 32-byte ed25519 public key. |
| signature | 128 lowercase hex characters — a 64-byte ed25519 signature. |
| integer | JSON number, non-negative, `u64`, strictly below 2^53 (§3.2). |
| string | JSON string. |

Digest-valued fields are distinct types, not interchangeable strings:
`prev_hash`, `policy_set_hash`, `request_digest`, `response_digest`, `key_id`.
An implementation SHOULD make transposing them a type error rather than a
convention — a Chain that hashes the policy set into `prev_hash` verifies clean
while being wrong, and the shipped Rust types make that swap fail to compile
([`crates/botzr-aegis-core/src/digest.rs`](../crates/botzr-aegis-core/src/digest.rs)).

---

## 3. Canonical form — RFC 8785 JCS over a constrained value space

Every hash and every signature in this format is computed over the
[RFC 8785 (JCS)](https://www.rfc-editor.org/rfc/rfc8785) canonical JSON form of
a Line. Storage stays JSON Lines; JCS defines the **hash input** (ADR-0003).

### 3.1 Canonicalization rules

1. Object members are serialized in ascending order of their key's **UTF-16 code
   unit** sequence, per RFC 8785 §3.2.3. This is *not* UTF-8 byte order. The two
   agree across the ASCII key set in this specification and disagree above the
   Basic Multilingual Plane, where UTF-16 surrogates (0xD800…) sort below U+E000.
   An implementation MUST implement the UTF-16 rule even if its own key set is
   ASCII, because a future or foreign emitter's may not be.
2. No insignificant whitespace: no spaces after `:` or `,`, no indentation, no
   newlines inside a Line.
3. Array order is preserved exactly. Arrays are never sorted.
4. Strings escape only what JSON requires — `"`, `\`, and control characters —
   using `\b`, `\t`, `\n`, `\f`, `\r` where those short forms exist and lowercase
   `\u00xx` otherwise. Everything else, including all non-ASCII, is emitted
   literally as UTF-8. `/` is **not** escaped.

### 3.2 Value space — normative

These are requirements, not style. They are what make JCS safe to use here, so
an emitter MUST NOT produce a Line that violates them and a canonicalizer SHOULD
refuse one rather than guess:

- **No floating-point values anywhere in a Line.** ES6 number formatting is the
  part of JCS that implementations disagree about, so the format removes the
  disagreement by removing floats. An integral float (`1.0`) is a float and is
  not an escape hatch.
- **Integers are non-negative and strictly below 2^53** (`9007199254740991`).
  This bound exists **for a JavaScript verifier reading `seq` as a `Number`**,
  not for Rust. A JS implementation is the realistic third-party verifier and
  losing precision above 2^53 would break verification in a way nobody would
  attribute to the format. A field whose natural domain exceeds this (for
  example a byte limit near `u64::MAX`) MUST be projected as a decimal string
  before it reaches the canonicalizer.
- **Absent fields are omitted, never null.** A canonical form cannot leave
  absent-versus-null to the emitter. A literal `null` anywhere in a Line is
  invalid. The one field that is always present but may be empty is
  `decision_axes`, which serializes as `{}` (§5.3).

### 3.3 Why this is safe, and the boundary that keeps it safe

This constrained value space is only viable because **payloads live in the
Envelope**. `request_digest` is SHA-256 over raw request bytes (§9), so arbitrary
user data never reaches the canonicalizer: every key it sees is one of Aegis's
own, and JCS's genuinely hard cases — float edge cases, unnormalized Unicode in
attacker-chosen keys — all live in user data, of which there is none.

**Do not relax that boundary without revisiting this decision.** Putting request
arguments inline would put attacker-chosen keys and arbitrary numbers into the
canonical form, and every constraint in §3.2 would stop being reachable.

---

## 4. The chain rule

For each appended Line, in this order, **inside the same lock that performs the
write**:

1. Assign `seq` — the next position in this Session — and `prev_hash` — the hash
   of the Line written immediately before it in this Session.
2. Compute `signing_input` = the canonical form of the Line with the `signature`
   member **omitted** and `key_id` **present**.
3. If the Line is in the signed set (§5.1): `signature` = ed25519 over
   `signing_input`; write both `signature` and `key_id` into the Line.
4. Compute `line_hash` = SHA-256 over the canonical form of the **complete**
   Line, signature included.
5. Write the canonical form as one JSON Lines row; flush; fsync.
6. Set the Session tail to `line_hash`. The next Line's `prev_hash` is this
   value.

**Step 1 must happen under the same lock as step 5.** Two threads that read the
chain head outside that lock receive the same `prev_hash` and fork the chain.
This is the single highest-risk defect in an implementation of this format; the
shipped writer holds `seq`, the tail and the file handle in one mutex-guarded
struct precisely so they cannot drift apart, and a concurrency test appends from
eight threads and asserts a single unforked chain.

**`line_hash` covers the signature, deliberately.** Stripping a signature
therefore changes the hash and breaks the *next* Line's `prev_hash`, which a
verifier reports as `Tampered`. If the hash excluded the signature,
signature-stripping would leave a clean chain.

**`seq` is per appended Line, per Session — never per Call.** Concurrent Calls
interleave, so a per-Call counter cannot describe a file's order.

A `seq` gap over an intact chain is possible and is not tampering: the writer
takes `seq` before the append and advances the tail only after the write lands,
so a failed write leaves a gap with the chain intact. See §8.

---

## 5. Lines

Every Line, of every type — including a type this specification does not define —
MUST carry:

| Field | Type | Notes |
|---|---|---|
| `schema_version` | integer | `2` for this specification. |
| `line_type` | string | See §5.1. |
| `seq` | integer | Position within the Session, from `0`. |
| `prev_hash` | digest | Hash of the predecessor Line, or genesis (§7). |

A Line missing or mistyping `line_type`, `seq` or `prev_hash` is not a Chain
Line; a verifier reports the file as `Tampered`, not as unrecognised. This is
what makes the extension story in §5.2 bounded: a future Line type may add
anything, but it may not opt out of its position in the chain.

### 5.1 Line types and the signed set

| `line_type` | Signed | Emitted by v0 | Role |
|---|---|---|---|
| `open` | yes | yes | First Line of a Session. Carries the public key and `prev_session_tail`. |
| `intent` | **no** | yes | Pre-execution Line for a Call. |
| `outcome` | yes | yes | The Agent Action Record — one per Call, on every exit path. |
| `decision` | yes | yes | A human approval verdict (ADR-0005). |
| `close` | yes | yes | Last Line of a Session. |
| `checkpoint` | yes | **no — reserved** | Defined so that adding it later is not a breaking change. |

The signed set is `open`, `outcome`, `decision`, `close`, `checkpoint`.

**`intent` is hashed into the chain but never signed.** The intent Line is
appended and fsynced *ahead of execution*, so anything added to it — including a
signature computation — lands on the pre-execution critical path. It is
authenticated transitively instead: the next signature commits to `prev_hash`,
and `prev_hash` chains back through every unsigned Line before it. In the shipped
implementation this is a type-system property, not a rule the writer remembers —
the intent type implements the chain trait and not the signing trait, so there is
no way to hand it to the signing path
([`crates/botzr-aegis-audit/src/line.rs`](../crates/botzr-aegis-audit/src/line.rs)).

**`checkpoint` is reserved.** No emitter in this repository produces one. A
verifier MUST handle one: it is a signed Line, so it extends Coverage — and it
still caps the verdict at `Indeterminate`, because this version does not define
what a Checkpoint asserts.

**There is no `park` Line type.** A park is an `outcome` Line carrying
`policy.status = "pending_approval"`, which has shipped since schema version 1.
The human verdict that answers it is a separate `decision` Line, and a resumed
call is a *new* Call with its own `intent` and `outcome`, cross-referenced by
`approval_id` (ADR-0005).

### 5.2 Unknown line types

An emitter newer than a verifier may write a `line_type` the verifier does not
recognise. Such a Line:

- **still hashes.** It is bytes; the chain stays valid across it, and Lines after
  it verify normally.
- **caps the verdict at `Indeterminate`**, with a reason naming the unrecognised
  token — "unknown line type `foo` at session 0 seq 12, newer emitter".

The cap is the answer for an unknown Line that carries **no `signature` field**.
Whether a future Line type must be signed is unknowable to this build, so an
unsigned one is only unreadable. A `signature` that *is* present and does not
authenticate the Line is `Tampered` instead (§8.1, §8.4): forgery is decidable
without understanding the Line, and it outranks the cap. Presence is read off
the Line's own fields — an unknown Line whose `signature` is present while
`key_id` was stripped is still a present-and-invalid signature, not an unsigned
Line.

A verifier MUST NOT report `Verified` over content it does not understand. If it
did, a future emitter could smuggle anything past an old auditor. This is the
format's entire extensibility story and it is fixed at this version.

The token itself MUST be preserved through parsing. A verifier that collapses
every unknown type to a single "other" can say that something was unreadable but
not what, which is the half of the message an operator needs.

### 5.3 Field reference

Fields marked *optional* are **omitted** when absent — never `null`.

#### `open`

| Field | Type | Notes |
|---|---|---|
| `schema_version`, `line_type`, `seq`, `prev_hash` | — | `seq` is `0`; `prev_hash` is the genesis digest (64 zeros). |
| `prev_session_tail` | digest, optional | The previous Session's final `line_hash`. Omitted for a fresh file. See §7. |
| `public_key` | public key | The ed25519 key every signed Line in this Session is signed under. |
| `signature`, `key_id` | — | The `open` Line signs itself under the key it publishes. |

#### `intent`

| Field | Type | Notes |
|---|---|---|
| `schema_version`, `line_type`, `seq`, `prev_hash` | — | |
| `call_id` | string | Pairs this Line with its `outcome`. |
| `tool_id` | string | |
| `request_digest` | digest | SHA-256 over the **verbatim** request bytes (§9). |

No `signature`, no `key_id`. An emitter MUST NOT sign an `intent` Line.

#### `outcome`

| Field | Type | Notes |
|---|---|---|
| `schema_version`, `line_type`, `seq`, `prev_hash` | — | |
| `call_id` | string | Matches the Call's `intent` Line. |
| `tool_id` | string | |
| `request_digest` | digest | Identical to the `intent` Line's. |
| `policy_set_hash` | digest | Which Policy Set governed this Call (§6). |
| `policy` | object | Tagged by `status`: `allowed` · `denied {reason}` · `rate_limited {reason}` · `pending_approval {approval_id}`. |
| `capability` | object | Tagged by `status`: `granted {grant}` · `denied {reason, denied_capability?}`. |
| `execution` | object | Tagged by `status`: `success` · `trap {message}` · `resource_exceeded {kind}` · `host_denied {reason}`. |
| `grant_id` | string, optional | The grant the Call ran under. Omitted when none was minted. |
| `response_digest` | digest, optional | SHA-256 over the verbatim response bytes. Omitted when the Call produced none, and when output was rejected by a cap — bytes that never left MUST NOT be recorded as a response. |
| `wall_ms` | integer, optional | Omitted when the sandbox never ran. |
| `peak_memory_bytes` | integer, optional | Omitted when the sandbox never ran. |
| `decision_axes` | object | **Always present**, possibly `{}`. See below. |
| `signature`, `key_id` | — | |

`capability.granted.grant` is a `CapabilityGrant`: `grant_id`, `tool_id`,
`fs {read_paths, write_paths}` (optional), `net {http: [{host, ports, methods}]}`
(optional), `max_memory_bytes`, `max_wall_ms`, `max_output_bytes`.

**`decision_axes`** — the inputs the verdict actually turned on. It is nested
rather than flattened because the `outcome` Line already has a top-level
`capability` field holding the capability *station outcome*, and two different
things named `capability` on one Line is a collision that survives review and
breaks an ingest.

| Field | Type | Notes |
|---|---|---|
| `capability` | string, optional | The capability axis the Call requested, e.g. `fs.read`. |
| `role` | string, optional | The role asserted by the caller. |
| `session` | string, optional | The policy session scope — the `PolicyRequest` scalar, **not** the audit Session. |
| `matched_rule` | string, optional | The rule that decided it. |
| `approval_ref` | string, optional | The approval a resumed Call was allowed under (ADR-0005). |
| `fs` | object, optional | Derived filesystem parameter: `{path_raw, path_canonical}`. |
| `net` | object, optional | Derived network parameter: `{host, port}`. |

The object is always emitted because `{}` and an absent member say different
things: `{}` says *this emitter recorded no axes*, an absent member says nothing
at all. Its members follow omit-never-null.

`fs` and `net` are the **derived capability parameters** of ADR-0006 — the
resource the runtime resolved the Call to, which is what argument matchers target.
They are recorded only when the Call resolved to exactly one such resource; a
grant naming several roots has not resolved the Call to *a* path, and the axis is
**omitted rather than guessed**. Recording an arbitrary one of N roots would be
evidence that reads as fact and is not.

Both `path_raw` and `path_canonical` are recorded because a difference between
them is itself evidence. In this version they carry the same string, because the
capability resolver canonicalizes at mint time; the pair exists now so that
AILAB-626 resolving a caller-supplied path against a root is not a breaking
change to the shape.

#### `decision`

| Field | Type | Notes |
|---|---|---|
| `schema_version`, `line_type`, `seq`, `prev_hash` | — | |
| `approval_id` | string | The park this verdict answers. |
| `verdict` | object | Tagged by `verdict`: `approved {scope}` · `denied {reason}`. |
| `signature`, `key_id` | — | |

`scope` is `{tool_id, fs?, net?}` — the authority the approval granted, not just
the fact of approval. The scope rides *inside* the approved variant so that an
approval without a recorded scope is unrepresentable: approval without recorded
scope is a blank check in the evidence, and the resumed Call's grant must be a
subset of what is recorded here.

#### `close`

| Field | Type | Notes |
|---|---|---|
| `schema_version`, `line_type`, `seq`, `prev_hash` | — | |
| `signature`, `key_id` | — | |

#### `checkpoint`

Reserved. This version defines no fields beyond the four every Line carries.

---

## 6. `policy_set_hash`

`policy_set_hash` names the Policy Set that governed the Call. It is SHA-256 over
the **canonical bytes of the parsed set** — the JCS form of a stable projection of
the validated rules — and deliberately **not** over the YAML text.

Hashing the text would make a reindent, a retyped comment, or a reordered mapping
key look like a different ruleset, and an identity that moves for non-reasons
trains a reader to ignore it moving. Every field the evaluator actually reads is
covered, so a semantic edit always moves the hash. Rule declaration order *is*
covered, because rule order is observable behaviour: the selector keeps the
incumbent on a full specificity-and-priority tie.

Every scalar in the projection is a string or a boolean. A legitimate policy
document may carry a negative priority or a byte limit near `u64::MAX`, both of
which are outside the §3.2 value space; projecting numbers as decimal strings
means no policy file can push canonicalization outside the value space, so hashing
a parsed set cannot fail.

There is a *separate*, older FNV-1a digest over the YAML text in this codebase.
It serves the hot-reload audit trail and is self-documented as not a security
digest. It MUST NOT be recorded as `policy_set_hash`.

---

## 7. Sessions

- A Session begins with an `open` Line at `seq` `0`.
- `seq` **restarts at 0 in every Session.** A file with two Sessions has two
  Lines numbered `seq` 5.
- An `open` Line's `prev_hash` is the **genesis digest**: 64 zeros. A Session's
  first Line has no predecessor *within* the Session.
- The back-reference across a Session boundary lives in `prev_session_tail` on
  the `open` Line, and MUST equal the previous Session's final `line_hash`. It is
  omitted only when the file was empty.
- The tail is **not** duplicated into `prev_hash`. One fact gets one spelling,
  and a verifier already special-cases `open` because that is where the public
  key is.
- A Session ends with a `close` Line, written when the writer is dropped. See
  §10 for what that does and does not cover.

**Coverage is `(session_index, seq)`, not a bare `seq`.** ADR-0002 defines
Coverage as "the highest `seq` covered by a valid signature", which reads
file-global; `seq` in fact restarts per Session. Those disagree the moment one
file holds two Sessions, where a bare `seq` names two different Lines. This
specification is normative: **a position in a Chain file is the pair
`(session_index, seq)`**, where `session_index` is the Session's ordinal within
the file counted from the first `open` Line. The ADR's wording is
under-specified, not wrong.

---

## 8. Verification

A verifier walks the file once, in order, holding the same state the writer held:
current Session index, expected `seq`, the running tail hash, and the Session's
published public key.

**Coverage** is the highest position covered by a valid signature.

The verdict is one of three states, and only three:

| Verdict | Meaning |
|---|---|
| `Verified` | Every Line parsed, chained and — where required — verified, and the file ends with a verified `close`. |
| `Indeterminate` | Nothing contradicts the file, but something could not be decided. Carries a typed reason. |
| `Tampered` | The file contradicts itself. |

A binary pass/fail is deliberately rejected. Failing on any unverified tail
alarms on healthy systems — the common case is not a crash but a *live file*
being appended to right now, and a gate that fires on every in-progress file is
noise within a week. Passing with a warning is worse: exit 0 is what every CI
gate actually reads, and an evidence tool whose machine-readable answer is "fine"
for a truncated file reproduces the very critique it exists to answer.

### 8.1 `Tampered`

- A Line's `prev_hash` is not the hash of the Line before it — an edit, a removed
  Line, or a forked chain.
- `seq` repeated or went backwards. Two Lines at one position is what a fork
  looks like from the file, and no correct writer can produce it.
- A Line in the signed set carries no signature, or one that does not verify
  against the key its Session published. A stripped signature on an `outcome`
  Line lands here.
- A Line's `key_id` does not match the key its Session published (§8.4).
- An `open` Line's `prev_session_tail` does not match the previous Session's
  final Line. **This is how truncating a non-final Session is caught.**
- A Line outside the format: not JSON and not the final Line; not an object;
  missing or ill-typed `line_type` / `seq` / `prev_hash`; or outside the §3.2
  value space, so it has no reproducible hash.
- An `open` Line publishes a public key that is **not in a trust slice the
  caller supplied** (§8.4). Not `Verified (unpinned)`: the caller stated which
  keys it accepts and the file answered with another one.
- A **second `decision` Line for an `approval_id`** already decided in the file.
  One park, one verdict — without this rule a recorded denial can be followed by
  an approval for the same park with both Lines validly signed (ADR-0005).

### 8.2 `Indeterminate`

- **Unknown line type**, with the emitter's token (§5.2) — capped only when it
  carries no signature; a signature present and invalid is `Tampered` (§8.1).
- **Reserved `checkpoint`** — signed, so it extends Coverage, and still capped.
  The cap does not excuse the signature: a `checkpoint` that is unsigned or
  whose signature does not verify is `Tampered` (§8.4), because it is in the
  signed set and a forgery must not hide behind the cap.
- **Torn final line** — the file's last Line does not parse. Distinct from "no
  close record": it is a torn write, and only the *last* Line can be one, because
  a correct writer refuses to append onto a torn tail.
- **Unanchored tail** — the final Session has no `close` and nothing anchors
  beyond it. The report names the Calls in flight: three intents for workspace
  reads is a shrug, one for a network POST is where an operator starts looking.
- **Missing line** — `seq` jumped forward while `prev_hash` still matched. Only a
  writer can produce this (§4); an attacker cannot, because removing a Line
  breaks the next Line's `prev_hash` and re-signing the remainder needs the key.
  So this is a durability incident, not a forgery, and calling it `Tampered`
  would alarm on a full disk.
- **Empty chain** — no Lines. Nothing contradicts the file; there is also nothing
  in it to verify.

Anchors are what resolve a tail: a `close` Line, a later Session's `open`, and —
reserved — a `checkpoint`. The verdict MUST NOT be computed from "is there a
close record" as a boolean; Coverage-plus-Anchor generalises across the crash
case, the multi-Session case and the live-file case, and a close-record boolean
does not.

**The verdict is deterministic: same bytes, same verdict, always.** This is a
property, not a test case.

### 8.3 What the unverified tail can contain

Every `outcome` Line is signed, so the unverified tail after the last signature
can hold only `intent` Lines plus at most one torn final Line. **An `outcome`
Line in the tail is a stripped signature — `Tampered`, not a crash.**

### 8.4 Key model and rotation

A per-host ed25519 keypair signs Lines. The Session `open` Line carries the
public key; every signed Line carries `key_id`, the SHA-256 fingerprint of that
32-byte public key.

Signature verification MUST be ed25519 **strict** verification, rejecting
small-order and malleable signatures. A record format wants one signature to have
one verdict everywhere; the permissive rule lets the same bytes verify in one
implementation and fail in a batch verifier.

`key_id` is inside the signed input — a signature is computed over the canonical
form with `signature` omitted and `key_id` present — so a signature cannot be
replayed under a different key's fingerprint. A verifier MUST read `key_id` off
the Line rather than substituting the fingerprint of the key it holds; otherwise a
Line naming a key it was not signed under would quietly verify.

**Rotation rule (normative).** A file MAY span multiple `key_id`s. A new `key_id`
is legal **only when introduced by a Session `open` Line that carries the matching
public key.** A `key_id` change *within* a Session is `Tampered`.

This is what makes rotation expressible without making key substitution free:
rotating means starting a Session, which is a signed, chained, anchored event that
back-references the previous Session's tail.

**Two success labels, not one.** Verifying a Session's signatures against the key
that same Session published proves internal consistency and nothing about
provenance: an attacker who rewrites a whole Session signs it with their own key,
publishes that key in the `open` Line, and the walk comes out clean. A verifier
therefore MUST print the fingerprint and MUST distinguish `Verified (pinned to
<fp>)` — a key was supplied out of band and matched — from `Verified (unpinned)`,
stated as internal consistency only. A `key_id` that fails to match a supplied
trust store is `Tampered`. The labels are specified here because they are a
property of what the format can prove; the CLI that prints them is AILAB-621.

**What the shipped walker enforces, and the one gap that remains** — stated
rather than papered over:

1. The rotation rule is enforced across the **whole** signed set. A foreign
   `key_id` on an `open`, `outcome`, `decision` or `close` Line is `Tampered`
   with a key-mismatch reason, and a Session-opening rotation is accepted, both
   under test. `checkpoint` is in the signed set and is held to it: a
   `checkpoint` whose signature does not verify is `Tampered`, not capped —
   discarding that result would let a forged Checkpoint hide behind the
   `Indeterminate` cap. An unknown-type Line is judged on what it carries: a
   signature that is *present and does not verify* is `Tampered`, because forgery
   is decidable without understanding the Line, while an unsigned one only caps,
   because whether a future Line type must be signed is unknowable to this build.
   Neither is ever reported as `Verified`.
2. Pinning ships. The walker takes an optional slice of public keys the caller
   anchored out of band, and `aegis verify` fills it from `--key` and
   `--trust-store` (see *The `aegis verify` command surface*, above), so both
   success labels are reachable. **Every** `open`
   Line's key must be in a supplied slice, not merely one of them — rotation
   across Sessions stays legal, while rotating into a key the caller never
   anchored is `Tampered` with an untrusted-key reason. Pinning is identity
   checking, not a second signature path: signatures verify against the key each
   Session published either way, and the slice only decides whether that key is
   one the caller accepts. A supplied slice therefore cannot make a broken chain
   verify; it upgrades the label from `Verified (unpinned)` to `Verified (pinned
   to <fp>)`, or to `Verified (pinned)` when the file legally rotates across
   several anchored keys.
3. **Remaining gap:** a signature on an `intent` Line is ignored rather than
   rejected. It is still covered by `line_hash`, so it cannot be altered
   undetected, but an emitter that signs intent Lines is out of spec and the
   shipped walker does not say so.

---

## 9. The Envelope boundary

Per ADR-0006 the Envelope is **purely forensic, not a recheck prerequisite.**
Argument matchers target derived capability parameters, and those parameters are
decision axes carried in the Chain (§5.3), so `aegis recheck` works chain-only
even after AILAB-626 lands. The Envelope exists for human investigation after an
incident, and as the seam a future execution journal grows into.

The boundary, normatively:

- An Envelope entry holds the **verbatim request bytes** of a Call.
- It is **content-addressed by `request_digest`** — the same digest the `intent`
  and `outcome` Lines carry.
- It is stored **outside the Chain**, in a separate artifact that need not travel
  with the Chain and often should not.
- It is **never signed.**
- It is **authenticated transitively**: a reader hashes the bytes on load and
  compares against the `request_digest` on the signed Line. The Line's signature
  covers that digest, so a matching hash means the signature covers the payload
  too.

**"Verbatim" is load-bearing and is stated here explicitly.** `request_digest` is
SHA-256 over the raw request bytes exactly as they arrived. An Envelope writer
that pretty-prints the JSON, re-encodes it, sorts its keys, or normalizes its
whitespace produces bytes that no longer hash to the recorded digest — and every
entry it wrote silently stops authenticating. **The trap is invisible until
someone runs a formatter**, at which point the break is retroactive and looks like
tampering. An implementation MUST hash and store the bytes it received, before any
processing, and MUST NOT expose an API that accepts a caller-supplied digest.

The same rule governs `response_digest`: hash what was produced, never a
re-encoding of it.

**No Envelope writer or reader ships in this version.** This section specifies
the boundary so that building one later cannot break the Chain format.

---

## 10. Threat model and non-guarantees

State these to anyone who is handed a Chain file. Each one is a limit of the
evidence, not a bug to be worked around.

**`Drop` does not run on SIGKILL.** The `close` Line is written when the writer is
dropped, which covers clean exit and panic unwinding — both under test. It does
not cover `SIGKILL`, a power loss, or a host that vanishes. **That gap is exactly
what produces `Indeterminate`**, and it is documented rather than engineered
around: a Session with no `close` and nothing anchoring beyond it is honestly
undecidable, and the format says so instead of guessing.

**Truncating a non-final Session is detectable from the Chain alone.** Drop Lines
off the end of Session N and its tail changes, so Session N+1's signed `open` no
longer agrees with it — `Tampered`, from the file alone, with no external witness.
**Only the final Session's tail is undecidable**, and only when nothing anchors
beyond it.

> ADR-0002's opening sentence says "truncation is therefore not detectable from
> the Chain alone". That sentence contradicts that ADR's own first Consequence,
> which correctly states the per-Session property above, and it understates what
> shipped. This specification states the shipped property; the ADR header is a
> known editorial defect.

**Content beyond the last signature is unverifiable by construction.** No format
that signs some Lines can say anything about bytes appended after the last one it
signed. That is what Coverage measures and what Anchors resolve.

**A self-embedded key proves consistency, not provenance.** See §8.4. Without an
out-of-band key, `Verified` means "some Aegis build wrote this and the file names
which key", never "this key is yours".

**Derived paths appear in the Chain, and the Chain is the publishable artifact.**
A derived `fs` path naming a client directory under someone's home directory is
smaller than a full argument tree, but it is **not non-sensitive**. Sensitivity
moved when the
Envelope split off; it did not vanish. Anyone publishing a Chain must read its
`decision_axes` first. `tool_id`, `call_id`, `matched_rule`, policy reasons and
trap messages are free text written by the host and are subject to the same
reading.

**Unmatched `intent` is a consistency cross-check, not a tamper signal.** An
`intent` with no `outcome` inside a closed Session is a structural error worth
reporting, but interior deletion is already caught by `prev_hash`. What the
invariant adds is catching a buggy emitter, and catching a rewriting attacker who
holds the signing key but drops an outcome sloppily. Do not claim more.

**Two linkage kinds with different strengths:**

- `intent` ↔ `outcome` is a **hard invariant, Session-scoped**, guaranteed by the
  writer's drop guard plus the borrow that makes the writer outlive every Call it
  issued. A violation inside a closed Session is a structural error.
- `approval_id` ↔ `decision` is a **soft cross-reference** that may span Sessions
  and files. A human approving after a restart is normal. A `pending_approval`
  outcome with no `decision` is legal and informational; a `decision` for an
  absent `approval_id` is legal and informational. **Two `decision` Lines for one
  `approval_id` is a structural violation**, the same class as a chain break,
  because a correct emitter cannot produce it.

**A `seq` gap is a durability incident, not a forgery.** See §8.2.

---

## 11. Test vectors

Every vector below publishes the **canonicalized intermediate form alongside the
final hash**. This is required, not a courtesy: an implementer who canonicalizes
wrong and only sees "hash mismatch" has nowhere to look, and the canonical string
is where the divergence is visible.

All vectors are live in the tree and are checked by CI.

### 11.1 Canonicalization

Source: [`crates/botzr-aegis-core/src/jcs.rs`](../crates/botzr-aegis-core/src/jcs.rs),
test `published_test_vector_canonical_form_and_hash`.

Input (member order deliberately scrambled, nested object included):

```json
{
  "tool_id": "echo",
  "seq": 7,
  "decision_axes": {
    "role": "ops",
    "capability": "fs.read",
    "fs": { "path_raw": "~/notes.md", "path_canonical": "/home/a/notes.md" }
  },
  "line_type": "outcome",
  "prev_hash": "0000000000000000000000000000000000000000000000000000000000000000"
}
```

Canonical form (one line, no whitespace, wrapped here only for reading):

```
{"decision_axes":{"capability":"fs.read","fs":{"path_canonical":"/home/a/notes.md",
"path_raw":"~/notes.md"},"role":"ops"},"line_type":"outcome","prev_hash":
"0000000000000000000000000000000000000000000000000000000000000000","seq":7,
"tool_id":"echo"}
```

SHA-256 of those canonical bytes:

```
9017de5e13e0a12b261e1960d0d0bc9220c6b7ef501b7dd189141e6327377664
```

Nothing else is mixed in — the Line hash is exactly SHA-256 over the canonical
bytes.

### 11.2 A Session, end to end

Source: the committed goldens in
[`crates/botzr-aegis-audit/tests/golden/`](../crates/botzr-aegis-audit/tests/golden/),
emitted through the real writer into one Session and signed with a fixed-seed
development key. Each file in that directory **is** the canonical form of one
Line, exactly as written to disk.

The Session is twelve Lines: `open`, `intent`, eight `outcome` Lines covering
policy deny, rate limit, pending approval, capability deny, trap, resource
exceeded, host panic and abandonment, then `decision`, then `close`.

**Line 0 — `session_open.json`** (canonical form, verbatim):

```
{"key_id":"77a2c2f5952039243c043b69e7e812a2deb69e3271adb3013b8f24d3b8ea40f6","line_type":"open","prev_hash":"0000000000000000000000000000000000000000000000000000000000000000","public_key":"3de537a06e04b2ffe1fb0558ea16d3c0f042ed99f7e392698aa5120f568d4e2c","schema_version":2,"seq":0,"signature":"f27b7f566bce4e0e8126a30dd951411a5ea82333b7b41740ee047f0382788b3239d382aa9506cf3ef7f34137cf9cd7f57388018c67a46b2c3285af8fcc2a7901"}
```

Derived values a third-party implementation must reproduce:

| Quantity | Value |
|---|---|
| `key_id` = SHA-256 of the 32 public-key bytes | `77a2c2f5952039243c043b69e7e812a2deb69e3271adb3013b8f24d3b8ea40f6` |
| `line_hash` = SHA-256 of the canonical bytes above | `ace4118a6a4ec1bf47503431aaa769ebb74de9c61174bf64470561a99abf4066` |
| Line 1's `prev_hash` | the same `ace4118a…` |

**Signing input for line 0** — the canonical form with `signature` omitted and
`key_id` present. This is the exact byte string the ed25519 signature covers:

```
{"key_id":"77a2c2f5952039243c043b69e7e812a2deb69e3271adb3013b8f24d3b8ea40f6","line_type":"open","prev_hash":"0000000000000000000000000000000000000000000000000000000000000000","public_key":"3de537a06e04b2ffe1fb0558ea16d3c0f042ed99f7e392698aa5120f568d4e2c","schema_version":2,"seq":0}
```

Note that `key_id` is *inside* the signed bytes while `signature` is not, and that
`line_hash` is taken over the form that *does* include `signature` — the two
differ by exactly one member, and getting that backwards is the most likely
implementation error in this specification.

**Line 1 — `intent.json`**, showing an unsigned Line inside the chain:

```
{"call_id":"call-golden-0","line_type":"intent","prev_hash":"ace4118a6a4ec1bf47503431aaa769ebb74de9c61174bf64470561a99abf4066","request_digest":"fb0288872031fc4818c03a7253bd3a78de192d05e6bccd09ceabeda65b4d7c6f","schema_version":2,"seq":1,"tool_id":"smoke"}
```

`line_hash` of line 1 is
`5d923c33bede5bef42ee41556fed00fa0660ab30feb57355b3316a2263ffa7f9`, which is
line 2's `prev_hash` — the unsigned Line is a full chain link, and the next
signature covers it transitively.

**Line 2 — `policy_deny.json`**, the populated `decision_axes` shape:

```
{"call_id":"call-golden-1","capability":{"reason":"policy blocked before capability","status":"denied"},"decision_axes":{"capability":"fs.read","fs":{"path_canonical":"/fixtures/notes.md","path_raw":"./notes.md"},"matched_rule":"block-smoke","role":"ops","session":"sess-golden"},"execution":{"reason":"not executed","status":"host_denied"},"key_id":"77a2c2f5952039243c043b69e7e812a2deb69e3271adb3013b8f24d3b8ea40f6","line_type":"outcome","policy":{"reason":"blocked in test","status":"denied"},"policy_set_hash":"89a056813bdf93f95c1881a78793b1a86f5b6bab829c1ba9d20bb4add2aae921","prev_hash":"5d923c33bede5bef42ee41556fed00fa0660ab30feb57355b3316a2263ffa7f9","request_digest":"2baf1f40105d9501fe319a8ec463fdf4325a2a5df445adf3f572f626253678c9","schema_version":2,"seq":2,"signature":"470a273226ed3d32516e40fe136c03b684998ed17fa65ac0ed387c8074edf5aaf75b85f263ce2bdfa93fc4c083e0685e1a1a2d3ca42459f943c4dc3be698830c","tool_id":"smoke"}
```

This is the vector that matters for ADR-0001's claim that a recorded deny can
explain itself: `role`, `capability`, `session` and `matched_rule` are all on the
Line, so the verdict can be reconstructed from the record alone without the
request payload.

The remaining Lines — including `session_close.json`, and `decision.json` with an
approved scope — are in the same directory and chain in the order listed above.

> **The signing key in these vectors is public and worthless.** It is a fixed seed
> compiled into the test crate so that goldens are reproducible and its `key_id`
> is identical on every machine. A Line it signs proves that *some* Aegis build
> wrote it, never *which* — a verifier can only report `Verified (unpinned)` over
> these files. Never use it for anything.

### 11.3 Reproducing the vectors

Signatures are deterministic (ed25519), the seed is fixed, and the records are
constants, so the whole Session is byte-reproducible:

```bash
cargo test -p botzr-aegis-audit --test golden
```

`every_committed_golden_line_verifies_and_chains` checks the committed *files*,
not a freshly written Session, so a golden edited by hand fails there rather than
passing as "expected output".

---

## 12. Versioning and compatibility

`schema_version` is `2`. Version 1 is not compatible: `phase` became `line_type`,
`input_digest` became `request_digest`, the chain and signature fields are new,
two line types became six, and hashing is now specified.

Within version 2, an emitter MAY add fields and MAY add line types. A verifier:

- MUST ignore members it does not recognise, and MUST still hash the whole Line.
- MUST NOT report `Verified` over a `line_type` it does not recognise (§5.2).
- MUST treat a Line missing `line_type`, `seq` or `prev_hash` as a format
  violation, not as an unknown extension (§5).

A change to the canonicalization rules, to the signing input, or to what
`line_hash` covers is a **version bump**, not an addition — each one silently
changes every hash in every file.

### 12.1 Downstream consumers

The Layer 2 governance ingest in [`governance/`](../governance/) targets this
version (AILAB-624) and rejects version 1. It consumes `intent` and `outcome`
lines; `open`, `close`, `decision`, `checkpoint` and any line type a newer
emitter adds are skipped and counted per §5.2, never treated as corruption. It
parses signatures without checking them — it is a consumer, not a verifier. See
[`governance/DECISIONS.md`](../governance/DECISIONS.md) D25.

Test packages that exercise this format:
`aegis-deny-suite`, `aegis-stress-suite`, `aegis-api-surface`,
`aegis-adversarial-demo`, `aegis-stage2-demo`.

Runtime crates that define and produce it: `botzr-aegis-core` (types, digests,
canonicalization), `botzr-aegis-audit` (writer, signing, verdict),
`botzr-aegis-policy` (`policy_set_hash`), `botzr-aegis-runtime` (decision axes).
