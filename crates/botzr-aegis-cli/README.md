# botzr-aegis-cli

CLI for Aegis. Installed binary name: `aegis`.

```
aegis 0.1.0 — research runtime for secure agent tool execution
Pipeline: policy → capability → sandbox → audit
```

## Usage

### Ready (library-style bootstrap)

```
aegis [--policy <yaml-path>] [--audit <jsonl-path> --signing-key <key-path>]
```

Wires `Runtime` with optional policy/audit, prints the audit path, and exits.
No tools are registered in this mode.

### `aegis run` — register + execute

```
aegis run --component <wasm> --id <tool-id> [OPTIONS]
```

Registers a `wasm32-wasip2` component and executes one call through
**POLICY → CAPABILITY → SANDBOX → AUDIT**. Tool output goes to stdout; progress
and `request_digest` go to stderr. Deny/trap paths still emit audit JSONL.

| Flag | Description |
|------|-------------|
| `--component`, `--wasm` | Path to the WASM component |
| `--id`, `--tool-id` | Tool id (policy / capability / audit) |
| `--input` | Call input bytes as text (default: empty) |
| `--input-file` | Read call input from a file |
| `--policy` | Policy YAML (default: allow-all) |
| `--audit` | Audit JSONL path (default: temp file). Requires `--signing-key` |
| `--signing-key` | ed25519 seed file signing the audit Session (see `aegis keygen`) |
| `--base-dir` | Manifest base dir (default: component parent) |
| `--sha256` | Optional component digest pin (G10) |
| `--version` | Tool version recorded in the Manifest (default `0.1.0`) |

`--audit` and `--signing-key` travel together, or neither is given — a persistent
record file with no provisioned key is a **usage error** (exit 1), never a
default. Without `--audit` the sink is a temp file signed by the loudly-named dev
key, and `--signing-key` alone would be pointing at nothing. See
[AILAB-620 in the audit crate README](../botzr-aegis-audit/README.md#the-signing-key).

Example against the in-tree echo fixture:

```bash
aegis keygen --out /tmp/aegis-signing.key      # once, per host

cargo run -p botzr-aegis-cli -- \
  run \
  --component tests/fixtures/echo-tool/echo.wasm \
  --id echo \
  --input 'hello' \
  --audit /tmp/aegis-audit.jsonl \
  --signing-key /tmp/aegis-signing.key
```

### `aegis keygen` — mint the key that signs a record file

```
aegis keygen --out <PATH> [--force]
```

Writes a fresh ed25519 seed to `<PATH>` as one line of 64 lowercase hex
characters, mode `0600`, fsynced. Prints exactly two lines to stdout:

```
public_key <64 hex>
key_id     <64 hex>
```

| Flag | Description |
|------|-------------|
| `--out <PATH>` | Where to write the key. **No default** — the location is a decision you state out loud, never one the CLI picks |
| `--force` | Overwrite an existing key file (and tighten its mode back to `0600`) |

Generation is its own command because it must never happen implicitly. A key
minted on the emit path would publish a brand-new `public_key` in the Session's
`open` line and silently invalidate every pin held against the old one — so
`--force` is the only way past an existing file.

Feed the printed `public_key` — not the `key_id` — to `aegis verify --key` to
pin. A recommended location is something like `~/.config/aegis/signing.key`, but
nothing is searched for: a missing key is a loud failure, by design.

**Rotation** means `keygen` into a new file and starting a new process (one
process is one Session, and one Session holds one key). The rule a verifier
enforces is normative in [`spec/SPEC.md`](../../spec/SPEC.md) §8.4.

### `aegis verify` — read a record file, report a verdict

```
aegis verify [--key <HEX>]... [--trust-store <PATH>] <PATH>
```

Reads one Agent Action Record chain file and reports whether it verifies. The
walk itself lives in `botzr-aegis-audit`; this command is the surface over it.
No policy is loaded, no runtime is built, no tool is executed.

`<PATH>` is a positional argument and any path is accepted — the record file's
name and extension are not specified yet (AILAB-623), so examples here write
`session.<ext>`.

| Flag | Description |
|------|-------------|
| `--key <HEX>` | A public key you trust, 64 lowercase hex. Repeatable. |
| `--trust-store <PATH>` | File of the same, one key per line; blank lines and `#` comment lines are skipped |

`--key` takes the **public key** an `open` line publishes, not the `key_id`
fingerprint the report prints. The union of `--key` values and trust-store
entries is the trust slice; supply *neither* flag and the walk is unpinned.
Supplying either one is a pin, so a `--trust-store` that turns out to hold no
keys is a pin nothing can satisfy — exit 1, not a quiet `Verified (unpinned)`.
A store that got truncated or mis-mounted must not keep a gate green.

#### Exit codes

These are API — CI gates script them (ADR-0002).

| Exit | Meaning |
|------|---------|
| `0` | `Verified` |
| `1` | `Tampered` — or a usage error (bad flag, bad key hex, missing `<PATH>`) |
| `2` | Could not read the record file or the trust store |
| `3` | `Indeterminate` — a typed reason, printed |

#### Output

stdout is deterministic: the same bytes produce the same report on every run
and on every machine. No timestamps, no paths. The first line is the verdict;
then one `key_id` line per observed key, a `coverage` line, and — on exit 3 with
an unanchored tail — one `in_flight` line per Call that was in progress. Empty
sections are omitted. Read errors print `error: …` on stderr and leave stdout
empty.

```
$ aegis verify session.<ext>
Verified (unpinned)
key_id 77a2c2f5952039243c043b69e7e812a2deb69e3271adb3013b8f24d3b8ea40f6
coverage session 0 seq 3
```

```
$ aegis verify --key 3de537a06e04b2ffe1fb0558ea16d3c0f042ed99f7e392698aa5120f568d4e2c session.<ext>
Verified (pinned to 77a2c2f5952039243c043b69e7e812a2deb69e3271adb3013b8f24d3b8ea40f6)
key_id 77a2c2f5952039243c043b69e7e812a2deb69e3271adb3013b8f24d3b8ea40f6
coverage session 0 seq 3
```

#### What the two success labels claim

Per [ADR-0004](../../docs/adr/0004-embedded-key-with-labelled-trust.md), the
difference between them is the whole point, not a caveat:

- **`Verified (unpinned)`** — every signature in the file checks out against the
  key the file itself published. That is **internal consistency only**, and
  explicitly **not** a claim about provenance: an attacker who rewrites a whole
  Session signs it with their own key, publishes that key in the `open` line, and
  the walk comes out clean. Unpinned means *some* Aegis build wrote this file, and
  nothing in the file says whose.
- **`Verified (pinned to <fp>)`** — same walk, plus every `open` key in the file
  was one you supplied out of band. That is what turns the signature into a
  provenance claim, and the anchor comes from you, never from the record.

A file that rotates keys across Sessions prints `Verified (pinned)` with one
`key_id` line per fingerprint; rotation is legal, and *every* `open` key must be
in your store, not merely one of them. An `open` key that is not in a supplied
store is `Tampered`, never "unpinned".

### `aegis recheck` — re-evaluate a finished record against new rules

```
aegis recheck --policy <YAML> <PATH>
```

Reads one Agent Action Record chain file, re-evaluates every recorded outcome
against the Policy Set in `<YAML>`, and prints a would-block diff — the answer to
"if these rules had been in force, which of these calls would have gone
differently?". **Nothing is executed**: no component is loaded, no grant is
minted, no approval id is issued, no network or filesystem effect is re-run.
The verdicts come from `botzr-aegis-policy`; this command is the surface over
them.

`<PATH>` is a positional argument and any path is accepted, as with `verify` —
the record file's name and extension are not specified yet (AILAB-623), so
examples here write `session.<ext>`.

| Flag | Description |
|------|-------------|
| `--policy <YAML>` | Policy YAML to re-evaluate against. **Required** |

`--policy` has no default, unlike `run`'s. The whole question is "what would
*these* rules have done?", and an implicit allow-all set would answer a question
nobody asked while looking like a finding — every recorded denial would print as
`newly_allowed`.

No signature is checked and no key is involved, so there is no `--signing-key`
here. `aegis verify` answers "is this chain intact?"; recheck answers "what would
today's rules do to these calls?", and asking that of a file `verify` would call
`Tampered` is a legitimate forensic question. The two verbs are deliberately
independent, so neither becomes a precondition for the other.

The work is chain-only. Every input a verdict needs is a decision axis carried in
the record itself, so no Envelope is opened (see [`spec/SPEC.md`](../../spec/SPEC.md)
§9). In particular the recorded `decision_axes.fs.path_canonical` is read as
*evidence* and never resolved, stat-ed or opened — a symlink repointed after the
call ran cannot move a verdict, and an auditor on a machine that never saw the
call reads the same report.

#### Exit codes

These are API — the moment anyone scripts `if aegis recheck` in a policy-change
review, they are the contract.

| Exit | Meaning |
|------|---------|
| `0` | Every call unchanged |
| `1` | A call is newly blocked, allowed or parked — or a usage error (bad flag, missing `--policy`, missing `<PATH>`) |
| `2` | Could not read the policy or the record |
| `3` | Indeterminate — at least one call could not be answered for |

`3` outranks `1`. A run that could not answer for one call has not established
that the rest of the file is a complete diff, so reporting "some calls would now
be blocked" would invite acting on a subset as though it were the whole finding.

#### Output

stdout is a pure function of two byte strings — the policy file and the record
file. No clock, no echo of the paths you typed, no key fingerprints, so two runs
over the same bytes are byte-identical. One line per recorded outcome, in file
order, addressed by the same `session {i} seq {n}` coordinates `aegis verify`
prints, so a finding carries from one report to the other.

```
$ aegis recheck --policy new-rules.yaml session.<ext>
call call-1 session 0 seq 2: newly_blocked was=allowed now=denied
call call-2 session 0 seq 3: unchanged denied
call call-3 session 0 seq 4: unchanged pending_approval
```

The verdict clause is one of `unchanged <action>`, `newly_blocked was=… now=…`,
`newly_allowed was=… now=…`, `newly_parked was=…`, or `indeterminate <reason>`.
An action is `allowed`, `denied`, `rate_limited` or `pending_approval`; a reason
is `missing_envelope`, `envelope_digest_mismatch`, `unknown_policy_set_hash`,
`no_binding` or `rate_limit_unevaluable`.

Two of those are worth stating plainly:

- **`newly_parked` is not `newly_blocked`.** A rules change that adds a human
  review gate is a different finding from one that refuses the call outright, and
  collapsing them would let the first read as an outage. It prints no `now=`
  clause, because the only `now` available would be a `pending_approval` whose id
  this run invented.
- **`rate_limit_unevaluable` is honest, not a gap.** A rate-limit window is
  process-local counter and wall-clock state that no record carries. Calling it
  allowed or blocked would be a coin flip wearing a verdict's clothes.

A line that cannot be read as an outcome record still occupies a row — a dropped
line would make the diff quietly incomplete — as `indeterminate no_binding`, with
the parse failure explained on stderr. Exit 2 prints nothing at all on stdout:
it is "no report", not a report, so a script piping stdout into a review never
finds a half-answer there.

## Status

`aegis run` lands the AEG-30 research quickstart path. `aegis verify` lands the
AILAB-621 evidence-reading path, and `aegis recheck` the AILAB-622 what-if path.
Full admin surface / config files remain out of scope, as do follow modes for a
live record file (D3).

## Dependencies

- `botzr-aegis-runtime` for pipeline orchestration
- `botzr-aegis-capability` for `ToolManifest` registration
- `botzr-aegis-audit` for the chain walker behind `aegis verify`
- `botzr-aegis-policy` for the side-effect-free preview behind `aegis recheck` —
  a direct dependency on purpose, so a read-only forensic path cannot reach a
  component engine through the runtime
