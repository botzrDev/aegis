# Benchmarks

Published numbers on cited hardware. No number ships without a bench behind
it, and **no bench with a missed target is left out of this page**. How to run
the suite:
[`benches/README.md`](https://github.com/botzrDev/aegis/blob/main/benches/README.md).

## Targets and status

Every target the project has set, and where it stands. Do **not** conflate
these into a single threshold — they measure different things.

| Scope | Group | Target | Status |
|---|---|---|---|
| Policy eval alone | `policy_eval/allow_all`, `policy_eval/multi_rule` | < 100 µs | **pass** |
| Combined policy + capability | `hot_path/multi_rule` | < 1 ms | **pass** |
| Warm cell instantiation | `instantiation/warm` | < 0.5 ms | **pass** |
| Cold instantiation | `instantiation/cold` | < 5 ms | **miss** — 39.490 ms, ~7.9× over |
| ed25519 line signing | `audit_signing/sign_outcome_line` | < 50 µs | **pass** |
| Wrap relay per recorded `tools/call` | `wrap_relay/tools_call_recorded` | 0.5–2 ms (informational) | **miss** — 4.371 ms/call, ~2.19× over |
| Audit emission | `audit_emission/begin_complete` | no target set (fsync-bound) | n/a |
| Rate-limit path, capability alone, attribution splits | — | informational only | n/a |

**Both misses are stated rather than retired quietly.** Cold instantiation is
dominated by a Cranelift compile of the component (~29.4 ms), not by engine
setup (~1–2% of the median), so the 5 ms target does not survive contact with
an AOT compile of this size; Execution Report §7 was amended rather than the
measurement reshaped. Wrap's per-call cost is two `sync_all` calls under the
shipped G3 durability default, which alone cost ~4.2 ms on this filesystem —
reaching 2 ms needs a batched-or-deferred-fsync decision, not tuning. Neither
number was improved by narrowing a bench or adding private-API-shaped surface
(PRD §10).

The three results files follow, verbatim.

---

{{#include ../benches/results/hot_path.md}}

---

{{#include ../benches/results/cell_and_audit.md}}

---

{{#include ../benches/results/wrap_overhead.md}}
