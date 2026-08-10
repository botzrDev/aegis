# macOS confinement fast-follows M4; it does not gate it

**Status:** accepted (2026-08-10) · lands in AILAB-630, conditions AILAB-631

M4 launches with Linux-only native confinement. macOS ships everything else.

The deciding reason is not that AILAB-628's fail-closed machinery already covers the degraded case — that is plumbing, and plumbing does not justify a launch decision. It is that **the D4 demo and two of report §1's three structural gaps do not depend on confinement at all.**

## What macOS delivers at M4

Report §3's own layering for D3: native servers get OS confinement, WASM tools get the cell, and *"everything gets argument-level policy, the approval flow, and the audit chain."* Confinement is an additional layer, not the only one.

So macOS at M4 ships argument-level policy — the §6.2 hard-20% that is the actual product — plus grants, approval, schema-hash pinning, broker-level egress deny, and the full signed chain. Against §1's three gaps: **gap 2** (evidence is a feature, not a format) and **gap 3** (injection treated per-call) close completely. **Gap 1** (execution is untouched) does not. Two of three, stated plainly, is a real product.

## The threat-model distinction that carries it

Confinement defends against a **malicious or compromised server implementation** — a binary that ignores the protocol and reads `~/.ssh` directly.

The published MCP exfiltration chains do not work that way. They run prompt injection → agent calls a *legitimate* tool with malicious arguments → data leaves. That is argument-level policy territory, and argument-level policy is platform-independent.

So "D4's demo lands unprotected on macOS" is wrong. The demo's exploit is blocked on macOS by the layer that was always going to block it. What macOS lacks is defence against a category of attacker the demo does not feature.

## Consequences

- **AILAB-631 gains a selection criterion:** choose the chain so that **broker-level enforcement** — argument policy, capability, egress deny — is what blocks it, never OS confinement. Then the demo script runs identically on both platforms and the macOS gap is a documentation matter rather than a demo matter. ADR-0009's archetype already satisfies this (both legs are refused by the broker), but it should be explicit rather than lucky.
- **Gating M4 on parity would force the `unsafe` decision under launch pressure** — a project-level invariant decided by a schedule, which is the worst available way to decide one. Fast-follow decouples them.
- **The exception may not be earned, so do not grant it.** [ADR-0007](./0007-confinement-via-self-restricting-re-exec.md)'s pattern generalises further on macOS than expected: **`sandbox-exec` is the OS's own restrict-then-exec helper** — a system binary that applies a Seatbelt profile and execs the target. No FFI, no `unsafe`, no crate dependency, same process-boundary trick. ADR-0007's rule applies unchanged: escalate only if a spike shows safe is impossible.
- **Three honesty surfaces are the condition on fast-follow**, and they are where users meet the product, not a footnote. Shipping *"gate the code, not just the call"* to a macOS-majority audience while the code is not gated is the overclaim pattern again — and the one users would discover themselves.
  1. README states which layers apply per platform
  2. `aegis run` on macOS fails closed, naming exactly what is missing and what `--best-effort` gives up, with a **persistent** banner rather than a startup line
  3. The record carries `confinement: none`, so the evidence stays accurate regardless of what anyone read
- **This is what makes fast-follow defensible rather than embarrassing:** the product is incomplete, and the evidence says so.

## Why not the alternatives

**Gate M4 on parity** adds scope to a milestone whose §8 exit criteria are already written and platform-agnostic, delays launch on the platform §10.3 flags as most fragile, and partially reverses the documented decision to sequence Seatbelt after Linux precisely so a breakage would not block a milestone.

**Ship macOS as WASM-only** conflates confinement with protection. It discards the argument-level policy and audit chain that *do* work for native servers — throwing away two closed gaps to avoid admitting the third is open, and telling a macOS-majority audience they cannot wrap the servers they already run. That damages the distribution thesis more than an honest limitation does.

## Unverified — a one-day mechanism spike, not a gating question

1. Which macOS versions still ship `sandbox-exec`
2. Whether its deprecation warning goes to stderr — harmless for MCP stdio since stdout is the transport, but it should be captured so it does not confuse users
3. Whether the Seatbelt profile language can express the grant-derived scope required
4. Whether a candidate FFI crate's macOS support is real or aspirational
