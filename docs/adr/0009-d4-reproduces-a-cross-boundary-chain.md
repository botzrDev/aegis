# D4 reproduces a cross-boundary exfiltration chain, not a same-server one

**Status:** accepted (2026-08-10) · lands in AILAB-631

The wedge demo reproduces an exfiltration chain whose **exfiltration leg leaves the capability envelope** — reading a credential outside the grant, or egress to a host with no `NetGrant`. Not a chain where the exfiltration leg is a legitimate call to an allowlisted server.

The archetype matters more than the specific incident, because it decides D4's dependencies.

## Why

The best-known MCP exfiltration chains — the canonical example being an injected issue in a public repository driving an agent with GitHub MCP access to push private repository contents into a public PR — share a structure: **the exfiltration is an allowlisted call to an allowlisted server doing exactly what it was designed to do.** If policy permits `create_pr`, deterministic containment does not stop it. Blocking that requires data-flow taint, which is D5 — explicitly research-grade, design-doc-before-code, with no launch commitment.

A cross-boundary chain is blocked **structurally** by §6.7's egress default-deny plus AILAB-626's argument policy. D4 therefore ships on D1 + D2 + D3 with **no D5 dependency**, and the demo shows the thesis — *deterministic containment that does not weaken as models get better at evasion* — demonstrating itself, rather than a partial result.

## Consequences

- **D4 is unblocked by D5.** This is the load-bearing consequence. Had the famous chain been chosen, either D4 waits on research-grade work or it demos something it does not block.
- **Recognition is the cost, and it must not be recovered by overclaiming.** The chosen chain is less famous. The demo, the README, and any writeup must state plainly which chains Aegis does *not* block — specifically the same-server legitimate-action class — in the same breath as what it does. Report §10.5 already sets this tone (*"what this does not solve"*); the demo has to carry it too, or the project trades its claim-integrity discipline for a headline.
- **The same-server chain is the motivation for D5, and should be named as such.** It is the honest bridge from the wedge to the research direction, and it costs nothing to say.
- **The audit chain is the artifact, not a footnote.** A denial that produces a verifiable, third-party-checkable record is the part no competitor ships. The demo should end on `aegis verify`, not on the denial message.
- **The blocking layer must be the broker, never OS confinement** (added per [ADR-0010](./0010-macos-confinement-fast-follows-m4.md)). Argument policy, capability, and egress deny are platform-independent; Landlock and Seatbelt are not. The archetype above already satisfies this — both legs are refused by the broker — but it is a **selection criterion**, not a lucky property, and the demo script must run identically on Linux and macOS.
- **Specific incident selection still needs sourcing.** The archetype is decided; which published chain instantiates it must be verified against primary sources before AILAB-631 cites one, per the standing rule that a claim ships with its evidence.
