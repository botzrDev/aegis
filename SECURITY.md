# Security Policy

Aegis is a research instrument for secure agent tool execution. This document
covers how to report vulnerabilities, what we support, and what is in scope.

**Threat model:** [docs/threat-model.md](docs/threat-model.md) — read this first
to understand what Aegis protects and its named non-goals. Scope of protection
and scope of disclosure are one story.

---

## Reporting a vulnerability

**Please do not open public GitHub issues for security vulnerabilities.**

Report privately to:

**Email:** [support@botzr.com](mailto:support@botzr.com)

Include:

- Description of the issue and impact
- Steps to reproduce (proof-of-concept welcome)
- Affected version or commit SHA
- Your contact for follow-up (optional)

You may also use [GitHub private vulnerability reporting](https://github.com/botzrDev/aegis/security/advisories/new)
on the repository if you prefer that channel.

### What to expect (solo maintainer SLA)

| Stage | Commitment |
|---|---|
| **Acknowledgment** | Within **72 hours** of report receipt |
| **Triage / updates** | Best effort; severity-dependent |
| **Fix & advisory** | Best effort; critical issues prioritized |
| **Credit** | With reporter permission, in the GitHub Security Advisory |

This is a solo-maintainer project. Timelines are honest estimates, not enterprise
SLAs. We appreciate responsible disclosure and will work in good faith.

### Coordinated disclosure

We follow a **90-day coordinated disclosure** window by default:

1. Reporter submits privately.
2. Maintainer acknowledges and triages.
3. Fix developed and validated.
4. Advisory published via [GitHub Security Advisories](https://github.com/botzrDev/aegis/security/advisories).
5. RustSec / `cargo audit` ecosystem notified for in-scope runtime crates when applicable.

If a fix cannot ship within 90 days, we will agree on an extension with the reporter.
Public disclosure before a fix is available should be coordinated with the maintainer.

---

## Supported versions

Pre-1.0 releases receive security fixes on the **latest minor release only**.

| Version | Supported |
|---|---|
| latest `0.x.y` on `main` | ✅ |
| older `0.x.*` tags | ❌ |

Check [releases](https://github.com/botzrDev/aegis/releases) for the current tag.
Integrators should pin to a released version and plan upgrades.

---

## In scope

Security issues in the **Aegis runtime crates** that affect confidentiality,
integrity, or availability of the enforcement pipeline:

| Crate | Scope |
|---|---|
| `botzr-aegis-core` | Types/traits used in enforcement decisions |
| `botzr-aegis-policy` | Policy evaluation bypass, silent widening |
| `botzr-aegis-capability` | Grant minting, default-deny bypass |
| `botzr-aegis-sandbox` | WASM isolation, cap-std preopens, host-function grant enforcement |
| `botzr-aegis-audit` | Record emission gaps, secret leakage in audit fields |
| `botzr-aegis-runtime` | Pipeline ordering, audit-on-all-exits |

Also in scope:

- Deny-suite or adversarial-demo tests that demonstrate a containment failure
- Resource limit bypass (memory, wall-clock, output size)
- Dependency CVEs in pinned wasmtime/cap-std when exploitable through Aegis's use

---

## Out of scope

| Category | Examples |
|---|---|
| **Layer 2 governance** | Pre-release; not part of v1 runtime |
| **Example / fixture code** | `examples/`, `tests/fixtures/damage-bot` — deliberately adversarial test guests |
| **Third-party WASM guests** | Tool code you compile and run; Aegis does not audit your guest's business logic |
| **Upstream wasmtime/cap-std** | Report to Bytecode Alliance / upstream; we track and bump pins |
| **Deployment misconfiguration** | Over-broad grants, shared host credentials, missing network segmentation |
| **Prompt injection / return-value exfil** | Named non-goals — see [threat model §6](docs/threat-model.md#6-named-non-goals) |
| **Model B marketed as full isolation** | Documentation issue if our docs are wrong; design limitation if expectations exceed Model B |

---

## Hardening recommendations for integrators

These are not Aegis bugs, but common failure modes:

1. **Keep host functions small and audited.** Every Model B import is a hole in the sandbox wall.
2. **Never configure the sandbox from the raw request** — only from the resolved grant.
3. **Use cap-std preopens** for filesystem scoping; do not hand-roll path prefix checks.
4. **Deploy process-per-tenant** for multi-tenant isolation (v1 honesty boundary).
5. **Read the threat model** before claiming isolation guarantees to downstream users.

---

## Contact

- **Security reports:** [support@botzr.com](mailto:support@botzr.com)
- **Repository:** https://github.com/botzrDev/aegis
