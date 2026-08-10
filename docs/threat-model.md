# Aegis threat model

> **Status:** v0.1 draft (AEG-17 / OQ-15 T6) · **Last updated:** 2026-07-16 (AEG-36 Part B review)  
> **Related:** [SECURITY.md](../SECURITY.md) · [Audit schema freeze](audit-schema.md) · [DamageBot demo](../examples/damage-bot-demo/README.md) · [Benchmarks](../benches/results/hot_path.md)  
> **Part B review:** [OQ-15 peer review (#19)](https://github.com/botzrDev/aegis/issues/19)

Aegis is a **research instrument** for testing what agent tool isolation actually
guarantees. This document states what the runtime protects, what it does not, and
how that compares to other approaches. It is written for security reviewers,
integrators, and anyone evaluating claims about agent tool execution.

**We do not claim foolproof security.** Aegis is defense-in-depth with an explicit
threat model and named non-goals. Any sentence that sounds absolute should be read
as "absolute **within the stated threat model**."

---

## 1. Scope

### In scope (v1 runtime)

The `botzr-aegis-*` crates implement a four-station enforcement pipeline for
agent tool calls:

```
POLICY → CAPABILITY → SANDBOX → AUDIT
```

Every call walks this order. Audit wraps all three inner stations and emits a
record on **every** exit path — allow, deny, trap, resource cap, or panic.

| Station | Role |
|---|---|
| **Policy** | Role gate, approval gate, rate limits (sync; parsed-once `Arc<PolicySet>`) |
| **Capability** | Default-deny manifest resolution → minted grant (denial never reaches sandbox) |
| **Sandbox** | Configure wasmtime `Store` **from the grant**, then run (per-call store; epoch + memory limits) |
| **Audit** | Schema-versioned JSONL records (`schema_version: 2`), hash-chained and ed25519-signed; no raw secrets — the shipped payload digests are `request_digest` / `response_digest` ([record format](../spec/SPEC.md)) |

### Out of scope (v1)

- Layer 2 governance (LLM-side guardian, approval UX, policy authoring)
- Multi-agent orchestration, dashboards, SaaS hosting
- Cryptographic audit proofs or tamper-evident log chains
- Output DLP / content filtering on return values (see [§6 Non-goals](#6-named-non-goals))
- Credential injection as a first-class capability (design reserved; host env reality today)
- In-process multi-tenancy (v1 = process-per-tenant deployment pattern)

---

## 2. Assets and adversaries

### Assets we protect

| Asset | Why it matters |
|---|---|
| **Host filesystem** outside granted preopens | Prompt-injected agents must not read/write arbitrary paths |
| **Host network** outside granted hosts | Exfiltration and lateral movement via outbound HTTP |
| **Capability grant integrity** | The grant is the sole authority that configures the sandbox |
| **Audit trail integrity** | Forensics and accountability for every tool call |
| **Host process stability** | Runaway or malicious guests must not exhaust host resources indefinitely |
| **Caller secrets in tool input** | Raw secrets must not appear in audit records |

### Adversaries assumed

| Adversary | Capability |
|---|---|
| **Malicious tool guest (Model A)** | Arbitrary WASM logic; attempts path escape, symlink tricks, resource exhaustion, WASI abuse |
| **Malicious tool guest via host imports (Model B)** | Calls host functions with crafted URLs/paths; relies on host-side grant enforcement |
| **Prompt-injected agent (upstream)** | Selects tools and arguments adversarially; may attempt bulk reads or staged exfil |
| **Misconfigured operator** | Over-broad grants, missing host-function checks, shared host credentials |
| **Compromised host process** | Attacker with host-level access — outside Aegis's isolation boundary |

We do **not** assume a compromised wasmtime engine, a broken cap-std implementation,
or a kernel-level attacker. Those are platform dependencies, not Aegis guarantees.

---

## 3. Trust boundaries: Model A vs Model B

Aegis supports two tool execution models with **different blast radii**. Conflating
them is the primary way a sandbox becomes decorative.

### Model A — WASM tool (logic inside wasmtime)

The tool compiles to `wasm32-wasip2` and runs inside wasmtime. The guest can only
reach the outside world through WASI surfaces wired from the grant:

- Filesystem: `cap-std` preopens (no hand-rolled `path.starts_with`)
- Network: no socket factories unless explicitly granted (default deny)
- Memory / CPU: per-call `MemoryLimiter` + epoch interruption

**Isolation is strong** because the guest cannot express an un-granted effect — there
is no syscall surface except what the host linked.

Evidence: [DamageBot demo](../examples/damage-bot-demo/README.md) — write under
read-only grant, `..` traversal, symlink escape all refused at the WASI/cap-std
boundary.

### Model B — host function (effect in host Rust)

Real side effects (HTTP, DB, exec) run in **host Rust**, exposed to the guest as
imported functions. The WASM sandbox isolates the guest's *decision logic*, but the
*effect* executes with **host privileges**.

> **Model B is not sandbox isolation.** It is a capability-checking, auditing proxy.
> The sandbox gives **zero** protection for host-side effects. Every host function
> must independently enforce the grant **before** acting. If a host function skips
> that check, the guest can invoke the host with full host authority for that effect.

Evidence: DamageBot `http_exfil` cases — grant gate enforced in `host.rs`; calls
without `NetGrant` or to disallowed hosts are refused and audited.

#### Context-owned effects vs the raw closure escape hatch

Model B enforcement is **not uniform**, and the difference is load-bearing:

| Path | Enforcement | Status |
|---|---|---|
| `HostEffectContext` methods (`http_get`, `open_read`, `open_write_append`, `log_emit`), reached via the handler registered with the tool and run by `Runtime::execute_host_call` | **Structural** — the grant is checked before any effect, and FS access is a cap-std `Dir` opened from the grant, so an un-granted path is unreachable rather than merely unchecked | Supported |
| Raw closure passed to `Runtime::execute_host_call_with` | **Convention only** — the runtime hands the closure a `&CapabilityGrant` and checks nothing before the effect runs; it applies the output cap afterwards | Research escape hatch |

The structural guarantee described in this document covers **context-owned effects
only**. A raw closure that forgets its check is exactly the "missing grant check in
a new host function" residual risk below — the runtime cannot catch it. The closure
API is kept deliberately for research and experiment wiring; Aegis-owned effects
must go through `HostEffectContext`.

Neither path is sandbox isolation. `HostEffectContext` narrows *which* effects a
grant can reach; it does not contain the effect once it runs in host Rust.

**Design consequence:** keep the host-function set small and hand-audited. Prefer
Model A wherever tool logic can live in WASM; reserve Model B for effects that
genuinely must touch the host.

---

## 4. What the pipeline guarantees (within scope)

When correctly configured and integrated, Aegis v1 aims to ensure:

1. **Default deny.** Unregistered tools, undeclared capabilities, and policy
   denials never reach sandbox instantiation.
2. **Grant-driven sandbox config.** The `Store` is configured from the resolved
   grant, never from the raw request.
3. **Filesystem containment (Model A).** cap-std preopens block `..` traversal,
   symlink escape, and TOCTOU races that defeat naive path-prefix checks.
4. **Network containment (Model B).** Host HTTP imports check `NetGrant.http`
   allow-list entries (`host` / `ports` / `methods`) before any outbound request.
5. **Resource bounds.** Per-call memory cap, epoch wall-clock budget, and
   `max_output_bytes` limit unbounded guest output. The output cap is enforced
   **orchestrator-side** on the bytes a call returns — not a wasmtime store
   limit — and applies identically to Model A sandbox output and Model B host
   effects; oversize output fails closed (`ResourceExceeded { kind: "output" }`),
   never truncated-and-returned.
6. **Audit on every exit.** Denials, traps, resource caps, and panics produce
   schema-versioned JSONL records without raw secret payloads. v0.1 persists via
   `AuditWriter` (per-line fsync) only — OpenTelemetry / OTLP export is
   **deferred** (not shipped). Wire contract: [`spec/SPEC.md`](../spec/SPEC.md).

Operational meaning of "foolproof" in this project: **no single mistake — a forgotten
host check, a malformed policy, a panicking host function — escalates into ambient
authority.** That is the design goal. A literal guarantee against all attack classes
is not.

---

## 5. Approach comparison (named context, not a bake-off)

Different isolation approaches protect different things. Aegis uses WASM + capability
grants; it does not replace network policy, kernel instrumentation, or human review.

| Approach | What it protects well | What it does **not** protect |
|---|---|---|
| **eBPF / LSM (kernel)** | Syscall-level enforcement on known processes; network egress at the host | Tool semantics, prompt-injected argument choices, return-value exfil to the LLM, WASM guest logic before syscalls |
| **Network proxy / MCP gateway** | Egress filtering, request logging, rate limits at the wire | In-process filesystem access, host-function effects that bypass the proxy, semantic abuse of legitimately granted reads |
| **WASM sandbox (Model A)** | Guest cannot express un-granted effects; strong containment for compiled tools | Only applies when tool logic runs in WASM; does not help host-side effects; adoption tax for non-Rust/non-wasip2 tools |
| **Capability proxy (Model B)** | Audited, grant-gated host effects; drop-in for existing tools | **Not** sandbox isolation — host function bugs = full host effect; equivalent blast radius to a well-audited proxy if checks are correct |
| **Behavioral / LLM guardian (Layer 2)** | Semantic policy on tool *intent* and conversation context | Not a substitute for runtime enforcement; can be prompt-injected; correctly deferred post-v1 |

Aegis composes **policy + capability + sandbox + audit** for the tool-call path.
It is not a replacement for kernel hardening, network segmentation, or secrets
management outside the runtime.

---

## 6. Named non-goals

These are **explicit gaps**, not oversights. Naming them is part of the credibility
story — a security reviewer finding an unnamed gap is the failure mode we avoid.

### G9 — Exfiltration via return values

Capabilities gate what a tool can **do**, not what data flows **back** to the LLM.
A tool legitimately granted `fs.read` can return file contents to a prompt-injected
agent that leaks them in a later turn. **v1 does not solve this.**

Partial mitigations that exist today:

| Mitigation | Effect |
|---|---|
| `max_output_bytes` | Caps single-call return size, runtime-enforced on returned bytes (default 1 MiB) |
| `input_digest` in audit | Forensic trail of call **input** without storing raw args (Intent + Outcome); derived by the runtime from the call's own bytes, so a caller cannot record a digest that does not match the payload |
| Policy rate limits | Friction on bulk read patterns |

**Not shipped (deferred):** `output_digest` is **absent** from `AuditIntent` /
`AuditRecord` in schema v1 — do not treat it as a current mitigation. Adding it
end-to-end (types + goldens + writer) is future work, not a v0.1 claim.

Full output DLP / content filtering is a candidate for a future enterprise tier
(Layer 2 guardian), not v1.

### Model B is not isolation

Do not market Model B host functions as "sandboxed." They are grant-checked,
audited proxies. Isolation guarantees for Model B are exactly as strong as the
hand-audited host-function set.

`HostEffectContext` does not change that. It makes the *check* structural for the
effects it owns (§3), so those effects cannot skip the grant — but the effect still
executes with host privileges. Effects wired through the raw
`execute_host_call_with` closure are not even structurally checked; they remain
convention-checked by their author.

### Host environment credentials (until credential injection ships)

Model B host functions that call real APIs may inherit the host process's ambient
credentials (env vars, IAM roles, kube service accounts). Aegis does not yet inject
scoped credentials per grant (G6 — reserved for v1.5+). Operators must treat the
host process as the credential boundary.

### Prompt injection upstream of the runtime

Aegis enforces at the **tool call** boundary. It does not prevent an agent from
choosing a legitimately granted tool with adversarial arguments, nor from relaying
returned data in natural language. That is an agent-framework and governance problem.

### Compromised host / operator

If the host OS, Aegis process, policy files, or manifests are attacker-controlled,
runtime guarantees do not apply. Process-per-tenant deployment is the v1 honesty
boundary for multi-tenancy.

### Every tool / every LLM

v1 targets one real tool E2E and a deny suite, not universal tool coverage. The
`wasip2` adoption tax means most existing Python agent tools fall back to Model B
unless rewritten as WASM components.

### Absolute / "foolproof" claims

We will not claim Aegis makes agent tool execution foolproof. Defense-in-depth with
honest non-goals is the product posture.

---

## 7. Residual risks

| Risk | Severity | Notes |
|---|---|---|
| Missing grant check in a new host function | **Critical** | #1 sandbox bypass for Model B; mitigated by keeping the host-function set tiny and routing Aegis-owned effects through `HostEffectContext`. Raw `execute_host_call_with` closures remain exposed to this |
| Hand-rolled path checks instead of cap-std | **High** | Bypassable via `..`, symlinks, TOCTOU — use cap-std preopens for Model A |
| Policy evaluated after capability minted | **High** | Pipeline order violation; denied calls must never get a `Store` |
| Hung Model B I/O ignoring epoch | **Medium** | Wall-clock timeout + cancellation token required for host I/O |
| Audit sink failure | **Medium** | Fail-closed vs fail-open is a deployment choice (see G3) |
| wasmtime / cap-std CVE | **Platform** | Track upstream advisories; in-scope for [SECURITY.md](../SECURITY.md) |
| Return-value exfil (G9) | **Accepted non-goal** | Partial mitigations only |

---

## 8. Evidence artifacts (not proof)

These in-repo artifacts support the claims above. They demonstrate specific
containment cases; they do not exhaust all attack classes.

| Artifact | What it shows |
|---|---|
| [DamageBot demo](../examples/damage-bot-demo/README.md) | Six adversarial cases through `Runtime::execute_tool_call` |
| [Deny suite](../tests/deny-suite/) | Policy/capability/sandbox denial paths + audit emission |
| [Record format spec](../spec/SPEC.md) | Field-level line contract, chain rule, verdict model, and the non-guarantees stated plainly |
| [Hot-path benchmarks](../benches/results/hot_path.md) | Policy ≪ 100 µs; combined pipeline ≪ 1 ms (cited hardware) |
| [Findings report](findings.md) | Measured guarantees vs named gaps; reproducible case studies + evidence bundle script |

A passing demo is evidence, not certification. This threat model is the explicit
statement of scope.

---

## 9. Reporting security issues

See [SECURITY.md](../SECURITY.md) for private disclosure, supported versions, and
coordinated disclosure policy.

---

## Decision references

Built against Gap Resolutions G9 (return-value exfil non-goal) and G15 (security
response process), OQ-15 T6 (written threat model), AEG-35 (audit-field honesty vs
shipped `audit.rs` / schema freeze), AEG-36 (OQ-15 Part B structured review —
[issue #19](https://github.com/botzrDev/aegis/issues/19)), and the Hardened
Implementation Design trust-model sections. Amendments should be logged in project
planning docs and reflected here.
