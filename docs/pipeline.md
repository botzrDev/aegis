# The pipeline

Every tool call walks the same four stations, in this order (load-bearing —
audit wraps the inner three):

```
POLICY → CAPABILITY → SANDBOX → AUDIT
```

| Station | Role |
|---|---|
| **Policy** | Role gate, approval gate, rate limits — sync eval over a parsed-once, immutable `PolicySet` the engine holds in an `ArcSwap` for hot reload |
| **Capability** | Default-deny manifest resolution → minted grant; a denial never reaches the sandbox |
| **Sandbox** | Configure a **per-call** wasmtime `Store` **from the grant**, then run (cap-std preopens; epoch + memory limits) |
| **Audit** | Schema-versioned record emitted on **every** exit — allow, deny, trap, resource cap, or panic — with no raw secret payloads |

Do not reorder the stations. A policy or capability denial never instantiates
a `Store`. Constants in `botzr-aegis-core`:

```rust
pub const PIPELINE_STAGES: &[&str] = &["policy", "capability", "sandbox", "audit"];
pub const HOST_PIPELINE_STAGES: &[&str] = &["policy", "capability", "audit"];
```

`HOST_PIPELINE_STAGES` is [Model B](trust-models.md): the effect runs in host
Rust, so there is no sandbox station.

## What each station does not do

- **Policy** does not inspect call arguments. Matchers are `tool`,
  `capability`, and `role` only. See [Policy YAML](policy.md).
- **Capability** never raises a grant. A policy ceiling can only narrow.
- **Sandbox** gives [Model B](trust-models.md) host functions **zero**
  isolation. Each host function must enforce the grant before the effect.
- **Audit** is not a public transparency log. It is a hash-chained,
  ed25519-signed JSONL file. Truncation of an unanchored tail is undetectable
  from the chain alone ([ADR-0002](adr/0002-verify-reports-coverage-not-pass-fail.md)).
