# Trust models

Aegis supports two execution models with **different blast radii**. Conflating
them is the primary way a sandbox becomes decorative. Details:
[threat model §3](../threat-model.md#3-trust-boundaries-model-a-vs-model-b).

## Model A — WASM tool

Tool logic compiles to `wasm32-wasip2` and runs *inside* wasmtime. The guest
can only reach the outside world through WASI surfaces wired from the grant.
**Isolation is strong** because the guest cannot express an un-granted effect
— there is no syscall surface except what the host linked.

`aegis run` is Model A. The [DamageBot demo](https://github.com/botzrDev/aegis/blob/main/examples/damage-bot-demo/README.md)
is Model A (plus a Model B host-effect case).

## Model B — host function

The real side effect (HTTP, DB, exec) runs in **host Rust**, exposed to the
guest as an imported function. The sandbox isolates the guest's *decision
logic*, but the *effect* executes with **host privileges**.

**Model B is not sandbox isolation.** It is a capability-checking, auditing
proxy. Every host function must enforce the grant *before* acting; if it
skips that check, the guest gets full host authority for that effect.

Prefer Model A wherever tool logic can live in WASM. Reserve Model B for
effects that genuinely must touch the host, and keep that host-function set
small and hand-audited.

## Wrap is weaker than either

[`aegis wrap`](wrap.md) is not Model A and is weaker than Model B. The child
is an ordinary OS process. Wrap does not mint a grant, does not evaluate
policy, and does not restrict the child's filesystem or network. What it
buys is a signed record of which `tools/call`s ran.
