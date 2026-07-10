# botzr-aegis-sandbox

wasmtime sandbox for Aegis — component-model-native (`wasip2`). Station 3 of the
enforcement pipeline (POLICY → CAPABILITY → **SANDBOX** → AUDIT).

The `Engine` is process-wide (it compiles components); the `Store` is **per-call**
and dropped when the call ends — stores never share mutable state. Every store is
configured *from the resolved grant*, never from the raw request: filesystem
preopens (cap-std, escape-proof), network deny, memory cap, and wall-clock
deadline all derive from `CapabilityGrant`.

> **Model B caveat.** Host functions (`aegis:host/*`) run their effect in host
> Rust. The sandbox gives them **zero** isolation — each host function must
> enforce the grant *before* the effect (see `host.rs`). Only Model A (WASM guest
> logic) gets true wasmtime isolation. See the [threat model](../../docs/threat-model.md)
> for the full Model A vs Model B trust boundary.

## Resource accounting: epoch vs. fuel (R5)

wasmtime offers two ways to bound guest CPU. Aegis v1 uses **epoch interruption**
as the production path and **defers fuel**; the error taxonomy
(`SandboxError::from_wasmtime`) already distinguishes both axes so fuel can be
added later without a schema change.

| | **Epoch** (v1, shipped) | **Fuel** (deferred) |
|---|---|---|
| Meters | Wall-clock time | Deterministic instruction count |
| Mechanism | Background ticker (~1 ms) bumps the engine epoch; each store sets a deadline of `max_wall_ms` ticks and traps on expiry | Per-instruction fuel counter; traps at zero |
| Hot-path cost | Negligible — no per-instruction accounting | Per-instruction accounting overhead |
| Host-speed dependence | Yes — same guest, faster host ⇒ more work per budget | No — reproducible across machines |
| Audit outcome | `resource_exceeded{wall_clock}` | `resource_exceeded{fuel}` |

**Why epoch for v1.** Tool isolation asks "did this call exceed its wall-clock
budget?" — epoch answers that directly, with near-zero overhead, which keeps the
per-call cost honest for the published benchmarks. Fuel answers a *different*
question — "how much deterministic work did it do?" — which is the right tool for
**reproducible** measurement (M2 benchmarks, AEG-16) and cross-machine findings.
Fuel is therefore a candidate to run *alongside* epoch, not to replace it.

## Memory cap

The per-call `MemoryLimiter` caps guest linear-memory growth at
`grant.max_memory_bytes`. A `memory.grow` past the cap is refused **in-band**
(the guest's `memory.grow` returns `-1`), matching how a real allocator signals
failure. If the guest then touches the memory it assumed it received, it traps
out-of-bounds; because that trap was preceded by a cap-denied grow, the engine
reclassifies it to `resource_exceeded{memory}` rather than an opaque trap, so the
audit record names the real cause. A guest that handles the `-1` gracefully runs
on uninterrupted.
