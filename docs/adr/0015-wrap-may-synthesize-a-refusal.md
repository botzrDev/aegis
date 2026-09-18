# Wrap may synthesize a JSON-RPC error for an opted-in enforcement refusal

**Status:** accepted (2026-09-17) · lands in AILAB-793

> **Not implemented.** This is an accepted design decision, not a description of
> shipped behaviour. Wrap on current `main` still relays every frame and
> synthesizes nothing — there is no enforcement mode to opt into, no code path
> that writes a frame the child did not produce, and
> `an_unknown_method_is_relayed_and_never_locally_refused` proves the client
> stream is the child's. The present-tense body below records the decision as
> written on 2026-09-17; it is not a product claim. Lands in AILAB-793 as
> ticketed.

Under an opted-in enforcement mode, `botzr-aegis-wrap` may write to the client a JSON-RPC `error` frame that no child produced. That is the **only** frame wrap is ever permitted to author, and it may answer only a `tools/call` that wrap refused before the request reached the child.

## The default does not change

Default wrap remains a transparent interposer. Every client frame reaches the child, every child frame reaches the client, and wrap writes no JSON-RPC of its own. That is today's behaviour and it stays the **default** after AILAB-793: enforcement is a mode an operator opts into, never a mode an `aegis wrap` invocation falls into. A default-mode wrap process is byte-identical on the client stream to one without this feature.

## Silence is not a refusal

An enforcement mode that swallows a refused `tools/call` and writes nothing back has not protected the client, it has hung it: the client is blocked on an `id` that will never be answered, and the operator is left with a timeout whose cause is invisible at the protocol layer. So when enforcement refuses a `tools/call`, wrap **must** write a well-formed JSON-RPC error to the client. A hung client is worse than a labelled one.

## The frame

```json
{
  "jsonrpc": "2.0",
  "id": "<echoed from the refused request; JSON null if the request had no id>",
  "error": {
    "code": -32042,
    "message": "aegis wrap refused this tools/call",
    "data": {
      "aegis": {
        "layer": "wrap",
        "code": "POLICY_DENIED"
      }
    }
  }
}
```

The `id` is echoed from the refused request, and a request that carried no usable `id` is answered with JSON `null` — the `id` is a placeholder in the sketch above, not a literal. `-32042` sits inside JSON-RPC 2.0's implementation-defined server-error range (`-32000`..`-32099`), so a conforming client already knows the code is the server's to define.

AILAB-793 may vary `data.aegis.code` across the gateway's existing string table (`POLICY_DENIED`, `CAPABILITY_DENIED`, … at `mcp.rs:150-165`), so that a wrap refusal and a gateway denial name the same cause with the same word. It may **not** vary `error.code`, `data.aegis.layer`, or the `error`-rather-than-`result` envelope. Those three are the shape a client integrates against, and a mode that varied them would be a mode nothing could be written against.

## Telling a wrap refusal from a genuine child error

Three signals, in increasing strength:

- **The numeric code is wrap-reserved in this project.** Zero shipped children emit `-32042`, and the one fixture child that emits a tool error uses the generic `-32000` slot (`mirror_child.rs:173`).
- **`data.aegis.layer` is the string `wrap`** — the frame names the layer that authored it, rather than leaving a reader to infer authorship from a number.
- **Once 793 lands, wrap's own audit record for that call carries the real policy-set hash and the real grant**, not the pass-through placeholders a relayed call gets today.

The JSON marker is not a cryptographic proof, and a hostile child could copy every field of it. The audit line is the evidence that the request never left wrap; the marker is a courtesy to a well-behaved client, and this ADR claims nothing more for it.

## What enforcement still relays

`-32601` stays forbidden, under enforcement exactly as without it. Unknown methods, `initialize`, `tools/list`, `ping` and notifications all still go to the child. Wrap never answers for a child that was never asked *whether the method exists* — "this call is refused" is a claim wrap is in a position to make, and "no such method" is not.

Enforcement therefore spends transparency on precisely one frame: the client-facing answer to a `tools/call` it refused. An allowed `tools/call` is relayed verbatim, its response is relayed verbatim, and every other method is untouched. Users are told so here and in the wrap crate README. `docs/wrap.md` still says nothing is ever blocked at this layer, which is true of this build and stays until 793 makes it false.

## The options rejected

- **Refuse synthesis, and keep the flat ban.** Then AILAB-793 can enforce but cannot tell the client anything, and rung 4 of the adoption ladder moves to the gateway. Rejected: wrap is the named enforcement point for an unmodified third-party server, and a hung MCP client is not a transparency feature.
- **Synthesize the gateway's `result` with `isError: true`** (`mcp.rs:141-145`). Rejected: a JSON-RPC `result` is wrap speaking *as the child*, which is the impersonation the flat ban existed to prevent. A JSON-RPC `error` is wrap speaking *as the interposer*. The gateway's shape is right for the gateway, which owns the tool call; it is wrong for a layer whose whole claim is that it is not the server.
- **Reuse `-32601` or `-32000`.** `-32601` is the specific lie `an_unknown_method_is_relayed_and_never_locally_refused` exists to prevent, and this ADR does not relax it. `-32000` is already the mirror child's tool-error code (`mirror_child.rs:173`) and the slot any real server reaches for first, so a refusal wearing it would be indistinguishable from the child answering badly.

## Consequences

- **AILAB-793 is unblocked on the client-facing shape.** The code, the envelope and the `layer` marker are settled here, so 793 argues about enforcement and not about wire format.
- **Wrap's crate graph does not grow a policy engine in *this* ticket.** Wrap depends on `audit`, `core` and `confine`, and an ADR does not add a dependency. Where the refusal decision comes from is 793's problem.
- **The pass-through `policy_set_hash` at `record.rs:30-37` becomes dishonest the moment a real engine runs.** Its doc comment records that nothing was scheduled to replace it; this decision schedules something. Replacing it is AILAB-793's acceptance criterion, not this ticket's.
- **It supersedes the flat ban in wrap's module docs and README, openly.** `record.rs` and the crate README both said wrap never synthesizes a response at all. That sentence was a correct description of the build and an over-broad promise about the design; both now point here instead. It supersedes no other ADR.
