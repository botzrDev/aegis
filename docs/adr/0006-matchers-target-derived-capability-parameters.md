# Argument matchers target derived capability parameters, not raw JSON

**Status:** accepted (2026-08-09) · lands in AILAB-626, changes [ADR-0001](./0001-aar-chain-and-envelope.md)

Report §6.2's "structured matchers over JSON arguments" is implemented as matchers over the **capability parameters the runtime derives from a call** — an `fs` path, a `net` host and port — not over raw JSON argument trees. A rule reads `deny fs.read path_under: ~/.ssh` and covers every tool regardless of whether that tool names its argument `path`, `file_path`, or `params.target.location`.

Turning arguments into axes requires a **Binding** per tool. For unmodified third-party servers, Bindings are proposed from the tool's declared schema, confirmed by a human once at first call, and pinned — with a small curated table shipped for the servers that carry the D4 demo, so the flagship path does not depend on inference quality. **The authority is the approval and the pin, never the schema.**

## Why not JSON Pointer into raw arguments

Addressing raw arguments couples policy to each tool's vocabulary. The same intent then needs one rule per tool, and a server that renames its argument after approval silently escapes the rule. Deriving the axis first makes the bypass unrepresentable: whatever the argument is called, the call either resolves to an `fs.read` on a path or it does not.

Unconfirmed schema inference was rejected in the same breath: a wrong inference is a silent policy bypass rather than a visible error. Human confirmation plus a pin converts the guess into a recorded decision.

## Scope constraint — bindings only, and it is a security property

**A Binding says *which argument is the path*. It must not be able to say *which paths are allowed*.** Authority stays in the policy set and the manifest.

This is what bounds the blast radius of the whole feature to **misidentifying a resource**, never **widening a grant** — which is in turn what makes "a human approves each Binding once" a tolerable amount of trust to place in a prompt. Get it wrong, let a binding file express `fs.read under /`, and you have shipped a policy file authored by whoever ships the MCP server.

Enforce structurally: the Binding type carries no field that could hold a limit, a scope, or a path prefix. State it as an explicit non-goal in AILAB-626 so it cannot be added later as a convenience.

This scoping is also what makes the AILAB-605 argument honest rather than rhetorical — see below.

## Consequences

- **This changes ADR-0001.** The Envelope was made a hard prerequisite for argument-level replay on the assumption that policy matches raw arguments. Derived parameters are decision axes, so they live in the Chain — `aegis replay` therefore works **chain-only even after AILAB-626 lands**, and the Envelope becomes purely forensic. The conditional-Envelope logic in AILAB-622 remains correct but should now almost never fire.
- **Derived parameters are decision axes and join the record**, under the same rule as `capability`/`role`/`session`: if replay needs it, the Chain carries it.
- **Sensitivity moves, it does not vanish.** A derived `fs_path` of `/home/a/clients/acme/notes.md` is smaller than the full argument tree but is not non-sensitive. The Chain is still the publishable artifact, so SPEC.md must say plainly that derived paths appear in it.
- **`ToolManifest` does not express Bindings today.** It declares static needs (`FsNeeds`, `NetNeeds` — *which* paths a tool may touch) with no mapping from an argument position to an axis.
- **This is the feature ticket AILAB-605 was waiting for — but only at bindings scope.** 605 (capability-*manifest* file format) was canceled because a file format would be "new product surface under a hardening heading", with the note that "if ever wanted, it earns its own feature ticket and the fuzz target follows it." Third-party servers cannot ship Rust builder calls, so Bindings must come from a file. **If the new surface recreates manifest-as-file — limits, tool kind, root paths — 605's rationale reappears legitimately and someone is right to call it relitigation.** Keeping it to bindings is what makes "earned by a shipped requirement" true. It also keeps the earned parse surface small, which keeps the fuzz target tractable.
- **Two hashes, not one.** Pin the **binding-relevant projection** of the schema to trigger re-approval, and record the **full schema** separately as evidence. A single hash over everything means a description edit re-prompts, and that churn is exactly how a human is trained to click through the one prompt that mattered.
- **The approval prompt classifies every argument, not just the bound ones.** `encoding → not a resource` gets a line. The human must be checking a complete list, not noticing an omission — the difference is invisible at two fields and decisive at twelve.
- **"Run unbound" is a required fourth choice**, alongside accept / edit / deny: the tool executes with no `fs` or `net` authority. A stranger who does not want to think about it yet gets a working, powerless tool rather than a wall. That is default-deny applied correctly, rather than default-deny as refusal.
- **AILAB-626's 8-point estimate predates all of this.** It now carries Binding surface, a file format for it, the approval integration, and the two-hash pin.
