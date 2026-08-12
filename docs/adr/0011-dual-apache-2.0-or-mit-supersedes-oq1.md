# The workspace and the spec are dual `Apache-2.0 OR MIT`; this supersedes OQ-1

**Status:** accepted (2026-08-09) · lands in AILAB-634 · supersedes OQ-1 (closed
MIT-only 2026-07-05, AILAB-132)

`[workspace.package] license` is `Apache-2.0 OR MIT`, and
[`spec/SPEC.md`](../../spec/SPEC.md) carries the same terms. A recipient picks a
branch; nobody has to ask.

OQ-1 closed MIT-only when Aegis was a runtime and the only thing being handed to
anyone was a crate. The mission elevation on 2026-08-09 changed what is being
handed out: the Agent Action Record is a **format**, and a format's whole value
is other people implementing it. MIT is silent on patents. Silence is fine for a
crate someone links; it is a live objection for a legal team evaluating whether
their company can emit an evidence format in an audited pipeline. Apache-2.0's
§3 grant answers that objection in the license text instead of in a thread.

Dual rather than Apache-only because MIT is what the Rust ecosystem defaults to,
and dropping it would make Aegis the awkward dependency in an otherwise
`MIT OR Apache-2.0` graph. The `OR` costs nothing: consumers who want the patent
grant take Apache-2.0, consumers who want the shortest possible license file take
MIT.

## The 0.3.0 boundary

**The eight crates published to crates.io at `0.3.0` are MIT as published and
stay that way.** A registry tarball is immutable; its `license` metadata cannot
be edited after upload, and republishing a spent version number is forbidden by
the [standing rules](../release-checklist.md). Nothing was retagged and nothing
was republished for this decision. The dual license covers this repository from
the AILAB-634 commit onward and reaches the registry with the **next** release
cut.

Anyone who took `0.3.0` from crates.io holds an MIT grant and keeps it. That is
not a defect to be repaired — it is what "immutable release" means, and the same
discipline that leaves `v0.1.0` pointing at a pre-fix commit applies here.

## Consequences

- **Two license texts at the root, and a pointer.** `LICENSE-APACHE` and
  `LICENSE-MIT` hold the texts; `LICENSE` becomes a short either-or pointer
  rather than disappearing. Deleting `LICENSE` would break inbound links,
  including the ones in `0.3.0`'s published metadata.
- **`cargo deny` is unaffected.** `MIT` and `Apache-2.0` were both already in
  `deny.toml`'s allow list, and MIT-only dependencies stay compatible with either
  branch a consumer takes. The supply-chain job did not need a new entry.
- **Contributions are dual by default** — the standard Apache-2.0 §5 inbound
  clause, stated in `LICENSE` and the README. No CLA.
- **The spec's grant does not create an attribution obligation.** Emitting Agent
  Action Records requires no reference to Aegis. Vendor-neutrality is the
  property ADR-0008 protects, and a license that quietly taxed adoption would
  undo it.
- **Historical OQ-1 text is left alone.** This ADR is the supersession record;
  rewriting the 2026-07-05 decision in place would erase why MIT-only was correct
  for the shape the project had then.
