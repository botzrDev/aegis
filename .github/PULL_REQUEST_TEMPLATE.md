<!--
Security fixes: do not open a public PR for an undisclosed vulnerability.
Follow SECURITY.md first so a fix and an advisory can land together.
-->

## What this changes

<!-- One paragraph. What is different afterwards, and why. -->

## How you verified it

<!--
Name the specific thing you convinced yourself of, not just "tests pass".
If this touches a denial, trap, or resource-cap path, say what the audit
record looks like now.
-->

## Gates

- [ ] `cargo fmt --all --check`
- [ ] `cargo clippy --workspace --all-targets -- -D warnings`
- [ ] `cargo test --workspace`
- [ ] `./scripts/coverage.sh check` (baseline bumped and committed if coverage rose)
- [ ] `cd docs && mdbook build` if documentation changed

## Posture

Tick what applies; delete the rest. These are the invariants that make the
project's claims true, so a reviewer will check them regardless.

- [ ] No `unsafe` code (the workspace forbids it)
- [ ] Default-deny preserved — no new path where a missing grant means allow
- [ ] Filesystem scoping still goes through `cap-std` preopens, not prefix comparison
- [ ] Still one `Store` per call; no mutable wasmtime state shared across calls
- [ ] Any new host function enforces its grant **before** the effect
- [ ] Every new exit path emits an audit record, including errors and panics
- [ ] Pipeline order unchanged: POLICY → CAPABILITY → SANDBOX, AUDIT wrapping all three

## Documentation

- [ ] Claims in this PR were checked against source, not against other docs
- [ ] Nothing here overstates isolation, or blurs Model A, Model B, and `aegis wrap`
- [ ] Anything that exists only on `main` and not in the published `0.3.0` crates is labelled as such
- [ ] Known gaps introduced or discovered are stated rather than omitted
- [ ] ADR added under `docs/adr/` if this turns on a judgement call a future reader would have to reverse-engineer

## Related

<!-- Issues, ADRs, or prior PRs. -->
