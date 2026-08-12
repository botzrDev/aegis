# Aegis release checklist

> **Status:** v0.3.0 (AILAB-608) · **Last updated:** 2026-08-12 (AILAB-636 coverage gate)
> **Related:** [CHANGELOG](../CHANGELOG.md) · [Findings](findings.md) · [Threat model](threat-model.md) · [Coverage ratchet](coverage-ratchet.md) · [SECURITY.md](../SECURITY.md)

Cutting a release means putting immutable artifacts on crates.io under the Aegis
name. **Steps 3–6 are run by the maintainer, not by an agent.** An agent may
prepare the tree — version reconciliation, changelog, lockfiles — and may run
the read-only verification in steps 1–2. Tagging, publishing, and cutting the
GitHub release are manual, because each is irreversible: a published version can
be yanked but never replaced, and a moved tag silently invalidates every
reference to it.

The workspace versions in lockstep. All eight `botzr-aegis-*` crates carry the
same number, inherited from `[workspace.package]`; there are no per-crate
version overrides. If you find one, reconcile it before releasing rather than
publishing a split set — the 0.1.0/0.1.1/0.2.0 skew that AILAB-608 unwound is
what this rule exists to prevent.

---

## 1. Pre-flight

- Working tree clean: `git status --porcelain` produces no output.
- On `main`, and `origin/main` is up to date: `git fetch origin && git status -sb`
  reports no ahead/behind divergence. An unpushed commit means the tag would
  point at something the public repo does not have.
- The version in `[workspace.package]` is the version you intend to publish, and
  it is **not** already on crates.io. Check the registry, not just the tree.
- [`CHANGELOG.md`](../CHANGELOG.md) has an entry for this version, and the
  `— unreleased` marker is removed and replaced with the release date.
- **License expression check.** Since AILAB-634 the workspace declares
  `license = "Apache-2.0 OR MIT"`, which every published crate inherits through
  `license.workspace = true` — confirm with
  `cargo metadata --no-deps --format-version 1`. The crates published at `0.3.0`
  carry MIT in their registry metadata and stay that way: that metadata is
  immutable, so the first dual-licensed tarballs are the ones cut **after**
  `0.3.0`. Do not republish or retag `0.3.0` to "fix" it. (The license *texts*
  live at the repo root, not inside each crate directory, so they are not in the
  tarballs — same as `0.3.0`. Changing that means adding per-crate license files,
  which is not part of AILAB-634.)

## 2. Full CI-equivalent locally

Run all five. Every one must be clean before proceeding.

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo +1.86 check --workspace --locked
./scripts/coverage.sh check
```

**Coverage is release-blocking.** The tagged commit must pass the same ratchet CI
enforces on `main`: if total line coverage sits below
[`coverage/baseline.json`](../coverage/baseline.json), the release does not go
out. A deliberate drop is handled by editing the baseline in the PR that caused
it — with a rationale, per [`coverage-ratchet.md`](coverage-ratchet.md) — never
by skipping the check at release time. The run needs `cargo-llvm-cov` and takes
around ten minutes.

The MSRV command is the one that catches a stale or uncommitted `Cargo.lock` —
it is what the MSRV job runs in CI. If it fails with a lockfile-needs-update
error, regenerate and commit `Cargo.lock`. Never drop `--locked` or add
`--offline` to make it pass; that hides the failure rather than fixing it.

`fuzz/` is a sibling project with its own lockfile and nightly toolchain. If a
crate version changed, regenerate `fuzz/Cargo.lock` too:
`cd fuzz && cargo +nightly check`.

## 3. Dry-run each crate, in dependency order

*Maintainer.* Same order as step 5 — a dry run of a dependent crate resolves its
`botzr-aegis-*` dependencies from the registry, so it can only succeed once the
tier below it is actually published. Expect the dry run of a dependent tier to
fail against the registry until its dependencies land; run the tiers in order
and treat a failure in tier 1 as blocking.

```bash
cargo publish --dry-run -p botzr-aegis-core
# …then each crate in the step 5 order
```

## 4. Tag

*Maintainer.* Signed, using the SSH signing key (`id_ed25519`; if signing fails,
unlock with `ssh-add`).

```bash
git tag -s v0.3.0 -m "v0.3.0"
git push origin v0.3.0
```

## 5. Publish, in dependency order

*Maintainer.* Wait for the crates.io index to catch up between tiers — the next
tier resolves its dependencies from the registry, not from the local path, so
publishing ahead of the index fails.

```bash
# Tier 1 — no in-workspace dependencies
cargo publish -p botzr-aegis-core

# Tier 2 — each depends on core only
cargo publish -p botzr-aegis-policy
cargo publish -p botzr-aegis-capability
cargo publish -p botzr-aegis-sandbox
cargo publish -p botzr-aegis-audit

# Tier 3 — depends on audit, capability, core, policy, sandbox
cargo publish -p botzr-aegis-runtime

# Tier 4 — each depends on capability, core, runtime
cargo publish -p botzr-aegis-mcp
cargo publish -p botzr-aegis-cli
```

## 6. Post-release

*Maintainer.*

- Update the README **Status** section to reflect the new tag and the published
  versions. This edit follows the tag rather than preceding it: until the tag
  exists, the old Status text is still accurate.
- Cut the GitHub release for the tag, referencing the CHANGELOG entry for this
  version.
- Verify each crate resolves from the registry in a scratch project outside the
  workspace — a clean `cargo add botzr-aegis-runtime` is the cheapest check that
  the published manifests are self-contained.

## 7. Standing rules

These hold across every release; violating one is not recoverable.

- **Never move or replace an existing tag.** `v0.1.0` points where it points,
  even though the published crates came from a later commit
  (`196ada6`) — the tag predates the manifest publishability fix. Record the
  discrepancy; do not retag.
- **Never republish a version already on crates.io.** A version is permanent
  once uploaded. It can be yanked, which stops new resolution, but the number is
  spent — pick the next one. This is why 0.2.0 could not be reused for the
  0.3.0 tranche.
- **Every `botzr-aegis-*` entry in `[workspace.dependencies]` keeps both `path`
  and `version`.** Dropping `path` breaks local builds; dropping `version`
  breaks `cargo publish`, which cannot resolve a bare path dependency from the
  registry. This failed AEG-31 pre-flight once already.
- **Never promote `fuzz/` to a workspace member.** It stays in
  `[workspace] exclude` — libFuzzer needs nightly, while the workspace pins 1.86
  with `unsafe_code = forbid`.
- **Never touch `scripts/reserve-crates/stubs/`.** Those are retired
  name-reservation manifests, including the yanked `botzr-aegis-sidecar`. They
  are deliberately frozen and are not part of any release.
- **`examples/` and `tests/fixtures/` are `publish = false`** and stay pinned at
  their own versions. They are never published; churning them adds diff noise to
  every release.
