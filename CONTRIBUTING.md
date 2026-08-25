# Contributing to Aegis

Thanks for looking. This document covers how to build the project, what the
gates are, and the few rules that are not negotiable because they are the
point of the project rather than style preferences.

**Security vulnerabilities do not go here.** Do not open a public issue.
Follow [SECURITY.md](SECURITY.md) — private email or GitHub private
vulnerability reporting.

## What this project is

Aegis is a **research instrument**, not a product. It exists to make claims
about agent tool isolation testable, and it is judged on whether those claims
survive inspection. That shapes what a good contribution looks like: a change
that makes a guarantee sharper, cheaper to verify, or honestly narrower is
worth more than one that adds surface area.

The v1 runtime scope is deliberately locked to five components (policy,
capability, sandbox, audit, resource accounting). Multi-agent orchestration,
dashboards, cryptographic transparency logs, and hosted services are named
non-goals — see [the threat model](docs/threat-model.md). A PR that adds one
of those will be declined however well it is written, so open an issue first
if your idea is near that line.

This is a solo-maintainer project. Review is best effort. Small, focused pull
requests get looked at; large speculative rewrites usually do not.

## Setup

```bash
git clone https://github.com/botzrDev/aegis
cd aegis
rustup target add wasm32-wasip2
cargo build --workspace
```

MSRV is **1.86** and CI enforces it explicitly. The WASM fixtures used by the
test suite are committed, so you do not need `cargo-component` unless you are
rebuilding them (`./scripts/build-fixtures.sh`).

## Gates

Run these before opening a pull request. They are the same commands CI runs,
so a green local run means a green CI run.

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
./scripts/coverage.sh check
```

CI additionally runs, and you can reproduce locally:

| Gate | Command | Notes |
|---|---|---|
| MSRV | `cargo +1.86 check --workspace --locked` | Must stay in sync with `rust-version` |
| Supply chain | `cargo deny check` | Advisories, licenses, bans, sources |
| Docs book | `cd docs && mdbook build` | mdBook **0.5.4**; a build failure fails CI |
| Fuzz smoke | `cargo +nightly fuzz run policy_yaml -- -max_total_time=60` | Nightly only; `fuzz/` is a sibling project, not a workspace member |
| Governance | `python -m pytest -q` in `governance/` | Separate Python service |

### Coverage

Coverage is a **ratchet**, not a fixed threshold: it may go up, and it may not
go down by more than a small tolerance. `./scripts/coverage.sh check` compares
against `coverage/baseline.json`. If your change legitimately raises coverage,
run `./scripts/coverage.sh bump` and commit the new baseline in the same PR.
See [the coverage ratchet doc](docs/coverage-ratchet.md).

## Rules that are not style preferences

These encode the security posture. A change that violates one is wrong even if
it compiles, passes tests, and reads nicely.

- **`unsafe_code = "forbid"`** workspace-wide. There is no escape hatch and no
  exception process.
- **Default-deny everywhere.** No ambient authority. If a capability was not
  granted, the answer is no — including on the path where an error made the
  grant unavailable.
- **`cap-std` preopens for filesystem scoping.** Never a hand-rolled
  `path.starts_with` check. Prefix comparison is not containment.
- **A `Store` per call.** Never share mutable wasmtime state across calls.
- **Host functions enforce the grant before the effect.** In Model B the
  sandbox provides no protection at all; the check in the host function *is*
  the enforcement. Getting the order wrong is a vulnerability, not a bug.
- **Audit on every exit path.** Denials, traps, resource-cap trips, and panics
  are first-class records. A silent exit is a defect.
- **Pipeline order is load-bearing:** POLICY → CAPABILITY → SANDBOX, with
  AUDIT wrapping all three. Do not reorder the stations.

### Provenance

Do not copy code from `uveddi` into this repository. It is CC-BY-NC-SA and
this project ships under permissive terms; reimplement from the design
reference instead. More generally, only contribute code you wrote or that is
compatibly licensed, and say so in the PR if any part came from elsewhere.

## Documentation

Documentation is held to the same standard as the code, because a false claim
in a security doc is a security defect.

- **Verify claims against source, not against other docs.** If a README says
  a function takes two arguments, check the signature.
- **Never overstate isolation.** Model A (logic inside wasmtime) and Model B
  (effect in host Rust, capability check plus audit only) must not be blurred,
  and `aegis wrap` records without confining anything. If a sentence could
  leave a reader believing something is blocked when it is not, rewrite it.
- **Distinguish `main` from the published release.** The crates.io `0.3.0`
  crates predate several features documented here. If you document something
  that only exists on `main`, say so at the point of the claim.
- **Name gaps rather than omitting them.** When `aegis wrap` is SIGKILLed its
  `AuditWriter` never drops, so the Session has no signed `close` line and a
  verifier reports `Indeterminate` rather than `Verified`. That is written down
  in `crates/botzr-aegis-wrap/DECISIONS.md` rather than glossed. That is the
  expected standard.

The book lives in `docs/` and is published to
<https://botzrdev.github.io/aegis/>. Add new chapters to `docs/SUMMARY.md`.

## Decisions

Architectural decisions land as ADRs in `docs/adr/`, numbered sequentially.
If your change turns on a judgement call that a future reader would otherwise
have to reverse-engineer — a trade-off, a rejected alternative, a deliberate
limitation — write the ADR alongside the code. An accepted ADR records a
decision; it is not a claim that the thing shipped.

## Pull requests

- One logical change per PR. Split refactors out from behaviour changes.
- Commit messages follow the conventional prefixes already in the log:
  `feat:`, `fix:`, `docs:`, `ci:`, `chore:`, `refactor:`, `test:`.
- Commits are SSH-signed. If signing fails, `ssh-add` your key.
- New behaviour needs a test. Behaviour on a denial or error path needs a test
  that asserts the audit record, not just the return value.
- Say what you verified and how. "Tests pass" is weaker than naming the
  specific case you convinced yourself about.

## Licensing of contributions

The repository is dual-licensed **Apache-2.0 OR MIT**. By contributing, you
agree that your contribution is licensed under the same terms, at the
recipient's option. (The `0.3.0` tarballs already published to crates.io were
cut under MIT alone; everything after is dual — see
[ADR-0011](docs/adr/0011-dual-apache-2.0-or-mit-supersedes-oq1.md).)
