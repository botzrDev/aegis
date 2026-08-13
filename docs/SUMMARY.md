# Summary

[Introduction](intro.md)

# Guide

- [Quickstart](guide/quickstart.md)
- [The pipeline](guide/pipeline.md)
- [Trust models](guide/trust-models.md)
- [Terminology](guide/terminology.md)

# Using Aegis

- [Install](guide/install.md)
- [CLI](guide/cli.md)
- [Wrapping an MCP server](guide/wrap.md)
- [Policy YAML](guide/policy.md)
- [Library mode](guide/library.md)
- [MCP gateway](guide/mcp.md)

# Evidence

- [Threat model](threat-model.md)
- [Findings](findings.md)
- [Record format](guide/spec.md)
- [Benchmarks](guide/benchmarks.md)
- [Demos](demos/README.md)

# Reference

- [Crate map](guide/crates.md)
- [ADRs](guide/adr.md)
  - [0001 — Chain and Envelope](adr/0001-aar-chain-and-envelope.md)
  - [0002 — Verify reports coverage](adr/0002-verify-reports-coverage-not-pass-fail.md)
  - [0003 — JCS canonical form](adr/0003-jcs-json-canonical-form.md)
  - [0004 — Labelled trust](adr/0004-embedded-key-with-labelled-trust.md)
  - [0005 — Approval parks in the interposer](adr/0005-approval-parks-in-the-interposer-not-the-audit-chain.md)
  - [0006 — Matchers target derived parameters](adr/0006-matchers-target-derived-capability-parameters.md)
  - [0007 — Confinement via re-exec](adr/0007-confinement-via-self-restricting-re-exec.md)
  - [0008 — Recheck, not replay](adr/0008-d2-re-evaluation-is-recheck-not-replay.md)
  - [0009 — D4 cross-boundary chain](adr/0009-d4-reproduces-a-cross-boundary-chain.md)
  - [0010 — macOS confinement fast-follows](adr/0010-macos-confinement-fast-follows-m4.md)
  - [0011 — Dual Apache-2.0 / MIT](adr/0011-dual-apache-2.0-or-mit-supersedes-oq1.md)
- [Audit schema v1 (superseded)](audit-schema.md)
- [Security](guide/security.md)
