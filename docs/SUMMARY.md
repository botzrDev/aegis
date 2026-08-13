# Summary

[Introduction](intro.md)

# Getting started

- [Install](install.md)
- [Quickstart](quickstart.md)

# Concepts

- [The pipeline](pipeline.md)
- [Trust models](trust-models.md)
- [Terminology](terminology.md)

# Guides

- [CLI](cli.md)
- [Wrapping an MCP server](wrap.md)
- [Policy YAML](policy.md)
- [Library mode](library.md)
- [MCP gateway](mcp.md)

# Evidence

- [Threat model](threat-model.md)
- [Findings](findings.md)
- [Record format](spec.md)
- [Benchmarks](benchmarks.md)
- [Demos](demos/README.md)

# Reference

- [Crate map](crates.md)
- [Architecture decisions](adr.md)
  - [0001 — Chain and Envelope](adr/0001-aar-chain-and-envelope.md)
  - [0002 — Verify reports coverage](adr/0002-verify-reports-coverage-not-pass-fail.md)
  - [0003 — JCS canonical form](adr/0003-jcs-json-canonical-form.md)
  - [0004 — Labelled trust](adr/0004-embedded-key-with-labelled-trust.md)
  - [0005 — Approval parks the MCP request](adr/0005-approval-parks-in-the-interposer-not-the-audit-chain.md)
  - [0006 — Matchers target derived parameters](adr/0006-matchers-target-derived-capability-parameters.md)
  - [0007 — Confinement via re-exec](adr/0007-confinement-via-self-restricting-re-exec.md)
  - [0008 — Recheck, not replay](adr/0008-d2-re-evaluation-is-recheck-not-replay.md)
  - [0009 — D4 cross-boundary chain](adr/0009-d4-reproduces-a-cross-boundary-chain.md)
  - [0010 — macOS confinement fast-follows](adr/0010-macos-confinement-fast-follows-m4.md)
  - [0011 — Dual Apache-2.0 / MIT](adr/0011-dual-apache-2.0-or-mit-supersedes-oq1.md)
- [Audit schema v1 (superseded)](audit-schema.md)
- [Security](security.md)
