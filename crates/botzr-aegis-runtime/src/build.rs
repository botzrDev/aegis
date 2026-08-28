//! Shared runtime construction facade (AEG-44 §3.D).
//!
//! MCP and CLI both need the same three-step wiring — optional policy YAML,
//! optional audit sink, otherwise the library defaults — and had drifted into
//! two hand-rolled copies. [`RuntimeBuilder`] is the single place that wiring
//! lives, so consumer crates never call [`PolicyEngine::from_yaml`] or
//! [`AuditWriter::open`] directly.

use std::path::{Path, PathBuf};

use botzr_aegis_audit::{load_signing_key, AuditError, AuditWriter};
use botzr_aegis_policy::PolicyEngine;
use thiserror::Error;

use crate::Runtime;

/// Failure while assembling a [`Runtime`] from configuration.
#[derive(Debug, Error)]
pub enum BuildError {
    #[error("read policy {path}: {source}")]
    ReadPolicy {
        path: PathBuf,
        source: std::io::Error,
    },

    #[error("parse policy: {0}")]
    ParsePolicy(String),

    #[error("open audit {path}: {source}")]
    OpenAudit { path: PathBuf, source: AuditError },

    /// The signing key for a persistent audit sink could not be loaded. Fatal
    /// on purpose: there is no fallback key, so a build that cannot sign must
    /// not hand back a runtime that emits records anyway.
    #[error("load signing key {path}: {source}")]
    LoadSigningKey { path: PathBuf, source: AuditError },
}

/// Builder for a configured [`Runtime`].
///
/// Every field is optional; an unset field keeps the [`Runtime::default`]
/// behaviour (`PolicyEngine::allow_all()` and a Volatile in-memory audit
/// sink — records are emitted, and nothing is retained). Tool
/// registration is deliberately *not* part of the builder — it stays on
/// [`Runtime::register_tool`] so catalogs remain the consumer's business.
#[derive(Default)]
pub struct RuntimeBuilder {
    policy: Option<PolicyEngine>,
    audit: Option<AuditWriter>,
}

impl RuntimeBuilder {
    /// Start from the library defaults.
    pub fn new() -> Self {
        Self::default()
    }

    /// Parse a policy document once, up front.
    ///
    /// Fallible here rather than at [`Self::build`] so the caller learns which
    /// input failed at the point it was supplied.
    pub fn policy_yaml(mut self, yaml: &str) -> Result<Self, BuildError> {
        let engine =
            PolicyEngine::from_yaml(yaml).map_err(|e| BuildError::ParsePolicy(e.to_string()))?;
        self.policy = Some(engine);
        Ok(self)
    }

    /// Read and parse a policy file once, up front.
    pub fn policy_file(self, path: &Path) -> Result<Self, BuildError> {
        let yaml = std::fs::read_to_string(path).map_err(|source| BuildError::ReadPolicy {
            path: path.to_path_buf(),
            source,
        })?;
        self.policy_yaml(&yaml)
    }

    /// Append audit records to `path`, signed by the key at `signing_key` —
    /// the only way to get a Chain that outlives the process, since the default
    /// sink is Volatile and in memory.
    ///
    /// The key path is **required**, not optional (AILAB-620). A persistent sink
    /// is a file somebody will later pin a `Verified (pinned to <fp>)` label to,
    /// and this call used to sign every one of them with `insecure_dev_key` — a
    /// seed compiled into the published audit crate. Pinning a published secret
    /// is worse than not pinning at all, so there is no overload that omits the
    /// key and no fallback if it fails to load. Generate one with
    /// `aegis keygen --out <PATH>`.
    ///
    /// The dev key survives only where it cannot be mistaken for provisioned
    /// authority: the Volatile in-memory sink [`Runtime::new`] opens, whose
    /// bytes nobody can pin a label to afterwards, and tests. A Durable sink
    /// refuses it outright (ADR-0012), so this method could not fall back to it
    /// even if it wanted to.
    pub fn audit_file(mut self, path: &Path, signing_key: &Path) -> Result<Self, BuildError> {
        let key = load_signing_key(signing_key).map_err(|source| BuildError::LoadSigningKey {
            path: signing_key.to_path_buf(),
            source,
        })?;
        let writer = AuditWriter::open(path, key).map_err(|source| BuildError::OpenAudit {
            path: path.to_path_buf(),
            source,
        })?;
        self.audit = Some(writer);
        Ok(self)
    }

    /// Assemble the runtime, applying only the options that were set.
    pub fn build(self) -> Result<Runtime, BuildError> {
        let mut rt = Runtime::new();
        if let Some(policy) = self.policy {
            rt = rt.with_policy(policy);
        }
        if let Some(audit) = self.audit {
            rt = rt.with_audit(audit);
        }
        Ok(rt)
    }
}

impl std::fmt::Debug for RuntimeBuilder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RuntimeBuilder")
            .field("policy", &self.policy.is_some())
            .field("audit", &self.audit)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use botzr_aegis_audit::Retention;
    use botzr_aegis_core::{AegisError, ToolId};
    use botzr_aegis_policy::CallAxes;

    use crate::ToolCallRequest;

    const DENY_YAML: &str = r#"
version: 1
default: allow
rules:
  - id: block-smoke
    action: deny
    tool: smoke
    reason: "blocked by builder policy"
"#;

    #[test]
    fn defaults_match_runtime_new() {
        // An empty builder must not change behaviour: allow-all policy and the
        // Volatile in-memory audit sink `Runtime::new()` opens.
        //
        // Asserted against the absolute value, not against
        // `Runtime::new().audit().retention()`: `build()` starts from
        // `Runtime::new()`, so comparing the two would hold for any default
        // whatsoever, including a regressed one.
        //
        // What no test here can reach: that the default sink *retains* the
        // lines it accepts. It hands out no reader by construction — that is
        // the point of it — so every assertion on recorded bytes injects its
        // own `MemoryChainSink`. Construction succeeding does prove the `Open`
        // line was accepted, since `with_sink` is fail-closed and `Default`
        // unwraps it.
        let rt = RuntimeBuilder::new().build().expect("default build");
        assert_eq!(rt.audit().retention(), Retention::Volatile);
        assert!(rt.audit().path().is_none());
        // allow-all policy → an unregistered tool is stopped by capability,
        // never by policy.
        let tool = ToolId::new("unregistered");
        let err = rt
            .execute_tool_call(ToolCallRequest::new(
                tool.clone(),
                b"{}",
                CallAxes::default(),
            ))
            .unwrap_err();
        assert!(
            matches!(err, AegisError::CapabilityDenied { .. }),
            "expected CapabilityDenied, got {err:?}"
        );
    }

    #[test]
    fn policy_yaml_is_applied_and_parse_errors_surface() {
        let rt = RuntimeBuilder::new()
            .policy_yaml(DENY_YAML)
            .expect("valid yaml")
            .build()
            .expect("build");
        let tool = ToolId::new("smoke");
        let err = rt
            .execute_tool_call(ToolCallRequest::new(
                tool.clone(),
                b"{}",
                CallAxes::default(),
            ))
            .unwrap_err();
        assert_eq!(
            err,
            AegisError::PolicyDenied {
                reason: "blocked by builder policy".into()
            }
        );

        let err = RuntimeBuilder::new()
            .policy_yaml("version: 99\ndefault: allow\nrules: []\n")
            .expect_err("unsupported version must not build");
        assert!(matches!(err, BuildError::ParsePolicy(_)), "{err:?}");
    }

    #[test]
    fn policy_file_reports_missing_path() {
        let missing = std::env::temp_dir().join("aegis-no-such-policy-file.yaml");
        let err = RuntimeBuilder::new()
            .policy_file(&missing)
            .expect_err("missing policy file must fail");
        assert!(matches!(err, BuildError::ReadPolicy { .. }), "{err:?}");
    }

    /// A provisioned key for a persistent sink, the way an operator gets one:
    /// `aegis keygen` into a file, then hand the builder the path.
    fn temp_signing_key(dir: &Path) -> PathBuf {
        let path = dir.join("signing.key");
        botzr_aegis_audit::generate_signing_key(&path, false).expect("generate signing key");
        path
    }

    #[test]
    fn audit_file_redirects_the_sink() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested/audit.jsonl");
        let key = temp_signing_key(dir.path());
        let rt = RuntimeBuilder::new()
            .audit_file(&path, &key)
            .expect("open audit")
            .build()
            .expect("build");
        assert_eq!(rt.audit().path(), Some(path.as_path()));

        let tool = ToolId::new("unregistered");
        let _ = rt.execute_tool_call(ToolCallRequest::new(
            tool.clone(),
            b"{}",
            CallAxes::default(),
        ));
        let text = std::fs::read_to_string(&path).expect("audit file written");
        // The writer is the Session owner, so the file opens with an `open`
        // line carrying the public key; the Call's intent follows it.
        let lines: Vec<&str> = text.lines().collect();
        assert!(lines[0].contains("\"line_type\":\"open\""), "{text}");
        assert!(lines[1].contains("\"line_type\":\"intent\""), "{text}");
    }

    /// LOAD-BEARING (AILAB-620): a persistent sink whose key will not load must
    /// fail the build, not quietly fall back to `insecure_dev_key`. A fallback
    /// would put a signature from a published seed on records an operator
    /// afterwards pins a `Verified (pinned)` label to.
    #[test]
    fn a_persistent_sink_with_an_unloadable_key_fails_the_build() {
        let dir = tempfile::tempdir().unwrap();
        let audit = dir.path().join("audit.jsonl");

        let err = RuntimeBuilder::new()
            .audit_file(&audit, &dir.path().join("absent.key"))
            .expect_err("a missing signing key must fail the build");
        assert!(matches!(err, BuildError::LoadSigningKey { .. }), "{err:?}");

        let corrupt = dir.path().join("corrupt.key");
        std::fs::write(&corrupt, "not-a-seed\n").unwrap();
        let err = RuntimeBuilder::new()
            .audit_file(&audit, &corrupt)
            .expect_err("a corrupt signing key must fail the build");
        assert!(matches!(err, BuildError::LoadSigningKey { .. }), "{err:?}");

        // And nothing was written: the sink never opened, so no Session exists.
        assert!(!audit.exists(), "a failed build must not create the sink");
    }

    /// The key the builder was handed is the key the Session publishes — the
    /// dev key must not appear on a persistent sink.
    #[test]
    fn a_persistent_sink_publishes_the_provisioned_key() {
        let dir = tempfile::tempdir().unwrap();
        let audit = dir.path().join("audit.jsonl");
        let key_path = temp_signing_key(dir.path());
        let key = botzr_aegis_audit::load_signing_key(&key_path).expect("load");

        let rt = RuntimeBuilder::new()
            .audit_file(&audit, &key_path)
            .expect("open audit")
            .build()
            .expect("build");
        assert_eq!(rt.audit().public_key(), key.public_key());
        assert_ne!(
            rt.audit().public_key(),
            botzr_aegis_audit::insecure_dev_key().public_key()
        );
    }
}
