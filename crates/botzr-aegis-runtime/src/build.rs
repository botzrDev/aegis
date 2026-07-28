//! Shared runtime construction facade (AEG-44 §3.D).
//!
//! MCP and CLI both need the same three-step wiring — optional policy YAML,
//! optional audit sink, otherwise the library defaults — and had drifted into
//! two hand-rolled copies. [`RuntimeBuilder`] is the single place that wiring
//! lives, so consumer crates never call [`PolicyEngine::from_yaml`] or
//! [`AuditWriter::open`] directly.

use std::path::{Path, PathBuf};

use botzr_aegis_audit::{AuditError, AuditWriter};
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
}

/// Builder for a configured [`Runtime`].
///
/// Every field is optional; an unset field keeps the [`Runtime::default`]
/// behaviour (`PolicyEngine::allow_all()` and a temp-file audit sink). Tool
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

    /// Append audit records to `path` instead of the default temp sink.
    pub fn audit_file(mut self, path: &Path) -> Result<Self, BuildError> {
        let writer = AuditWriter::open(path).map_err(|source| BuildError::OpenAudit {
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
    use botzr_aegis_core::{AegisError, ToolId};

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
        // An empty builder must not change behaviour: allow-all policy and a
        // usable temp audit sink, exactly like `Runtime::new()`.
        let rt = RuntimeBuilder::new().build().expect("default build");
        assert!(rt.audit().path().exists());
        // allow-all policy → an unregistered tool is stopped by capability,
        // never by policy.
        let err = rt
            .execute_tool_call(ToolId::new("unregistered"), b"{}")
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
        let err = rt
            .execute_tool_call(ToolId::new("smoke"), b"{}")
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

    #[test]
    fn audit_file_redirects_the_sink() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested/audit.jsonl");
        let rt = RuntimeBuilder::new()
            .audit_file(&path)
            .expect("open audit")
            .build()
            .expect("build");
        assert_eq!(rt.audit().path(), path);

        let _ = rt.execute_tool_call(ToolId::new("unregistered"), b"{}");
        let text = std::fs::read_to_string(&path).expect("audit file written");
        assert!(text.contains("\"phase\":\"intent\""), "{text}");
    }
}
