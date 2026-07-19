//! [`PolicyEngine`] — the runtime-facing policy station.
//!
//! Holds the active [`PolicySet`] behind an [`ArcSwap`] (parse once, atomic hot
//! reload — G5) plus the process-local rate-limit state and the approval-id
//! sequence. Evaluation is synchronous, lock-light, and never parses YAML.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use arc_swap::ArcSwap;
use botzr_aegis_core::{PolicyAction, ResourceCeiling};

use crate::error::PolicyError;
use crate::eval::{select, PolicyDecision, PolicyRequest, Selection};
use crate::parse::parse_str;
use crate::ratelimit::RateLimiter;
use crate::set::{DefaultAction, PolicySet, Rule, RuleKind};

/// Result of a hot reload — the digests either side of an atomic swap, for the
/// `old → new` audit record (G5). On parse/validate failure the old set keeps
/// serving and [`PolicyError`] is returned instead.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReloadOutcome {
    pub old_digest: String,
    pub new_digest: String,
    pub source: ReloadSource,
}

/// Where a reload came from (mirrors G5's `file | governance-layer | cli`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReloadSource {
    File,
    Cli,
    Governance,
}

/// The policy station: active rule set + rate-limit counters + approval ids.
pub struct PolicyEngine {
    active: ArcSwap<PolicySet>,
    limiter: RateLimiter,
    approvals: AtomicU64,
    source_path: Option<PathBuf>,
}

impl PolicyEngine {
    /// Wrap an already-validated set.
    pub fn new(set: PolicySet) -> Self {
        Self {
            active: ArcSwap::from_pointee(set),
            limiter: RateLimiter::new(),
            approvals: AtomicU64::new(1),
            source_path: None,
        }
    }

    /// Zero-config engine: policy imposes nothing (capability stays the
    /// default-deny layer). This is the runtime's default.
    pub fn allow_all() -> Self {
        Self::new(PolicySet::allow_all())
    }

    /// Parse + validate a YAML document once, up front.
    pub fn from_yaml(yaml: &str) -> Result<Self, PolicyError> {
        Ok(Self::new(parse_str(yaml)?))
    }

    /// Load a policy file once at startup; the path is remembered so
    /// [`PolicyEngine::reload_from_file`] can re-read it.
    pub fn load(path: impl AsRef<Path>) -> Result<Self, PolicyError> {
        let path = path.as_ref();
        let yaml = std::fs::read_to_string(path).map_err(|e| PolicyError::Io {
            path: path.display().to_string(),
            reason: e.to_string(),
        })?;
        let mut engine = Self::from_yaml(&yaml)?;
        engine.source_path = Some(path.to_path_buf());
        Ok(engine)
    }

    /// Grab the active set once (station 1). In-flight calls that captured an
    /// earlier `Arc` complete under the set they started with.
    pub fn snapshot(&self) -> Arc<PolicySet> {
        self.active.load_full()
    }

    /// Digest of the currently-active set.
    pub fn active_digest(&self) -> String {
        self.active.load().digest().to_string()
    }

    /// Evaluate a request synchronously. Never parses YAML; the only lock taken
    /// is the rate-limiter map lock, held for a single counter bump.
    pub fn evaluate(&self, req: &PolicyRequest<'_>) -> PolicyDecision {
        let set = self.active.load();
        match select(&set, req) {
            Selection::Default(DefaultAction::Allow) => PolicyDecision {
                action: PolicyAction::Allow,
                limits: ResourceCeiling::default(),
                matched_rule: None,
            },
            Selection::Default(DefaultAction::Deny) => PolicyDecision {
                action: PolicyAction::Deny {
                    reason: "no matching rule (default deny)".to_string(),
                },
                limits: ResourceCeiling::default(),
                matched_rule: None,
            },
            Selection::Matched(rule) => self.finalize(rule, req),
        }
    }

    fn finalize(&self, rule: &Rule, req: &PolicyRequest<'_>) -> PolicyDecision {
        let matched_rule = Some(rule.id.clone());
        match rule.kind {
            RuleKind::Allow => PolicyDecision {
                action: PolicyAction::Allow,
                limits: rule.limits,
                matched_rule,
            },
            RuleKind::Deny => PolicyDecision {
                action: PolicyAction::Deny {
                    reason: rule
                        .reason
                        .clone()
                        .unwrap_or_else(|| format!("denied by rule `{}`", rule.id)),
                },
                limits: ResourceCeiling::default(),
                matched_rule,
            },
            RuleKind::PendingApproval => PolicyDecision {
                action: PolicyAction::PendingApproval {
                    approval_id: self.mint_approval_id(rule, req),
                },
                limits: ResourceCeiling::default(),
                matched_rule,
            },
            RuleKind::RateLimit => {
                let spec = rule
                    .rate
                    .expect("rate_limit rules carry a rate spec (enforced at parse time)");
                let key = self.rate_key(rule, req);
                if self.limiter.check(&key, spec) {
                    PolicyDecision {
                        action: PolicyAction::Allow,
                        limits: rule.limits,
                        matched_rule,
                    }
                } else {
                    PolicyDecision {
                        action: PolicyAction::RateLimited {
                            reason: rule.reason.clone().unwrap_or_else(|| {
                                format!(
                                    "rate limit exceeded for `{}` ({} per {}s)",
                                    rule.id, spec.max, spec.per_seconds
                                )
                            }),
                        },
                        limits: ResourceCeiling::default(),
                        matched_rule,
                    }
                }
            }
        }
    }

    fn rate_key(&self, rule: &Rule, req: &PolicyRequest<'_>) -> String {
        // Per rule, per tool, per session (G12) — session defaults to the tool
        // when the caller does not supply one.
        format!(
            "{}::{}::{}",
            rule.id,
            req.tool_id,
            req.session.unwrap_or_else(|| req.tool_id.as_str())
        )
    }

    fn mint_approval_id(&self, rule: &Rule, req: &PolicyRequest<'_>) -> String {
        let seq = self.approvals.fetch_add(1, Ordering::Relaxed);
        // Reject-with-resume-token (G2): the id is the idempotency key a caller
        // re-submits with. Persistence + TTL land with the approval queue.
        format!("apr-{}-{}-{}", rule.id, req.tool_id, seq)
    }

    /// Atomically swap in a new set parsed from YAML. On parse/validate failure
    /// the current set keeps serving and the error is returned (never a partial
    /// application, G5).
    pub fn reload_from_yaml(
        &self,
        yaml: &str,
        source: ReloadSource,
    ) -> Result<ReloadOutcome, PolicyError> {
        let new_set = parse_str(yaml)?;
        let old_digest = self.active_digest();
        let new_digest = new_set.digest().to_string();
        self.active.store(Arc::new(new_set));
        Ok(ReloadOutcome {
            old_digest,
            new_digest,
            source,
        })
    }

    /// Re-read and swap in the file this engine was [`PolicyEngine::load`]ed
    /// from. Errors if the engine has no source path.
    pub fn reload_from_file(&self) -> Result<ReloadOutcome, PolicyError> {
        let path = self.source_path.as_ref().ok_or_else(|| PolicyError::Io {
            path: "<none>".to_string(),
            reason: "engine has no source file to reload".to_string(),
        })?;
        let yaml = std::fs::read_to_string(path).map_err(|e| PolicyError::Io {
            path: path.display().to_string(),
            reason: e.to_string(),
        })?;
        self.reload_from_yaml(&yaml, ReloadSource::File)
    }
}

impl Default for PolicyEngine {
    fn default() -> Self {
        Self::allow_all()
    }
}

impl std::fmt::Debug for PolicyEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PolicyEngine")
            .field("active_digest", &self.active.load().digest())
            .field("rules", &self.active.load().rules().len())
            .finish_non_exhaustive()
    }
}
