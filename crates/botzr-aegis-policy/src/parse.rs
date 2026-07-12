//! YAML → validated [`PolicySet`]. Runs **once** at startup (or on hot reload),
//! never per call (anti-pattern #7).
//!
//! On-disk shape (v1):
//!
//! ```yaml
//! version: 1
//! default: allow          # allow (default) | deny
//! rules:
//!   - id: deny-exec
//!     action: deny        # allow | deny | rate_limit | pending_approval
//!     tool: exec-runner   # match axes (omitted or "*" = wildcard)
//!     capability: exec.command
//!     role: "*"
//!     priority: 10        # tie-break among equally-specific rules
//!     reason: "exec disabled in this environment"
//!   - id: rate-search
//!     action: rate_limit
//!     tool: search
//!     rate: { max: 100, per_seconds: 60 }
//!   - id: approve-dream
//!     action: pending_approval
//!     tool: dream
//!   - id: cap-writer
//!     action: allow
//!     tool: writer
//!     limits: { max_memory_bytes: 33554432, max_wall_ms: 5000 }
//! ```

use std::collections::HashSet;

use serde::Deserialize;

use crate::error::PolicyError;
use crate::set::{DefaultAction, Matcher, PolicyLimits, PolicySet, RateSpec, Rule, RuleKind};

/// Highest `version` this build understands.
pub const SUPPORTED_POLICY_VERSION: u32 = 1;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPolicy {
    #[serde(default = "default_version")]
    version: u32,
    #[serde(default)]
    default: RawDefault,
    #[serde(default)]
    rules: Vec<RawRule>,
}

fn default_version() -> u32 {
    SUPPORTED_POLICY_VERSION
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
enum RawDefault {
    #[default]
    Allow,
    Deny,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRule {
    id: String,
    action: RawAction,
    #[serde(default)]
    tool: Option<String>,
    #[serde(default)]
    capability: Option<String>,
    #[serde(default)]
    role: Option<String>,
    #[serde(default)]
    priority: i32,
    #[serde(default)]
    reason: Option<String>,
    #[serde(default)]
    rate: Option<RawRate>,
    #[serde(default)]
    limits: Option<RawLimits>,
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum RawAction {
    Allow,
    Deny,
    RateLimit,
    PendingApproval,
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRate {
    max: u32,
    per_seconds: u64,
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawLimits {
    #[serde(default)]
    max_memory_bytes: Option<u64>,
    #[serde(default)]
    max_wall_ms: Option<u64>,
    #[serde(default)]
    max_output_bytes: Option<u64>,
}

/// Parse and validate a policy document into an immutable [`PolicySet`].
pub fn parse_str(yaml: &str) -> Result<PolicySet, PolicyError> {
    let raw: RawPolicy =
        serde_norway::from_str(yaml).map_err(|e| PolicyError::Parse(e.to_string()))?;

    if raw.version != SUPPORTED_POLICY_VERSION {
        return Err(PolicyError::UnsupportedVersion {
            found: raw.version,
            supported: SUPPORTED_POLICY_VERSION,
        });
    }

    let default = match raw.default {
        RawDefault::Allow => DefaultAction::Allow,
        RawDefault::Deny => DefaultAction::Deny,
    };

    let mut seen = HashSet::new();
    let mut rules = Vec::with_capacity(raw.rules.len());
    for raw_rule in raw.rules {
        if !seen.insert(raw_rule.id.clone()) {
            return Err(PolicyError::DuplicateRuleId { id: raw_rule.id });
        }
        rules.push(compile_rule(raw_rule)?);
    }

    let digest = digest_of(yaml);
    Ok(PolicySet::new(default, rules, digest))
}

fn compile_rule(raw: RawRule) -> Result<Rule, PolicyError> {
    let kind = match raw.action {
        RawAction::Allow => RuleKind::Allow,
        RawAction::Deny => RuleKind::Deny,
        RawAction::RateLimit => RuleKind::RateLimit,
        RawAction::PendingApproval => RuleKind::PendingApproval,
    };

    let rate = match (kind, raw.rate) {
        (RuleKind::RateLimit, Some(r)) => {
            if r.max == 0 || r.per_seconds == 0 {
                return Err(PolicyError::InvalidRule {
                    id: raw.id,
                    reason: "rate.max and rate.per_seconds must be > 0".to_string(),
                });
            }
            Some(RateSpec {
                max: r.max,
                per_seconds: r.per_seconds,
            })
        }
        (RuleKind::RateLimit, None) => {
            return Err(PolicyError::InvalidRule {
                id: raw.id,
                reason: "rate_limit action requires a `rate` block".to_string(),
            });
        }
        (_, Some(_)) => {
            return Err(PolicyError::InvalidRule {
                id: raw.id,
                reason: "`rate` is only valid on a rate_limit action".to_string(),
            });
        }
        (_, None) => None,
    };

    let limits = raw
        .limits
        .map(|l| PolicyLimits {
            max_memory_bytes: l.max_memory_bytes,
            max_wall_ms: l.max_wall_ms,
            max_output_bytes: l.max_output_bytes,
        })
        .unwrap_or_default();

    // Limits only make sense where the call actually executes (allow / rate
    // limit). A deny or pending-approval never mints a grant, so a ceiling is
    // meaningless there — reject it rather than silently ignore.
    if !limits.is_unconstrained() && matches!(kind, RuleKind::Deny | RuleKind::PendingApproval) {
        return Err(PolicyError::InvalidRule {
            id: raw.id,
            reason: "`limits` is only valid on allow or rate_limit actions".to_string(),
        });
    }

    Ok(Rule {
        id: raw.id,
        kind,
        matcher: Matcher {
            tool: raw.tool,
            capability: raw.capability,
            role: raw.role,
        },
        priority: raw.priority,
        reason: raw.reason,
        rate,
        limits,
    })
}

/// Small, dependency-free content digest (FNV-1a, 64-bit) used to tag a set for
/// the `old → new` reload audit trail. Not a security digest — just change
/// detection.
fn digest_of(yaml: &str) -> String {
    const OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const PRIME: u64 = 0x0000_0100_0000_01b3;
    let mut hash = OFFSET;
    for byte in yaml.bytes() {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(PRIME);
    }
    format!("fnv1a:{hash:016x}")
}
