//! Policy engine — station 1 of the enforcement pipeline (**POLICY** →
//! CAPABILITY → SANDBOX → AUDIT).
//!
//! YAML is parsed **once** into an immutable (crate-internal) `PolicySet` held behind an
//! [`arc_swap::ArcSwap`] inside [`PolicyEngine`]; evaluation is synchronous,
//! lock-light, and targets <100 µs (never parses at call time — anti-pattern
//! #7). Conflict resolution follows G5 (deny-overrides · most-specific ·
//! priority tie-break) and `PendingApproval` is reject-with-resume-token (G2):
//! the call is not executed and no grant is minted.

mod engine;
mod error;
mod eval;
mod parse;
mod ratelimit;
mod recheck;
mod set;

// Supported consumer surface. The compiled AST (`PolicySet`, `Rule`,
// `Matcher`, `RateSpec`, `RuleKind`, `DefaultAction`), the rate-limiter, and
// the YAML parser are deliberately crate-internal: they are an implementation
// of G5 conflict resolution, not an API consumers pin against.
pub use botzr_aegis_core::{PolicySetHash, ResourceCeiling};
pub use engine::{PolicyEngine, ReloadOutcome, ReloadSource};
pub use error::PolicyError;
pub use eval::{PolicyDecision, PolicyRequest};
pub use parse::SUPPORTED_POLICY_VERSION;
// Forensic re-evaluation (`aegis recheck`). `PolicyEngine::preview` is the
// side-effect-free twin of `evaluate` and stays a method on the engine, so the
// crate-internal `select` and `PolicySet` never have to become public to let a
// caller ask what a rule set *would* decide.
pub use recheck::{
    classify, outcome_token, recheck_record, RecheckClass, RecheckIndeterminate, RecheckVerdict,
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::set::DefaultAction;
    use botzr_aegis_core::{PolicyAction, ToolId};

    fn deny_yaml() -> &'static str {
        r#"
version: 1
default: allow
rules:
  - id: allow-search
    action: allow
    tool: search
  - id: deny-search
    action: deny
    tool: search
    reason: "search disabled"
"#
    }

    #[test]
    fn deny_overrides_allow() {
        let engine = PolicyEngine::from_yaml(deny_yaml()).unwrap();
        let tool = ToolId::new("search");
        let decision = engine.evaluate(&PolicyRequest::for_tool(&tool));
        match decision.action {
            PolicyAction::Deny { reason } => assert_eq!(reason, "search disabled"),
            other => panic!("expected deny-overrides, got {other:?}"),
        }
    }

    #[test]
    fn most_specific_allow_wins_and_carries_ceiling() {
        let yaml = r#"
version: 1
default: deny
rules:
  - id: broad-allow
    action: allow
    tool: "*"
  - id: specific-allow
    action: allow
    tool: writer
    role: owner
    limits: { max_memory_bytes: 1048576, max_wall_ms: 1000 }
"#;
        let engine = PolicyEngine::from_yaml(yaml).unwrap();
        let tool = ToolId::new("writer");
        let decision = engine.evaluate(&PolicyRequest::for_tool(&tool).with_role("owner"));
        assert_eq!(decision.action, PolicyAction::Allow);
        assert_eq!(decision.matched_rule.as_deref(), Some("specific-allow"));
        assert_eq!(decision.limits.max_memory_bytes, Some(1_048_576));
        assert_eq!(decision.limits.max_wall_ms, Some(1_000));
    }

    #[test]
    fn priority_breaks_specificity_tie() {
        let yaml = r#"
version: 1
default: deny
rules:
  - id: low
    action: pending_approval
    tool: t
    priority: 1
  - id: high
    action: allow
    tool: t
    priority: 5
"#;
        let engine = PolicyEngine::from_yaml(yaml).unwrap();
        let tool = ToolId::new("t");
        let decision = engine.evaluate(&PolicyRequest::for_tool(&tool));
        assert_eq!(decision.action, PolicyAction::Allow);
        assert_eq!(decision.matched_rule.as_deref(), Some("high"));
    }

    #[test]
    fn rate_limit_trips_after_max() {
        let yaml = r#"
version: 1
default: allow
rules:
  - id: rl
    action: rate_limit
    tool: chatty
    rate: { max: 2, per_seconds: 60 }
"#;
        let engine = PolicyEngine::from_yaml(yaml).unwrap();
        let tool = ToolId::new("chatty");
        let req = PolicyRequest::for_tool(&tool);
        assert_eq!(engine.evaluate(&req).action, PolicyAction::Allow);
        assert_eq!(engine.evaluate(&req).action, PolicyAction::Allow);
        match engine.evaluate(&req).action {
            PolicyAction::RateLimited { .. } => {}
            other => panic!("expected rate limit trip, got {other:?}"),
        }
    }

    #[test]
    fn pending_approval_mints_stable_id() {
        let yaml = r#"
version: 1
default: allow
rules:
  - id: gate
    action: pending_approval
    tool: dream
"#;
        let engine = PolicyEngine::from_yaml(yaml).unwrap();
        let tool = ToolId::new("dream");
        match engine.evaluate(&PolicyRequest::for_tool(&tool)).action {
            PolicyAction::PendingApproval { approval_id } => {
                assert!(approval_id.starts_with("apr-gate-dream-"));
            }
            other => panic!("expected pending approval, got {other:?}"),
        }
    }

    #[test]
    fn default_deny_when_no_rule_matches() {
        let yaml = "version: 1\ndefault: deny\nrules: []\n";
        let engine = PolicyEngine::from_yaml(yaml).unwrap();
        let tool = ToolId::new("anything");
        match engine.evaluate(&PolicyRequest::for_tool(&tool)).action {
            PolicyAction::Deny { .. } => {}
            other => panic!("expected default deny, got {other:?}"),
        }
    }

    #[test]
    fn hot_reload_atomic_swap() {
        let engine = PolicyEngine::from_yaml("version: 1\ndefault: allow\nrules: []\n").unwrap();
        let tool = ToolId::new("x");
        assert_eq!(
            engine.evaluate(&PolicyRequest::for_tool(&tool)).action,
            PolicyAction::Allow
        );

        // A snapshot taken before reload keeps serving the old set.
        let before = engine.snapshot();
        let outcome = engine
            .reload_from_yaml("version: 1\ndefault: deny\nrules: []\n", ReloadSource::Cli)
            .unwrap();
        assert_ne!(outcome.old_digest, outcome.new_digest);
        assert_eq!(before.default_action(), DefaultAction::Allow);

        match engine.evaluate(&PolicyRequest::for_tool(&tool)).action {
            PolicyAction::Deny { .. } => {}
            other => panic!("expected deny after reload, got {other:?}"),
        }
    }

    #[test]
    fn reload_failure_keeps_old_set() {
        let engine = PolicyEngine::from_yaml("version: 1\ndefault: deny\nrules: []\n").unwrap();
        let err = engine
            .reload_from_yaml("version: 999\nrules: []\n", ReloadSource::File)
            .unwrap_err();
        assert!(matches!(err, PolicyError::UnsupportedVersion { .. }));
        // Old set still serves.
        let tool = ToolId::new("x");
        assert!(matches!(
            engine.evaluate(&PolicyRequest::for_tool(&tool)).action,
            PolicyAction::Deny { .. }
        ));
    }

    #[test]
    fn rejects_rate_limit_without_rate_block() {
        let yaml = "version: 1\nrules:\n  - id: bad\n    action: rate_limit\n    tool: t\n";
        assert!(matches!(
            PolicyEngine::from_yaml(yaml),
            Err(PolicyError::InvalidRule { .. })
        ));
    }
}
