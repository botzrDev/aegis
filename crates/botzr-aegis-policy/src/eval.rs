//! Synchronous policy evaluation with G5 conflict semantics.
//!
//! Conflict resolution (G5, no implicit file ordering):
//! 1. **deny-overrides** — any matching `deny` wins outright;
//! 2. among the rest, **most-specific wins** (more constrained match axes);
//! 3. ties broken by explicit rule **`priority`** (higher wins);
//! 4. no match → the set's default action.
//!
//! This module is pure and allocation-light; rate-limit counter state and
//! approval-id minting live in [`crate::engine`] so the set stays immutable.

use botzr_aegis_core::{PolicyAction, ResourceCeiling, ToolId};

use crate::set::{DefaultAction, PolicySet, Rule};

/// What a caller is trying to do, evaluated against the active policy set. Axes
/// beyond `tool_id` are optional; a rule that constrains an axis the request
/// leaves unset simply does not match (role gates fire only when a role is
/// asserted).
#[derive(Debug, Clone, Copy)]
pub struct PolicyRequest<'a> {
    pub tool_id: &'a ToolId,
    pub capability: Option<&'a str>,
    pub role: Option<&'a str>,
    pub session: Option<&'a str>,
}

impl<'a> PolicyRequest<'a> {
    /// Minimal request keyed on tool identity only (no role/capability axis).
    pub fn for_tool(tool_id: &'a ToolId) -> Self {
        Self {
            tool_id,
            capability: None,
            role: None,
            session: None,
        }
    }

    pub fn with_role(mut self, role: &'a str) -> Self {
        self.role = Some(role);
        self
    }

    pub fn with_capability(mut self, capability: &'a str) -> Self {
        self.capability = Some(capability);
        self
    }

    pub fn with_session(mut self, session: &'a str) -> Self {
        self.session = Some(session);
        self
    }
}

/// The outcome of evaluating a request: the verdict plus any ceiling the winning
/// rule imposes and the id of the rule that decided it (for the audit trail).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyDecision {
    pub action: PolicyAction,
    pub limits: ResourceCeiling,
    pub matched_rule: Option<String>,
}

/// Which rule (if any) won selection, before rate-limit state is applied.
pub(crate) enum Selection<'a> {
    Default(DefaultAction),
    Matched(&'a Rule),
}

/// Select the governing rule per G5, without touching rate-limit state.
pub(crate) fn select<'a>(set: &'a PolicySet, req: &PolicyRequest<'_>) -> Selection<'a> {
    let mut best_deny: Option<&Rule> = None;
    let mut best_other: Option<&Rule> = None;

    for rule in set.rules() {
        if !rule.matcher.matches(req) {
            continue;
        }
        if matches!(rule.kind, crate::set::RuleKind::Deny) {
            best_deny = Some(more_specific(best_deny, rule));
        } else {
            best_other = Some(more_specific(best_other, rule));
        }
    }

    if let Some(deny) = best_deny {
        return Selection::Matched(deny);
    }
    if let Some(other) = best_other {
        return Selection::Matched(other);
    }
    Selection::Default(set.default_action())
}

/// Pick the winner between the current best and a challenger: higher specificity
/// first, then higher priority. On a full tie the incumbent is kept, which keeps
/// selection deterministic without depending on file position (an exact
/// specificity+priority tie between conflicting rules is an authoring error).
fn more_specific<'a>(current: Option<&'a Rule>, challenger: &'a Rule) -> &'a Rule {
    match current {
        None => challenger,
        Some(cur) => {
            let cur_key = (cur.matcher.specificity(), cur.priority);
            let chal_key = (challenger.matcher.specificity(), challenger.priority);
            if chal_key > cur_key {
                challenger
            } else {
                cur
            }
        }
    }
}
