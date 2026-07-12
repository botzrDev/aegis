//! Validated, in-memory policy model.
//!
//! A [`PolicySet`] is the compiled form the hot path evaluates against. It is
//! produced once (parse + validate) and then treated as immutable — hot reload
//! swaps a whole new `Arc<PolicySet>` rather than mutating an existing one
//! (G5). All fields are read-only after construction; no interior mutability
//! lives here (rate-limit counters live in the engine, so a reload never resets
//! them).

/// Action taken when no rule matches a request. Policy only *restricts* — the
/// capability resolver remains the default-deny layer — so the default is
/// [`DefaultAction::Allow`] unless a document opts into `default: deny`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DefaultAction {
    #[default]
    Allow,
    Deny,
}

/// The four policy verdict kinds a rule can carry (PRD R3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleKind {
    Allow,
    Deny,
    RateLimit,
    PendingApproval,
}

/// Fixed-window rate-limit specification (`max` calls per `per_seconds`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RateSpec {
    pub max: u32,
    pub per_seconds: u64,
}

/// Optional resource ceiling a rule imposes. Policy may only *lower* limits, so
/// these map onto a capability `PolicyCeiling` (`None` = do not constrain).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PolicyLimits {
    pub max_memory_bytes: Option<u64>,
    pub max_wall_ms: Option<u64>,
    pub max_output_bytes: Option<u64>,
}

impl PolicyLimits {
    pub fn is_unconstrained(&self) -> bool {
        self.max_memory_bytes.is_none()
            && self.max_wall_ms.is_none()
            && self.max_output_bytes.is_none()
    }
}

/// Match predicate for a rule. A `None` axis (or the literal `"*"`) matches any
/// value; a `Some(v)` axis matches only when the request supplies that exact
/// value. Specificity counts the concrete (non-wildcard) axes.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Matcher {
    pub tool: Option<String>,
    pub capability: Option<String>,
    pub role: Option<String>,
}

impl Matcher {
    /// Number of concretely-constrained axes — the tie ordering key for G5's
    /// "most-specific wins".
    pub fn specificity(&self) -> u8 {
        [
            axis_is_concrete(&self.tool),
            axis_is_concrete(&self.capability),
            axis_is_concrete(&self.role),
        ]
        .into_iter()
        .filter(|&concrete| concrete)
        .count() as u8
    }

    /// True when this rule applies to `req`. An axis constrained by the rule but
    /// absent from the request (e.g. a role-gated rule against a request with no
    /// role) does not match — role gates only fire when a role is asserted.
    pub fn matches(&self, req: &super::PolicyRequest<'_>) -> bool {
        axis_matches(&self.tool, Some(req.tool_id.as_str()))
            && axis_matches(&self.capability, req.capability)
            && axis_matches(&self.role, req.role)
    }
}

fn axis_is_concrete(axis: &Option<String>) -> bool {
    matches!(axis, Some(v) if v != "*")
}

fn axis_matches(axis: &Option<String>, value: Option<&str>) -> bool {
    match axis {
        None => true,
        Some(v) if v == "*" => true,
        Some(v) => value == Some(v.as_str()),
    }
}

/// A compiled rule. `index` is a stable key for rate-limit counters that
/// survives reloads only if the rule keeps its position — counters are keyed by
/// rule `id`, so renaming a rule intentionally resets its window.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rule {
    pub id: String,
    pub kind: RuleKind,
    pub matcher: Matcher,
    pub priority: i32,
    pub reason: Option<String>,
    pub rate: Option<RateSpec>,
    pub limits: PolicyLimits,
}

/// The validated, immutable rule set the hot path evaluates.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicySet {
    default: DefaultAction,
    rules: Vec<Rule>,
    digest: String,
}

impl PolicySet {
    /// Construct from already-validated parts. Prefer [`crate::parse`] entry
    /// points, which validate and compute the digest.
    pub(crate) fn new(default: DefaultAction, rules: Vec<Rule>, digest: String) -> Self {
        Self {
            default,
            rules,
            digest,
        }
    }

    /// An empty allow-all set (policy imposes nothing; capability stays
    /// default-deny). Used as the runtime's zero-config default.
    pub fn allow_all() -> Self {
        Self {
            default: DefaultAction::Allow,
            rules: Vec::new(),
            digest: "allow-all".to_string(),
        }
    }

    pub fn default_action(&self) -> DefaultAction {
        self.default
    }

    pub fn rules(&self) -> &[Rule] {
        &self.rules
    }

    /// Content digest (`old → new` audit trail on hot reload, G5).
    pub fn digest(&self) -> &str {
        &self.digest
    }
}

impl Default for PolicySet {
    fn default() -> Self {
        Self::allow_all()
    }
}
