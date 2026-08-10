//! Validated, in-memory policy model.
//!
//! A [`PolicySet`] is the compiled form the hot path evaluates against. It is
//! produced once (parse + validate) and then treated as immutable — hot reload
//! swaps a whole new `Arc<PolicySet>` rather than mutating an existing one
//! (G5). All fields are read-only after construction; no interior mutability
//! lives here (rate-limit counters live in the engine, so a reload never resets
//! them).

use botzr_aegis_core::{to_canonical_json, PolicySetHash, ResourceCeiling};

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
    /// Optional resource ceiling this rule imposes. Policy may only *lower*
    /// limits (`None` = do not constrain that axis) — the same core-owned
    /// [`ResourceCeiling`] the capability resolver folds into grant minting.
    pub limits: ResourceCeiling,
}

/// The validated, immutable rule set the hot path evaluates.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicySet {
    default: DefaultAction,
    rules: Vec<Rule>,
    digest: String,
    /// Computed once at construction. The audit record names it on **every**
    /// call, so recomputing a SHA-256 over the whole set per call would put the
    /// ruleset's identity on the hot path for a value that cannot change.
    content_hash: PolicySetHash,
}

impl PolicySet {
    /// Construct from already-validated parts. Prefer [`crate::parse`] entry
    /// points, which validate and compute the digest.
    pub(crate) fn new(default: DefaultAction, rules: Vec<Rule>, digest: String) -> Self {
        let content_hash = compute_content_hash(default, &rules);
        Self {
            default,
            rules,
            digest,
            content_hash,
        }
    }

    /// An empty allow-all set (policy imposes nothing; capability stays
    /// default-deny). Used as the runtime's zero-config default.
    pub fn allow_all() -> Self {
        Self::new(DefaultAction::Allow, Vec::new(), "allow-all".to_string())
    }

    pub fn default_action(&self) -> DefaultAction {
        self.default
    }

    pub fn rules(&self) -> &[Rule] {
        &self.rules
    }

    /// Content digest (`old → new` audit trail on hot reload, G5).
    ///
    /// FNV-1a over the YAML **text** — change detection, deliberately not a
    /// security digest. Never record this as an audit record's
    /// `policy_set_hash`; use [`PolicySet::content_hash`].
    pub fn digest(&self) -> &str {
        &self.digest
    }

    /// SHA-256 over this set's canonical bytes — the ruleset identity an audit
    /// record carries so a verdict can be rechecked against the rules that
    /// produced it.
    ///
    /// **Canonical bytes** are the RFC 8785 (JCS) form of a stable projection of
    /// the *parsed* set (see [`SetProjection`]) — deliberately not the YAML
    /// text. Hashing the text would make a reindent, a retyped comment, or a
    /// reordered mapping key look like a different ruleset, and an identity that
    /// moves for non-reasons trains a reader to ignore it moving. Every field
    /// the evaluator actually reads is covered, so a semantic edit always moves
    /// the hash.
    pub fn content_hash(&self) -> PolicySetHash {
        self.content_hash
    }
}

/// Stable serializable projection of a validated set — the JCS input behind
/// [`PolicySet::content_hash`].
///
/// Every scalar here is a string or a bool, on purpose. The JCS value space
/// rejects floats, negatives, and integers at or above 2^53 (ADR-0003), but a
/// legitimate policy document may carry `priority: -5` or
/// `max_memory_bytes: 18446744073709551615`. Projecting numbers as decimal
/// strings means no policy file can push canonicalization outside the value
/// space, so hashing a parsed set cannot fail.
#[derive(serde::Serialize)]
struct SetProjection<'a> {
    default: &'static str,
    /// Declaration order is preserved. `select` keeps the incumbent on a full
    /// specificity+priority tie, so rule order is observable behaviour: two
    /// orderings are not guaranteed to be the same ruleset, and a content hash
    /// must not claim they are.
    rules: Vec<RuleProjection<'a>>,
}

#[derive(serde::Serialize)]
struct RuleProjection<'a> {
    id: &'a str,
    action: &'static str,
    /// Match axes. `None` and the literal `"*"` are the same predicate for both
    /// [`Matcher::matches`] and [`Matcher::specificity`], so a wildcard projects
    /// as absent — otherwise two spellings of "unconstrained" would hash apart.
    #[serde(skip_serializing_if = "Option::is_none")]
    tool: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    capability: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    role: Option<&'a str>,
    priority: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    rate: Option<RateProjection>,
    #[serde(skip_serializing_if = "Option::is_none")]
    limits: Option<LimitsProjection>,
}

#[derive(serde::Serialize)]
struct RateProjection {
    max: String,
    per_seconds: String,
}

#[derive(serde::Serialize)]
struct LimitsProjection {
    #[serde(skip_serializing_if = "Option::is_none")]
    max_memory_bytes: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_wall_ms: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_output_bytes: Option<String>,
}

fn compute_content_hash(default: DefaultAction, rules: &[Rule]) -> PolicySetHash {
    let projection = SetProjection {
        default: match default {
            DefaultAction::Allow => "allow",
            DefaultAction::Deny => "deny",
        },
        rules: rules.iter().map(project_rule).collect(),
    };
    let canonical = to_canonical_json(&projection)
        .expect("the policy projection is strings, bools and objects only — no float, negative or oversized integer can reach the canonicalizer");
    PolicySetHash::of_canonical_bytes(canonical.as_bytes())
}

fn project_rule(rule: &Rule) -> RuleProjection<'_> {
    RuleProjection {
        id: &rule.id,
        action: match rule.kind {
            RuleKind::Allow => "allow",
            RuleKind::Deny => "deny",
            RuleKind::RateLimit => "rate_limit",
            RuleKind::PendingApproval => "pending_approval",
        },
        tool: project_axis(&rule.matcher.tool),
        capability: project_axis(&rule.matcher.capability),
        role: project_axis(&rule.matcher.role),
        priority: rule.priority.to_string(),
        reason: rule.reason.as_deref(),
        rate: rule.rate.map(|rate| RateProjection {
            max: rate.max.to_string(),
            per_seconds: rate.per_seconds.to_string(),
        }),
        limits: project_limits(rule.limits),
    }
}

/// A wildcard axis and an omitted axis constrain nothing — see
/// [`axis_matches`] and [`axis_is_concrete`] — so they project identically.
fn project_axis(axis: &Option<String>) -> Option<&str> {
    match axis {
        Some(value) if value != "*" => Some(value.as_str()),
        _ => None,
    }
}

/// An unconstrained ceiling is projected as absent rather than three absent
/// axes, so `limits: {}` and no `limits` block are the same set.
fn project_limits(limits: ResourceCeiling) -> Option<LimitsProjection> {
    if limits.is_unconstrained() {
        return None;
    }
    Some(LimitsProjection {
        max_memory_bytes: limits.max_memory_bytes.map(|v| v.to_string()),
        max_wall_ms: limits.max_wall_ms.map(|v| v.to_string()),
        max_output_bytes: limits.max_output_bytes.map(|v| v.to_string()),
    })
}

impl Default for PolicySet {
    fn default() -> Self {
        Self::allow_all()
    }
}

#[cfg(test)]
mod content_hash_tests {
    use crate::parse::parse_str;

    const BASE: &str = r#"
version: 1
default: deny
rules:
  - id: deny-exec
    action: deny
    tool: exec-runner
    capability: exec.command
    priority: 10
    reason: "exec disabled"
  - id: cap-writer
    action: allow
    tool: writer
    limits: { max_memory_bytes: 33554432, max_wall_ms: 5000 }
"#;

    /// Same rules, reformatted: block style instead of flow style, comments
    /// added, mapping keys reordered, indentation and quoting changed.
    const REFORMATTED: &str = r#"
# The set below is byte-for-byte different and semantically identical.
default: deny        # unchanged
version: 1
rules:

  - action: deny
    reason: exec disabled
    priority: 10
    capability: "exec.command"
    tool: exec-runner
    id: deny-exec

  # a ceiling, spelled block-style this time
  - action:   allow
    id:       cap-writer
    tool:     "writer"
    limits:
      max_wall_ms: 5000
      max_memory_bytes: 33554432
"#;

    fn hash(yaml: &str) -> String {
        parse_str(yaml)
            .expect("valid policy")
            .content_hash()
            .to_hex()
    }

    #[test]
    fn formatting_comment_and_key_order_edits_do_not_move_the_content_hash() {
        assert_eq!(hash(BASE), hash(REFORMATTED));
        // …and the point of a *separate* hash: the FNV text digest does move,
        // which is what keeps it useful for the `old → new` reload trail.
        assert_ne!(
            parse_str(BASE).unwrap().digest(),
            parse_str(REFORMATTED).unwrap().digest()
        );
    }

    #[test]
    fn every_semantic_change_moves_the_content_hash() {
        let base = hash(BASE);
        for (what, yaml) in [
            (
                "a rule added",
                format!("{BASE}  - id: extra\n    action: allow\n    tool: reader\n"),
            ),
            (
                "an action flipped",
                BASE.replace("action: allow", "action: deny").replace(
                    "    limits: { max_memory_bytes: 33554432, max_wall_ms: 5000 }\n",
                    "",
                ),
            ),
            (
                "a priority changed",
                BASE.replace("priority: 10", "priority: 11"),
            ),
            (
                "a limit changed",
                BASE.replace("max_wall_ms: 5000", "max_wall_ms: 4999"),
            ),
            (
                "the default flipped",
                BASE.replace("default: deny", "default: allow"),
            ),
            (
                "a rule renamed",
                BASE.replace("id: cap-writer", "id: cap-author"),
            ),
            (
                "a match axis narrowed",
                BASE.replace("tool: writer", "tool: writer\n    role: owner"),
            ),
            (
                "a reason reworded",
                BASE.replace("exec disabled", "exec disabled here"),
            ),
        ] {
            assert_ne!(base, hash(&yaml), "{what} must move the content hash");
        }
    }

    #[test]
    fn rule_order_is_part_of_the_identity() {
        // `select` keeps the incumbent on a full tie, so ordering is observable.
        let swapped = r#"
version: 1
default: deny
rules:
  - id: cap-writer
    action: allow
    tool: writer
    limits: { max_memory_bytes: 33554432, max_wall_ms: 5000 }
  - id: deny-exec
    action: deny
    tool: exec-runner
    capability: exec.command
    priority: 10
    reason: "exec disabled"
"#;
        assert_ne!(hash(BASE), hash(swapped));
    }

    #[test]
    fn a_wildcard_axis_hashes_as_the_unconstrained_axis_it_is() {
        // `Matcher::matches` and `Matcher::specificity` treat `"*"` and an
        // omitted axis identically, so the identity must too.
        let wildcard = "version: 1\ndefault: allow\nrules:\n  - id: r\n    action: allow\n    tool: \"*\"\n    role: \"*\"\n";
        let omitted = "version: 1\ndefault: allow\nrules:\n  - id: r\n    action: allow\n";
        assert_eq!(hash(wildcard), hash(omitted));
    }

    #[test]
    fn the_zero_config_set_hashes_as_the_empty_allow_all_document() {
        assert_eq!(
            super::PolicySet::allow_all().content_hash(),
            parse_str("version: 1\ndefault: allow\nrules: []\n")
                .unwrap()
                .content_hash()
        );
    }

    #[test]
    fn extreme_but_legal_numbers_hash_instead_of_panicking() {
        // Guards the projection's reason for existing: a `u64::MAX` limit is
        // outside the JCS integer range and a negative priority is outside its
        // sign range, yet both are legal policy.
        let yaml = "version: 1\ndefault: allow\nrules:\n  - id: r\n    action: allow\n    tool: t\n    priority: -5\n    limits: { max_memory_bytes: 18446744073709551615 }\n";
        let first = hash(yaml);
        assert_eq!(first.len(), 64);
        assert_ne!(first, hash(&yaml.replace("priority: -5", "priority: -6")));
    }
}
