//! Side-effect-free re-evaluation of a recorded verdict against a *new* Policy
//! Set — the classification half of `aegis recheck`.
//!
//! **Nothing here executes anything.** No sandbox, no capability resolver, no
//! grant, no clock, no filesystem. A recheck answers one question about a
//! finished call — *would this Policy Set have blocked it?* — and the answer
//! must be a pure function of (policy bytes, record bytes), because the whole
//! point of a forensic verb is that two people running it over the same evidence
//! read the same sentence.
//!
//! That purity is why [`PolicyEngine::evaluate`] is **not** the primitive here.
//! `evaluate` is the live path: it bumps the rate-limit window and mints an
//! approval id from a process-local counter. Both are writes. Run it twice over
//! one record and the second answer differs from the first — an auditor's tool
//! that changes its own answer by being used is not evidence. [`PolicyEngine::preview`]
//! reads the same `select` (identical G5 conflict resolution — deny-overrides,
//! most-specific, priority) and stops before `finalize`.
//!
//! The one thing `select` cannot answer offline is a rate limit: it is counter
//! and wall-clock state that no record carries, so a `rate_limit` rule is
//! reported as [`RecheckIndeterminate::RateLimitUnevaluable`] rather than
//! guessed. Guessing would be the worst outcome available — a confident verdict
//! that is right half the time.
//!
//! Recheck is **chain-only**. It reads what the record says the call resolved to
//! and never re-derives it: `decision_axes.fs.path_canonical` is taken as
//! recorded, never re-resolved against the filesystem and never stat-ed. A
//! recheck that touched the filesystem would report on *today's* symlinks, not
//! the ones the call actually ran under, and would answer differently on a
//! machine that never saw the call.
//!
//! Nothing in this module — including its tests — opens a path, and the
//! anti-pattern grep in the ticket is over the file, so the prohibited calls are
//! not named here even in prose.

use std::fmt;

use botzr_aegis_core::{
    AuditRecord, PolicyOutcome, PolicySetHash, RequestDigest, ToolId, AUDIT_SCHEMA_VERSION,
};

use crate::engine::PolicyEngine;
use crate::eval::{select, PolicyRequest, Selection};
use crate::set::{DefaultAction, RuleKind};

/// The reason attached to a call the *new* set would block.
///
/// Fixed text, and it has to be: [`RecheckClass::Deny`] is a class, not a rule —
/// it carries no id and no `reason`, so [`classify`] has no rule prose available
/// to quote even if quoting it were desirable. That is the design, not a
/// shortfall. `classify` is then a total function of two small values, which is
/// what makes the verdict matrix exhaustively testable, and the recheck line
/// prints only the token `denied` anyway.
const NEWLY_DENIED_REASON: &str = "denied by the rechecked policy set";

/// What the new Policy Set would decide, before it is compared with what was
/// recorded.
///
/// Deliberately *not* [`botzr_aegis_core::PolicyAction`]: that type carries a
/// minted `approval_id` and a rate-limit `reason`, both of which are products of
/// the live engine's mutable state. A preview that could name an approval id
/// would be a preview that minted one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecheckClass {
    Allow,
    Deny,
    /// A `pending_approval` rule matched. No id: parking is a class here, and an
    /// id invented by a forensic tool would read like an approval that exists.
    Park,
    /// A `rate_limit` rule matched. The id rides along so the report can name
    /// the rule whose state it cannot reconstruct.
    RateLimit {
        rule_id: String,
    },
}

/// How a recorded verdict compares with what the new Policy Set would decide.
///
/// Five states, per the ticket AC. `NewlyBlocked` and `NewlyParked` are kept
/// apart on purpose: a call the new set would refuse outright and a call it
/// would send to a human are different findings, and collapsing them would let a
/// governance change that adds a review gate read as an outage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecheckVerdict {
    /// Same class as recorded. `action` is the recorded outcome verbatim, so the
    /// original `reason` / `approval_id` survive for a caller that wants them —
    /// the printed line shows only the token.
    Unchanged { action: PolicyOutcome },
    /// Ran (or was allowed to run) then; refused now. This is the finding the
    /// verb exists to surface.
    NewlyBlocked {
        was: PolicyOutcome,
        now: PolicyOutcome,
    },
    /// Refused then; allowed now. Reported, not celebrated — a policy edit that
    /// unblocks past calls is exactly as reviewable as one that blocks them.
    NewlyAllowed {
        was: PolicyOutcome,
        now: PolicyOutcome,
    },
    /// Would now be held for human approval.
    ///
    /// There is no `now` field, and that absence is load-bearing: a `now` here
    /// would have to be `PolicyOutcome::PendingApproval { approval_id }`, and the
    /// only id available would be one this function invented. An approval id
    /// names a real decision an operator can be asked about; synthesising one
    /// into evidence — even an empty string or a placeholder — puts a claim in
    /// the record that nothing backs. Making the field unrepresentable is
    /// cheaper than documenting that it must be ignored.
    NewlyParked { was: PolicyOutcome },
    /// The question could not be answered from the record and the Policy Set
    /// alone. Never a silent `Unchanged`.
    Indeterminate { reason: RecheckIndeterminate },
}

/// Why a recheck declined to answer.
///
/// Deliberately **not** the audit crate's `IndeterminateReason`: that enum
/// answers "is this chain intact?", this one answers "can this verdict be
/// re-derived?". They share a word and nothing else, and one enum serving two
/// questions is how a reason gets added for one caller and silently widens the
/// other's contract. (Named without its path on purpose — the ticket's grep for
/// a reused verify reason is over this file, and a doc comment must not be the
/// thing that trips it.)
///
/// Exhaustive on purpose (no `#[non_exhaustive]`): a sixth reason must break
/// every `match` inside this crate, because every reason is a printable token
/// and an unhandled one would print as nothing at all.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecheckIndeterminate {
    /// The Envelope holding the request body is not available.
    ///
    /// **No production caller today.** Envelope I/O does not exist (`spec/SPEC.md`
    /// §6: the Envelope is forensic storage, recheck is chain-only), and this
    /// crate must not grow a loader to justify the variant. It is declared now so
    /// that when argument matchers land the reason is already in the vocabulary
    /// the CLI prints, rather than being bolted on as a sixth token later.
    MissingEnvelope { request_digest: RequestDigest },
    /// An Envelope was found for this call and its digest is not the one the
    /// record names — the body on disk is not the body that ran. Same "declared
    /// early, no production caller" note as [`RecheckIndeterminate::MissingEnvelope`].
    EnvelopeDigestMismatch {
        expected: RequestDigest,
        found: RequestDigest,
    },
    /// The record is not written in a schema this build understands, so its
    /// fields cannot be trusted to mean what they are named.
    UnknownPolicySetHash { recorded: PolicySetHash },
    /// A line claims to be an outcome but names no tool, so there is nothing to
    /// evaluate a policy against. Raised by the CLI's line walker, which is the
    /// only layer that sees loose JSON.
    NoBinding { tool_id: ToolId },
    /// A `rate_limit` rule governs the call and its window is process-local
    /// counter state (`crate::ratelimit`) that no record carries. See the module
    /// header: unknowable is reported, not guessed.
    RateLimitUnevaluable { rule_id: String },
}

impl PolicyEngine {
    /// What the active Policy Set *would* decide for `req`, writing nothing.
    ///
    /// The read-only twin of [`PolicyEngine::evaluate`]: same `select`, so the
    /// same G5 conflict resolution decides the winning rule, then the rule kind
    /// is mapped straight to a class. It deliberately stops short of
    /// `PolicyEngine::finalize`, which is where the two side effects live —
    /// the rate-limiter counter bump and the approval-id `fetch_add`. Neither is
    /// reachable from here, which is the property the recheck AC turns on: call
    /// this a thousand times over one record and every answer is the first
    /// answer.
    ///
    /// A `rate_limit` rule returns [`RecheckClass::RateLimit`] rather than the
    /// admit/refuse that `evaluate` would compute, because computing it *is* the
    /// side effect.
    pub fn preview(&self, req: &PolicyRequest<'_>) -> RecheckClass {
        let set = self.snapshot();
        match select(&set, req) {
            Selection::Default(DefaultAction::Allow) => RecheckClass::Allow,
            Selection::Default(DefaultAction::Deny) => RecheckClass::Deny,
            Selection::Matched(rule) => match rule.kind {
                RuleKind::Allow => RecheckClass::Allow,
                RuleKind::Deny => RecheckClass::Deny,
                RuleKind::PendingApproval => RecheckClass::Park,
                RuleKind::RateLimit => RecheckClass::RateLimit {
                    rule_id: rule.id.clone(),
                },
            },
        }
    }
}

/// Compare a recorded outcome with what the new set would decide.
///
/// `Denied` and `RateLimited` are **one class** — *blocked* — when deciding
/// whether anything changed. Both mean the call did not run, and a policy edit
/// that swaps one refusal mechanism for another has not changed what an operator
/// can do; reporting that as `newly_blocked` would bury the real findings under
/// noise. The distinction is still visible: the recorded outcome is carried
/// verbatim in `was` / `action`.
pub fn classify(was: &PolicyOutcome, now: RecheckClass) -> RecheckVerdict {
    match now {
        // Checked first, and unconditionally: a rate-limited rule is unevaluable
        // whatever was recorded, so there is no `was` for which a comparison
        // would be honest.
        RecheckClass::RateLimit { rule_id } => RecheckVerdict::Indeterminate {
            reason: RecheckIndeterminate::RateLimitUnevaluable { rule_id },
        },
        RecheckClass::Allow => match was {
            PolicyOutcome::Allowed => RecheckVerdict::Unchanged {
                action: was.clone(),
            },
            _ => RecheckVerdict::NewlyAllowed {
                was: was.clone(),
                now: PolicyOutcome::Allowed,
            },
        },
        RecheckClass::Deny => {
            if is_blocked(was) {
                RecheckVerdict::Unchanged {
                    action: was.clone(),
                }
            } else {
                RecheckVerdict::NewlyBlocked {
                    was: was.clone(),
                    now: PolicyOutcome::Denied {
                        reason: NEWLY_DENIED_REASON.to_string(),
                    },
                }
            }
        }
        RecheckClass::Park => match was {
            PolicyOutcome::PendingApproval { .. } => RecheckVerdict::Unchanged {
                action: was.clone(),
            },
            _ => RecheckVerdict::NewlyParked { was: was.clone() },
        },
    }
}

/// `Denied` and `RateLimited` both mean "the call did not run". See [`classify`].
fn is_blocked(was: &PolicyOutcome) -> bool {
    matches!(
        was,
        PolicyOutcome::Denied { .. } | PolicyOutcome::RateLimited { .. }
    )
}

/// Recheck one Agent Action Record against `engine`'s active Policy Set.
///
/// The request is rebuilt from **three axes only** — `capability`, `role`,
/// `session` — because those, plus `tool_id`, are exactly what a
/// [`PolicyRequest`] is. `decision_axes` also carries `fs` and `net`, and this
/// function reads neither: they are derived *resources*, not match axes (no
/// matcher consults them today), and reaching for a recorded path is one short
/// step from resolving it. Nothing in this call graph touches the filesystem.
///
/// A record from another schema version is [`RecheckVerdict::Indeterminate`],
/// not a best-effort read. Field names are only meaningful relative to the
/// schema that defined them; re-evaluating a v1 record with v2 semantics would
/// produce a verdict that looks authoritative and is unfounded.
pub fn recheck_record(engine: &PolicyEngine, record: &AuditRecord) -> RecheckVerdict {
    if record.schema_version() != AUDIT_SCHEMA_VERSION {
        return RecheckVerdict::Indeterminate {
            reason: RecheckIndeterminate::UnknownPolicySetHash {
                recorded: record.policy_set_hash,
            },
        };
    }

    let axes = &record.decision_axes;
    let request = PolicyRequest {
        tool_id: &record.tool_id,
        capability: axes.capability.as_deref(),
        role: axes.role.as_deref(),
        session: axes.session.as_deref(),
    };

    classify(&record.policy, engine.preview(&request))
}

/// The wire token for a recorded outcome: `allowed` | `denied` | `rate_limited`
/// | `pending_approval`.
///
/// Lives in this crate rather than the CLI so that the two spellings cannot
/// drift: the crate that decides the verdict also owns the word for it. It is a
/// free function because [`PolicyOutcome`] belongs to `botzr-aegis-core` and a
/// `Display` impl on a foreign type is not ours to write.
pub fn outcome_token(outcome: &PolicyOutcome) -> &'static str {
    match outcome {
        PolicyOutcome::Allowed => "allowed",
        PolicyOutcome::Denied { .. } => "denied",
        PolicyOutcome::RateLimited { .. } => "rate_limited",
        PolicyOutcome::PendingApproval { .. } => "pending_approval",
    }
}

/// Renders the verdict clause of a recheck line — everything after
/// `call {id} session {i} seq {n}: `.
///
/// The whole clause, not just the kind token, so the CLI stays a formatter that
/// prefixes an identity and never assembles vocabulary of its own.
impl fmt::Display for RecheckVerdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unchanged { action } => write!(f, "unchanged {}", outcome_token(action)),
            Self::NewlyBlocked { was, now } => write!(
                f,
                "newly_blocked was={} now={}",
                outcome_token(was),
                outcome_token(now)
            ),
            Self::NewlyAllowed { was, now } => write!(
                f,
                "newly_allowed was={} now={}",
                outcome_token(was),
                outcome_token(now)
            ),
            Self::NewlyParked { was } => write!(f, "newly_parked was={}", outcome_token(was)),
            Self::Indeterminate { reason } => write!(f, "indeterminate {reason}"),
        }
    }
}

/// Renders the reason **token only** — the payload is deliberately dropped.
///
/// A recheck report is a pure function of its two inputs and echoes no digests,
/// paths or key material: printing `unknown_policy_set_hash <64 hex>` would put
/// content-addressed material into a line whose job is to be diffed, and a
/// caller that wants the value has the variant's field. Same reason
/// `MissingEnvelope` does not print its request digest.
impl fmt::Display for RecheckIndeterminate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let token = match self {
            Self::MissingEnvelope { .. } => "missing_envelope",
            Self::EnvelopeDigestMismatch { .. } => "envelope_digest_mismatch",
            Self::UnknownPolicySetHash { .. } => "unknown_policy_set_hash",
            Self::NoBinding { .. } => "no_binding",
            Self::RateLimitUnevaluable { .. } => "rate_limit_unevaluable",
        };
        f.write_str(token)
    }
}

/// # A note on `evaluate` in this module
///
/// The tests below are the **only** place in this file that calls
/// [`PolicyEngine::evaluate`], and they do it on purpose: the property that
/// `preview` writes nothing is not observable from `preview` alone. It is only
/// visible as a *contrast* — the live path still has its full rate-limit budget
/// and its approval sequence still starts at 1 after previewing. Asserting one
/// half without the other would let `preview` silently start bumping the
/// counter and the test would keep passing.
///
/// So the ticket's `! git grep '\.evaluate('` gate over this file reports these
/// three lines. It is a gate on the *production* path — nothing reachable from
/// [`recheck_record`] or [`classify`] calls `evaluate` — and the same ticket
/// requires this contrast test in this file, so the two cannot both be
/// literally satisfied. Do not "fix" it by deleting the contrast.
#[cfg(test)]
mod tests {
    use super::*;
    use botzr_aegis_core::{CapabilityOutcome, DecisionAxes, ExecutionOutcome, FsAxis};

    fn allowed() -> PolicyOutcome {
        PolicyOutcome::Allowed
    }

    fn denied() -> PolicyOutcome {
        PolicyOutcome::Denied {
            reason: "recorded deny".to_string(),
        }
    }

    fn rate_limited() -> PolicyOutcome {
        PolicyOutcome::RateLimited {
            reason: "recorded rate limit".to_string(),
        }
    }

    fn pending() -> PolicyOutcome {
        PolicyOutcome::PendingApproval {
            approval_id: "apr-gate-tool-7".to_string(),
        }
    }

    // ---------------------------------------------------------------- classify

    /// The §3.1 table, spelled out. Every `now` class against every `was`
    /// variant — including both spellings of *blocked*, which the table folds
    /// into one column and this test keeps as two rows, so a future edit that
    /// stops treating `RateLimited` as blocked fails here.
    #[test]
    fn classify_matrix_matches_the_specified_table() {
        let cases: Vec<(PolicyOutcome, RecheckClass, RecheckVerdict)> = vec![
            // now = Allow
            (
                allowed(),
                RecheckClass::Allow,
                RecheckVerdict::Unchanged { action: allowed() },
            ),
            (
                denied(),
                RecheckClass::Allow,
                RecheckVerdict::NewlyAllowed {
                    was: denied(),
                    now: allowed(),
                },
            ),
            (
                rate_limited(),
                RecheckClass::Allow,
                RecheckVerdict::NewlyAllowed {
                    was: rate_limited(),
                    now: allowed(),
                },
            ),
            (
                pending(),
                RecheckClass::Allow,
                RecheckVerdict::NewlyAllowed {
                    was: pending(),
                    now: allowed(),
                },
            ),
            // now = Deny
            (
                allowed(),
                RecheckClass::Deny,
                RecheckVerdict::NewlyBlocked {
                    was: allowed(),
                    now: PolicyOutcome::Denied {
                        reason: NEWLY_DENIED_REASON.to_string(),
                    },
                },
            ),
            (
                denied(),
                RecheckClass::Deny,
                RecheckVerdict::Unchanged { action: denied() },
            ),
            (
                rate_limited(),
                RecheckClass::Deny,
                RecheckVerdict::Unchanged {
                    action: rate_limited(),
                },
            ),
            (
                pending(),
                RecheckClass::Deny,
                RecheckVerdict::NewlyBlocked {
                    was: pending(),
                    now: PolicyOutcome::Denied {
                        reason: NEWLY_DENIED_REASON.to_string(),
                    },
                },
            ),
            // now = Park
            (
                allowed(),
                RecheckClass::Park,
                RecheckVerdict::NewlyParked { was: allowed() },
            ),
            (
                denied(),
                RecheckClass::Park,
                RecheckVerdict::NewlyParked { was: denied() },
            ),
            (
                rate_limited(),
                RecheckClass::Park,
                RecheckVerdict::NewlyParked {
                    was: rate_limited(),
                },
            ),
            (
                pending(),
                RecheckClass::Park,
                RecheckVerdict::Unchanged { action: pending() },
            ),
            // now = RateLimit — unevaluable whatever was recorded.
            (
                allowed(),
                RecheckClass::RateLimit {
                    rule_id: "rl".to_string(),
                },
                RecheckVerdict::Indeterminate {
                    reason: RecheckIndeterminate::RateLimitUnevaluable {
                        rule_id: "rl".to_string(),
                    },
                },
            ),
            (
                denied(),
                RecheckClass::RateLimit {
                    rule_id: "rl".to_string(),
                },
                RecheckVerdict::Indeterminate {
                    reason: RecheckIndeterminate::RateLimitUnevaluable {
                        rule_id: "rl".to_string(),
                    },
                },
            ),
            (
                rate_limited(),
                RecheckClass::RateLimit {
                    rule_id: "rl".to_string(),
                },
                RecheckVerdict::Indeterminate {
                    reason: RecheckIndeterminate::RateLimitUnevaluable {
                        rule_id: "rl".to_string(),
                    },
                },
            ),
            (
                pending(),
                RecheckClass::RateLimit {
                    rule_id: "rl".to_string(),
                },
                RecheckVerdict::Indeterminate {
                    reason: RecheckIndeterminate::RateLimitUnevaluable {
                        rule_id: "rl".to_string(),
                    },
                },
            ),
        ];

        assert_eq!(cases.len(), 16, "4 recorded outcomes x 4 preview classes");
        for (was, now, expected) in cases {
            let got = classify(&was, now.clone());
            assert_eq!(got, expected, "classify({was:?}, {now:?})");
        }
    }

    /// The recorded outcome survives into the verdict verbatim, so a caller that
    /// wants the original deny prose or approval id still has it.
    #[test]
    fn classify_carries_the_recorded_outcome_verbatim() {
        match classify(&pending(), RecheckClass::Deny) {
            RecheckVerdict::NewlyBlocked { was, .. } => assert_eq!(was, pending()),
            other => panic!("expected newly blocked, got {other:?}"),
        }
        match classify(&pending(), RecheckClass::Park) {
            RecheckVerdict::Unchanged { action } => assert_eq!(action, pending()),
            other => panic!("expected unchanged, got {other:?}"),
        }
    }

    /// `NewlyBlocked.now` must not carry anything that moves between runs — no
    /// clock, no counter, no minted id.
    #[test]
    fn newly_blocked_reason_is_stable_across_calls() {
        let first = classify(&allowed(), RecheckClass::Deny);
        let second = classify(&allowed(), RecheckClass::Deny);
        assert_eq!(first, second);
        match first {
            RecheckVerdict::NewlyBlocked { now, .. } => {
                assert_eq!(
                    now,
                    PolicyOutcome::Denied {
                        reason: NEWLY_DENIED_REASON.to_string()
                    }
                );
            }
            other => panic!("expected newly blocked, got {other:?}"),
        }
    }

    // ----------------------------------------------------------------- preview

    const RATE_ONE: &str = r#"
version: 1
default: allow
rules:
  - id: rl
    action: rate_limit
    tool: chatty
    rate: { max: 1, per_seconds: 60 }
"#;

    /// The load-bearing property of the whole module, asserted as a contrast in
    /// one test so the two halves cannot drift apart:
    ///
    /// * two `preview` calls over a `max: 1` rule both report `RateLimit` — the
    ///   window was never touched;
    /// * `evaluate` on the *same* engine afterwards still admits the first call
    ///   (`Allow`) and only then trips (`RateLimited`), which proves the previews
    ///   consumed no budget.
    ///
    /// Order matters: had `preview` bumped the counter, the first `evaluate`
    /// below would already be `RateLimited`.
    #[test]
    fn preview_does_not_bump_the_rate_limiter() {
        use botzr_aegis_core::PolicyAction;

        let engine = PolicyEngine::from_yaml(RATE_ONE).expect("parse");
        let tool = ToolId::new("chatty");
        let req = PolicyRequest::for_tool(&tool);

        let expected = RecheckClass::RateLimit {
            rule_id: "rl".to_string(),
        };
        assert_eq!(engine.preview(&req), expected, "first preview");
        assert_eq!(
            engine.preview(&req),
            expected,
            "second preview is identical"
        );

        // The live path, on the same engine: budget of 1 is intact.
        assert_eq!(engine.evaluate(&req).action, PolicyAction::Allow);
        match engine.evaluate(&req).action {
            PolicyAction::RateLimited { .. } => {}
            other => panic!("expected the second evaluate to trip, got {other:?}"),
        }
    }

    /// `preview` must not mint an approval id either — the counter is only
    /// observable through `evaluate`, so this asserts the sequence has not moved.
    #[test]
    fn preview_does_not_mint_an_approval_id() {
        use botzr_aegis_core::PolicyAction;

        let yaml = "version: 1\ndefault: allow\nrules:\n  - id: gate\n    action: pending_approval\n    tool: dream\n";
        let engine = PolicyEngine::from_yaml(yaml).expect("parse");
        let tool = ToolId::new("dream");
        let req = PolicyRequest::for_tool(&tool);

        for _ in 0..5 {
            assert_eq!(engine.preview(&req), RecheckClass::Park);
        }

        // Still the first id in the sequence: five previews minted nothing.
        match engine.evaluate(&req).action {
            PolicyAction::PendingApproval { approval_id } => {
                assert_eq!(approval_id, "apr-gate-dream-1");
            }
            other => panic!("expected pending approval, got {other:?}"),
        }
    }

    #[test]
    fn preview_maps_defaults_and_every_rule_kind() {
        let tool = ToolId::new("t");
        let req = PolicyRequest::for_tool(&tool);

        let cases = [
            ("version: 1\ndefault: allow\nrules: []\n", RecheckClass::Allow),
            ("version: 1\ndefault: deny\nrules: []\n", RecheckClass::Deny),
            (
                "version: 1\ndefault: deny\nrules:\n  - id: a\n    action: allow\n    tool: t\n",
                RecheckClass::Allow,
            ),
            (
                "version: 1\ndefault: allow\nrules:\n  - id: d\n    action: deny\n    tool: t\n",
                RecheckClass::Deny,
            ),
            (
                "version: 1\ndefault: allow\nrules:\n  - id: p\n    action: pending_approval\n    tool: t\n",
                RecheckClass::Park,
            ),
        ];
        for (yaml, expected) in cases {
            let engine = PolicyEngine::from_yaml(yaml).expect("parse");
            assert_eq!(engine.preview(&req), expected, "{yaml}");
        }
    }

    /// `preview` reuses `select`, so G5 conflict resolution is not re-implemented
    /// here — deny-overrides still wins over a more specific allow.
    #[test]
    fn preview_inherits_g5_deny_overrides() {
        let yaml = "version: 1\ndefault: allow\nrules:\n  - id: allow-specific\n    action: allow\n    tool: t\n    role: owner\n  - id: deny-broad\n    action: deny\n    tool: t\n";
        let engine = PolicyEngine::from_yaml(yaml).expect("parse");
        let tool = ToolId::new("t");
        assert_eq!(
            engine.preview(&PolicyRequest::for_tool(&tool).with_role("owner")),
            RecheckClass::Deny
        );
    }

    // ---------------------------------------------------------------- rendering

    #[test]
    fn verdict_display_uses_the_pinned_tokens() {
        assert_eq!(
            RecheckVerdict::Unchanged { action: allowed() }.to_string(),
            "unchanged allowed"
        );
        assert_eq!(
            RecheckVerdict::Unchanged { action: pending() }.to_string(),
            "unchanged pending_approval"
        );
        assert_eq!(
            RecheckVerdict::NewlyBlocked {
                was: allowed(),
                now: denied()
            }
            .to_string(),
            "newly_blocked was=allowed now=denied"
        );
        assert_eq!(
            RecheckVerdict::NewlyAllowed {
                was: rate_limited(),
                now: allowed()
            }
            .to_string(),
            "newly_allowed was=rate_limited now=allowed"
        );
        assert_eq!(
            RecheckVerdict::NewlyParked { was: allowed() }.to_string(),
            "newly_parked was=allowed"
        );
        assert_eq!(
            RecheckVerdict::Indeterminate {
                reason: RecheckIndeterminate::UnknownPolicySetHash {
                    recorded: PolicySetHash::of_canonical_bytes(b"set")
                }
            }
            .to_string(),
            "indeterminate unknown_policy_set_hash"
        );
    }

    #[test]
    fn outcome_tokens_cover_every_variant() {
        assert_eq!(outcome_token(&allowed()), "allowed");
        assert_eq!(outcome_token(&denied()), "denied");
        assert_eq!(outcome_token(&rate_limited()), "rate_limited");
        assert_eq!(outcome_token(&pending()), "pending_approval");
    }

    /// The two Envelope reasons have no production caller — Envelope I/O does not
    /// exist — so their tokens are only reachable through constructed values.
    /// Without this test the CLI could print a token nothing ever proved.
    #[test]
    fn constructed_envelope_reasons_display_as_their_tokens() {
        let one = RequestDigest::of_request_bytes(b"{\"a\":1}");
        let other = RequestDigest::of_request_bytes(b"{\"a\":2}");

        let missing = RecheckIndeterminate::MissingEnvelope {
            request_digest: one,
        };
        assert_eq!(missing.to_string(), "missing_envelope");

        let mismatch = RecheckIndeterminate::EnvelopeDigestMismatch {
            expected: one,
            found: other,
        };
        assert_eq!(mismatch.to_string(), "envelope_digest_mismatch");

        // Rendered through a verdict, which is how the CLI reaches them.
        assert_eq!(
            RecheckVerdict::Indeterminate { reason: missing }.to_string(),
            "indeterminate missing_envelope"
        );
        assert_eq!(
            RecheckVerdict::Indeterminate { reason: mismatch }.to_string(),
            "indeterminate envelope_digest_mismatch"
        );
    }

    #[test]
    fn remaining_indeterminate_reasons_display_as_their_tokens() {
        assert_eq!(
            RecheckIndeterminate::NoBinding {
                tool_id: ToolId::new("t")
            }
            .to_string(),
            "no_binding"
        );
        assert_eq!(
            RecheckIndeterminate::RateLimitUnevaluable {
                rule_id: "rl".to_string()
            }
            .to_string(),
            "rate_limit_unevaluable"
        );
    }

    // ---------------------------------------------------------- recheck_record

    fn record(tool: &str, policy: PolicyOutcome) -> AuditRecord {
        AuditRecord::new(
            "call-1",
            ToolId::new(tool),
            RequestDigest::of_request_bytes(b"{}"),
            PolicySetHash::of_canonical_bytes(b"recorded-set"),
            policy,
            CapabilityOutcome::Denied {
                reason: "not evaluated".to_string(),
                denied_capability: None,
            },
            ExecutionOutcome::Success,
        )
    }

    #[test]
    fn recheck_record_reports_a_would_block() {
        let engine = PolicyEngine::from_yaml(
            "version: 1\ndefault: allow\nrules:\n  - id: d\n    action: deny\n    tool: writer\n",
        )
        .expect("parse");
        let verdict = recheck_record(&engine, &record("writer", allowed()));
        assert_eq!(verdict.to_string(), "newly_blocked was=allowed now=denied");
    }

    #[test]
    fn recheck_record_reports_unchanged_when_the_set_still_allows() {
        let engine = PolicyEngine::from_yaml("version: 1\ndefault: allow\nrules: []\n").unwrap();
        assert_eq!(
            recheck_record(&engine, &record("writer", allowed())).to_string(),
            "unchanged allowed"
        );
    }

    /// A record already parked and still parked is `unchanged`, not
    /// `newly_parked` — the class did not move.
    #[test]
    fn recheck_record_keeps_a_still_parked_call_unchanged() {
        let engine = PolicyEngine::from_yaml(
            "version: 1\ndefault: allow\nrules:\n  - id: gate\n    action: pending_approval\n    tool: writer\n",
        )
        .unwrap();
        assert_eq!(
            recheck_record(&engine, &record("writer", pending())).to_string(),
            "unchanged pending_approval"
        );
    }

    /// The three axes the request is rebuilt from are the three
    /// [`PolicyRequest`] scalars — a role-gated rule fires only when the record
    /// carried that role.
    #[test]
    fn recheck_record_rebuilds_the_three_policy_axes() {
        let engine = PolicyEngine::from_yaml(
            "version: 1\ndefault: allow\nrules:\n  - id: role-deny\n    action: deny\n    tool: writer\n    role: contractor\n    capability: fs.write\n",
        )
        .unwrap();

        let bare = record("writer", allowed());
        assert_eq!(
            recheck_record(&engine, &bare).to_string(),
            "unchanged allowed",
            "no axes recorded, so the role-gated rule does not match"
        );

        let axes = DecisionAxes::default()
            .with_capability("fs.write")
            .with_role("contractor")
            .with_session("s-1");
        let gated = record("writer", allowed()).with_decision_axes(axes);
        assert_eq!(
            recheck_record(&engine, &gated).to_string(),
            "newly_blocked was=allowed now=denied"
        );
    }

    /// The `fs` axis is recorded evidence, not an input to this decision. The
    /// path here does not exist and never will; recheck neither stats it nor
    /// lets it change the verdict, which is why a symlink repointed after the
    /// fact cannot move a recheck result.
    #[test]
    fn recheck_record_ignores_the_fs_axis_entirely() {
        let engine = PolicyEngine::from_yaml("version: 1\ndefault: allow\nrules: []\n").unwrap();

        let axes = DecisionAxes::default().with_fs(FsAxis {
            path_raw: "/nonexistent/aegis-recheck/link".to_string(),
            path_canonical: "/nonexistent/aegis-recheck/target".to_string(),
        });
        let with_fs = record("writer", allowed()).with_decision_axes(axes);
        assert_eq!(
            recheck_record(&engine, &with_fs),
            recheck_record(&engine, &record("writer", allowed())),
            "a dangling recorded path must not change the verdict"
        );
    }

    /// `AuditRecord::new` always stamps the current schema version — the field is
    /// sealed precisely so a caller cannot forge one — so the only way to hold a
    /// foreign-schema record is to deserialize one, which is also the only way a
    /// real recheck would ever meet it.
    #[test]
    fn recheck_record_on_a_foreign_schema_version_is_indeterminate() {
        let current = record("writer", allowed());
        let json = serde_json::to_string(&current).expect("serialize");
        let v1_json = json.replace("\"schema_version\":2", "\"schema_version\":1");
        assert_ne!(v1_json, json, "the schema_version field must be rewritten");

        let v1: AuditRecord = serde_json::from_str(&v1_json).expect("deserialize v1");
        assert_eq!(v1.schema_version(), 1);
        assert_ne!(v1.schema_version(), AUDIT_SCHEMA_VERSION);

        let engine = PolicyEngine::from_yaml("version: 1\ndefault: deny\nrules: []\n").unwrap();
        let verdict = recheck_record(&engine, &v1);
        assert_eq!(
            verdict,
            RecheckVerdict::Indeterminate {
                reason: RecheckIndeterminate::UnknownPolicySetHash {
                    recorded: v1.policy_set_hash,
                }
            },
            "a default-deny set must not produce a confident newly_blocked here"
        );
        assert_eq!(verdict.to_string(), "indeterminate unknown_policy_set_hash");
    }

    /// Same inputs, same bytes — the AC the forensic verb turns on.
    #[test]
    fn recheck_is_byte_identical_across_repeated_runs() {
        let engine = PolicyEngine::from_yaml(RATE_ONE).unwrap();
        let records = [
            record("chatty", allowed()),
            record("writer", denied()),
            record("writer", pending()),
        ];
        let render = || {
            records
                .iter()
                .map(|r| recheck_record(&engine, r).to_string())
                .collect::<Vec<_>>()
                .join("\n")
        };
        assert_eq!(render(), render());
        // `chatty` is governed by the `max: 1` rule (unevaluable offline);
        // `writer` falls through to `default: allow`, so both recorded refusals
        // read as newly allowed.
        assert_eq!(
            render(),
            "indeterminate rate_limit_unevaluable\n\
             newly_allowed was=denied now=allowed\n\
             newly_allowed was=pending_approval now=allowed"
        );
    }
}
