//! Property tests for the RFC 8785 (JCS) canonicalizer — AILAB-850.
//!
//! `to_canonical_json` computes the hash input for **every signature in every
//! Chain**, and it is reached from attacker-controlled bytes at three places:
//! the verifier walk (`crates/botzr-aegis-audit/src/verdict.rs`), signature
//! verification (`crates/botzr-aegis-audit/src/signing.rs`) and
//! `tail_of_lines` (`crates/botzr-aegis-audit/src/sink.rs`), which runs
//! *before* a Session opens on an existing file. A divergence there does not
//! fail loudly: it invalidates every signature and surfaces as an
//! unexplainable hash mismatch.
//!
//! These live in `tests/` rather than in `jcs.rs`'s own test module for two
//! reasons: they need nothing beyond the published surface
//! (`to_canonical_json`, `canonical_digest`, `JcsError`, `MAX_SAFE_INTEGER`),
//! and integration tests stay out of the coverage denominator.
//!
//! They do **not** replace the hand-written cases in `jcs.rs`, and the reason
//! is stronger than a preference for named cases: **no property in this file
//! can pin an absolute key order**, because all three compare the
//! canonicalizer against itself. Replacing the UTF-16 sort in `write_value`'s
//! object branch with Rust's `String: Ord` was measured against the whole
//! workspace: 68 suites, 506 passed, **one** failed. Every property in this
//! file stayed green, and so did `published_test_vector_canonical_form_and_hash`,
//! whose keys are all ASCII — where UTF-8 and UTF-16 agree. The only test that
//! caught it was `object_keys_sort_by_utf16_code_unit_not_utf8_bytes`. Do not
//! delete it, and do not assume a property here subsumes it.

use botzr_aegis_core::jcs::MAX_SAFE_INTEGER;
use botzr_aegis_core::{canonical_digest, to_canonical_json, JcsError};
use proptest::prelude::*;
use serde_json::Value;
use std::collections::BTreeSet;

/// Characters chosen so the generated keys reach `utf16_key_cmp`'s reason for
/// existing. RFC 8785 §3.2.3 sorts by UTF-16 code unit; Rust's `String: Ord`
/// sorts by UTF-8 byte. The two agree on ASCII and disagree across the
/// surrogate boundary — UTF-8 sorts U+E000..U+FFFF *below* the astral planes,
/// UTF-16 sorts them *above*, because astral characters encode as surrogates
/// starting at 0xD800. A generator that only emits ASCII would never tell the
/// two orders apart, and the divergence is precisely the failure mode this
/// file exists to catch.
fn interesting_char() -> impl Strategy<Value = char> {
    prop_oneof![
        // Printable ASCII — the ordinary case, and the only one our own keys use.
        4 => proptest::char::range('\u{20}', '\u{7e}'),
        // Control characters, which `write_string` must escape (RFC 8785 §3.2.2.2).
        2 => proptest::char::range('\u{00}', '\u{1f}'),
        // BMP above the surrogate block: the low side of the divergence.
        2 => proptest::char::range('\u{e000}', '\u{ffff}'),
        // Astral: encodes as a surrogate pair, so UTF-16 sorts it below the line above.
        2 => proptest::char::range('\u{10000}', '\u{10ffff}'),
    ]
}

/// Object keys and string values. Short, because the interesting behaviour is
/// in which characters appear, not in how many.
fn any_key() -> impl Strategy<Value = String> {
    proptest::collection::vec(interesting_char(), 0..6)
        .prop_map(|chars| chars.into_iter().collect())
}

/// A value drawn from **inside** the canonicalizer's value space: strings,
/// booleans, `u64` at or below `MAX_SAFE_INTEGER`, arrays, and objects with
/// arbitrary string keys. Nothing here may make `to_canonical_json` return
/// `Err` — the refusals are property 3's job, and a leak between the two
/// generators would turn a real defect into a passing test.
fn any_in_space_value() -> impl Strategy<Value = Value> {
    let leaf = prop_oneof![
        any::<bool>().prop_map(Value::Bool),
        // The bound itself is pinned rather than left to chance: a uniform draw
        // over 2^53 values essentially never lands on the boundary.
        prop_oneof![
            3 => 0u64..=MAX_SAFE_INTEGER,
            1 => Just(0u64),
            1 => Just(MAX_SAFE_INTEGER),
        ]
        .prop_map(|n| Value::Number(n.into())),
        any_key().prop_map(Value::String),
    ];

    leaf.prop_recursive(3, 32, 4, |inner| {
        prop_oneof![
            proptest::collection::vec(inner.clone(), 0..4).prop_map(Value::Array),
            proptest::collection::btree_map(any_key(), inner, 0..4)
                .prop_map(|members| Value::Object(members.into_iter().collect())),
        ]
    })
}

/// Which of the four value-space refusals a generated value should trigger.
/// `JcsError::Serialize` is deliberately absent: it reports a `serde` failure,
/// not a value-space rule, and a `serde_json::Value` cannot produce one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Refusal {
    Float,
    NegativeInteger,
    IntegerTooLarge,
    Null,
}

/// One out-of-space leaf, paired with the variant it must produce.
fn refused_leaf() -> impl Strategy<Value = (Refusal, Value)> {
    prop_oneof![
        // Finite only: `Number::from_f64` refuses NaN and the infinities, and
        // JSON cannot spell them either, so they are not a reachable input.
        (-1.0e6f64..1.0e6f64).prop_map(|f| (
            Refusal::Float,
            Value::Number(serde_json::Number::from_f64(f).expect("finite float")),
        )),
        (i64::MIN..0i64).prop_map(|n| (Refusal::NegativeInteger, Value::Number(n.into()))),
        ((MAX_SAFE_INTEGER + 1)..=u64::MAX)
            .prop_map(|n| (Refusal::IntegerTooLarge, Value::Number(n.into()))),
        Just((Refusal::Null, Value::Null)),
    ]
}

/// Bury a refused leaf under alternating arrays and single-member objects, so
/// the property covers nested positions rather than only the root.
///
/// The array level carries an in-space sibling; the object level never does,
/// because a second generated key could collide with the first and overwrite
/// the refused leaf, silently turning the case into a passing one.
fn value_containing_a_refusal() -> impl Strategy<Value = (Refusal, Value)> {
    (refused_leaf(), any_key(), any_in_space_value(), 0usize..4).prop_map(
        |((refusal, leaf), key, sibling, depth)| {
            let mut value = leaf;
            for level in 0..depth {
                value = if level % 2 == 0 {
                    Value::Array(vec![sibling.clone(), value])
                } else {
                    Value::Object([(key.clone(), value)].into_iter().collect())
                };
            }
            (refusal, value)
        },
    )
}

/// Serialize members in the given order as JSON object text. Deliberately not
/// canonical: this is the *input* side of property 2, and the whole point is
/// that the input order is arbitrary.
fn object_text(members: &[(String, Value)]) -> String {
    let mut out = String::from("{");
    for (index, (key, value)) in members.iter().enumerate() {
        if index > 0 {
            out.push(',');
        }
        out.push_str(&serde_json::to_string(key).expect("a string always serializes"));
        out.push(':');
        out.push_str(&serde_json::to_string(value).expect("an in-space value always serializes"));
    }
    out.push('}');
    out
}

proptest! {
    /// **Property 1 — idempotence.** Canonicalizing the reparse of a canonical
    /// form reproduces it byte for byte. This is the property the whole Chain
    /// rests on: a third-party verifier reads bytes off disk, parses them, and
    /// re-canonicalizes to check a signature. If that round trip is not the
    /// identity, every signature it checks is wrong.
    ///
    /// The digest is asserted alongside because `canonical_digest` is the
    /// function the audit crate actually calls; a canonical form that agrees
    /// while the digest does not would be the same defect one layer down.
    #[test]
    fn canonicalizing_a_reparsed_canonical_form_reproduces_it(value in any_in_space_value()) {
        let canonical = to_canonical_json(&value)
            .expect("the in-space generator must never produce a refusal");

        let reparsed: Value = serde_json::from_str(&canonical)
            .expect("canonical output must itself be parseable JSON");

        let again = to_canonical_json(&reparsed)
            .expect("a reparsed canonical form is still in the value space");

        prop_assert_eq!(&again, &canonical);
        prop_assert_eq!(
            canonical_digest(&reparsed).expect("digest of a reparsed canonical form"),
            canonical_digest(&value).expect("digest of the original value"),
        );
    }

    /// **Property 2 — member-order independence.** The generated counterpart of
    /// `field_declaration_order_does_not_change_the_canonical_form`, which is
    /// kept in `jcs.rs` rather than replaced by this.
    ///
    /// The two documents are built as *text* in different member orders and
    /// parsed, rather than assembled as values: text is the form the verifier
    /// walk actually receives, and building values directly would compare a
    /// map against itself.
    ///
    /// **What this proves today is narrow, and saying so is the point.**
    /// `serde_json`'s `preserve_order` feature is off in this workspace — its
    /// lock entry pulls no `indexmap` — so `Map` is `BTreeMap`-backed and every
    /// member order parses to the *identical* map before the canonicalizer sees
    /// it. This property can therefore only fail if parsing itself becomes
    /// order-sensitive. It is kept because it is the assertion that would catch
    /// exactly that, and it becomes load-bearing the day `preserve_order` is
    /// switched on.
    #[test]
    fn member_order_in_the_input_text_does_not_change_the_canonical_form(
        members in proptest::collection::vec((any_key(), any_in_space_value()), 1..6),
        rotation in 0usize..6,
    ) {
        // A repeated key is not a permutation of the same document: JSON
        // last-wins means reordering would change which value survives, so the
        // two texts would legitimately canonicalize differently.
        let mut seen = BTreeSet::new();
        let members: Vec<(String, Value)> = members
            .into_iter()
            .filter(|(key, _)| seen.insert(key.clone()))
            .collect();

        let forward: Value = serde_json::from_str(&object_text(&members))
            .expect("generated object text must parse");

        let mut reversed = members.clone();
        reversed.reverse();
        let reversed: Value = serde_json::from_str(&object_text(&reversed))
            .expect("generated object text must parse");

        let mut rotated = members.clone();
        rotated.rotate_left(rotation % members.len());
        let rotated: Value = serde_json::from_str(&object_text(&rotated))
            .expect("generated object text must parse");

        let expected = "the in-space generator must never produce a refusal";
        let canonical = to_canonical_json(&forward).expect(expected);
        let from_reversed = to_canonical_json(&reversed).expect(expected);
        let from_rotated = to_canonical_json(&rotated).expect(expected);

        prop_assert_eq!(&from_reversed, &canonical);
        prop_assert_eq!(&from_rotated, &canonical);
    }

    /// **Property 3 — the value-space refusals hold under generated input.** A
    /// value containing a float, a negative integer, an integer at or above
    /// 2^53, or an explicit `null` never produces output, at any depth, and
    /// fails with the variant that names the reason.
    ///
    /// All four are covered, including `NullNotAllowed`: absent fields are
    /// omitted rather than nulled, and a canonicalizer that quietly picked a
    /// spelling for `null` would hash something no other implementation would.
    #[test]
    fn a_value_outside_the_value_space_never_canonicalizes(
        (refusal, value) in value_containing_a_refusal()
    ) {
        let error = to_canonical_json(&value)
            .expect_err("a value outside the value space must never canonicalize");

        let variant_matches = match refusal {
            Refusal::Float => matches!(error, JcsError::FloatNotAllowed { .. }),
            Refusal::NegativeInteger => matches!(error, JcsError::NegativeInteger { .. }),
            Refusal::IntegerTooLarge => matches!(error, JcsError::IntegerTooLarge { .. }),
            Refusal::Null => matches!(error, JcsError::NullNotAllowed { .. }),
        };
        prop_assert!(
            variant_matches,
            "expected the {refusal:?} refusal, got {error:?}"
        );

        // The digest is the same refusal one layer up: no output means no hash.
        prop_assert!(canonical_digest(&value).is_err());
    }
}
