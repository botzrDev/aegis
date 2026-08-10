//! RFC 8785 (JCS) canonical JSON — the hash input for every audit line.
//!
//! Storage stays JSONL; JCS defines what gets hashed, not what gets written
//! (ADR-0003). The value space is constrained so that JCS's genuinely hard
//! cases — ES6 number formatting, float edge cases — are unreachable, and those
//! constraints are enforced **here, as errors**, not left to convention. A
//! record that cannot be canonicalized must fail loudly rather than hash
//! something subtly different from what a third-party verifier will compute.
//!
//! This is only safe because payloads live in the Envelope: `request_digest` is
//! SHA-256 over raw bytes, so arbitrary user data never reaches the
//! canonicalizer and every key it sees is one of ours. Do not relax that
//! boundary without revisiting ADR-0003.

use std::cmp::Ordering;
use std::fmt;

use serde_json::Value;

use crate::digest::Digest;

/// Largest integer a JavaScript verifier can read as a `Number` without
/// silently losing precision (`Number.MAX_SAFE_INTEGER`).
///
/// The bound exists for cross-language verifiers, not for Rust: a JS
/// implementation reading `seq` as a `Number` is the realistic third-party
/// verifier, and losing precision above 2^53 would break verification in a way
/// nobody would attribute to the format (ADR-0003).
pub const MAX_SAFE_INTEGER: u64 = (1u64 << 53) - 1;

/// Why a value could not be canonicalized.
///
/// Every variant carries the path to the offending value. An implementer who
/// only ever sees "hash mismatch" has nowhere to look; the same reasoning is
/// why the test vectors publish the canonicalized intermediate form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JcsError {
    /// `serde` could not produce a JSON value at all.
    Serialize(String),
    /// A floating-point value. Outside the value space: ES6 number formatting
    /// is the part of JCS implementations disagree about, so no field may be
    /// a float.
    FloatNotAllowed { path: String },
    /// An integer at or above 2^53 — see [`MAX_SAFE_INTEGER`].
    IntegerTooLarge { path: String, value: String },
    /// A negative integer. The value space is `u64`; a negative number in a
    /// record is a bug, and canonicalizing it would ship the bug into evidence.
    NegativeInteger { path: String },
    /// An explicit `null`. Absent fields are **omitted, never null** — a
    /// canonical form cannot leave absent-vs-null to the emitter, so the
    /// canonicalizer refuses rather than picking a spelling.
    NullNotAllowed { path: String },
}

impl fmt::Display for JcsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Serialize(message) => write!(f, "not serializable as JSON: {message}"),
            Self::FloatNotAllowed { path } => {
                write!(
                    f,
                    "floating-point value at {path} is outside the JCS value space"
                )
            }
            Self::IntegerTooLarge { path, value } => write!(
                f,
                "integer {value} at {path} is at or above 2^53 (max {MAX_SAFE_INTEGER})"
            ),
            Self::NegativeInteger { path } => {
                write!(
                    f,
                    "negative integer at {path} is outside the JCS value space"
                )
            }
            Self::NullNotAllowed { path } => {
                write!(
                    f,
                    "null at {path}; absent fields must be omitted, never null"
                )
            }
        }
    }
}

impl std::error::Error for JcsError {}

/// Canonicalize a value to RFC 8785 JSON.
pub fn to_canonical_json<T: serde::Serialize>(value: &T) -> Result<String, JcsError> {
    let value = serde_json::to_value(value).map_err(|e| JcsError::Serialize(e.to_string()))?;
    let mut out = String::new();
    let mut path = String::from("$");
    write_value(&mut out, &value, &mut path)?;
    Ok(out)
}

/// SHA-256 over the canonical bytes of a value.
pub fn canonical_digest<T: serde::Serialize>(value: &T) -> Result<Digest, JcsError> {
    Ok(Digest::sha256(to_canonical_json(value)?.as_bytes()))
}

/// RFC 8785 §3.2.3 sorts object keys by **UTF-16 code unit**, not by UTF-8
/// byte order, which is what Rust's `String: Ord` gives. The two agree across
/// our ASCII key set and disagree above the BMP, where UTF-16 surrogates
/// (0xD800..) sort below U+E000. Implemented to the spec anyway: a third-party
/// emitter's key set may not be ASCII, and this is the kind of divergence that
/// surfaces only as an unexplainable hash mismatch.
fn utf16_key_cmp(a: &str, b: &str) -> Ordering {
    a.encode_utf16().cmp(b.encode_utf16())
}

fn write_value(out: &mut String, value: &Value, path: &mut String) -> Result<(), JcsError> {
    match value {
        Value::Null => Err(JcsError::NullNotAllowed { path: path.clone() }),
        Value::Bool(b) => {
            out.push_str(if *b { "true" } else { "false" });
            Ok(())
        }
        Value::Number(number) => {
            if let Some(unsigned) = number.as_u64() {
                if unsigned > MAX_SAFE_INTEGER {
                    return Err(JcsError::IntegerTooLarge {
                        path: path.clone(),
                        value: unsigned.to_string(),
                    });
                }
                out.push_str(&unsigned.to_string());
                Ok(())
            } else if number.as_i64().is_some() {
                // `as_u64` only fails on a signed integer when it is negative.
                Err(JcsError::NegativeInteger { path: path.clone() })
            } else {
                Err(JcsError::FloatNotAllowed { path: path.clone() })
            }
        }
        Value::String(s) => {
            write_string(out, s);
            Ok(())
        }
        Value::Array(items) => {
            out.push('[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                let restore = path.len();
                path.push_str(&format!("[{index}]"));
                write_value(out, item, path)?;
                path.truncate(restore);
            }
            out.push(']');
            Ok(())
        }
        Value::Object(members) => {
            let mut keys: Vec<&String> = members.keys().collect();
            keys.sort_by(|a, b| utf16_key_cmp(a, b));
            out.push('{');
            for (index, key) in keys.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                write_string(out, key);
                out.push(':');
                let restore = path.len();
                path.push('.');
                path.push_str(key);
                let member = members
                    .get(key.as_str())
                    .expect("key came from this map's own key set");
                write_value(out, member, path)?;
                path.truncate(restore);
            }
            out.push('}');
            Ok(())
        }
    }
}

/// RFC 8785 §3.2.2.2: escape only what JSON requires — `"`, `\`, and the
/// control characters — using the short forms where they exist and lowercase
/// `\u00xx` otherwise. Everything else, including all non-ASCII, is emitted
/// literally as UTF-8.
fn write_string(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{08}' => out.push_str("\\b"),
            '\u{09}' => out.push_str("\\t"),
            '\u{0a}' => out.push_str("\\n"),
            '\u{0c}' => out.push_str("\\f"),
            '\u{0d}' => out.push_str("\\r"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// The normative vector. ADR-0003 requires the **canonicalized intermediate
    /// form** to be published alongside the hash: an implementer who
    /// canonicalizes wrong otherwise sees only "hash mismatch" with nowhere to
    /// look. If this test fails, compare the canonical string first.
    #[test]
    fn published_test_vector_canonical_form_and_hash() {
        let input = json!({
            "tool_id": "echo",
            "seq": 7,
            "decision_axes": {
                "role": "ops",
                "capability": "fs.read",
                "fs": { "path_raw": "~/notes.md", "path_canonical": "/home/a/notes.md" }
            },
            "line_type": "outcome",
            "prev_hash": "0000000000000000000000000000000000000000000000000000000000000000"
        });

        const CANONICAL: &str = concat!(
            r#"{"decision_axes":{"capability":"fs.read","#,
            r#""fs":{"path_canonical":"/home/a/notes.md","path_raw":"~/notes.md"},"#,
            r#""role":"ops"},"line_type":"outcome","#,
            r#""prev_hash":"0000000000000000000000000000000000000000000000000000000000000000","#,
            r#""seq":7,"tool_id":"echo"}"#
        );
        const HASH: &str = "9017de5e13e0a12b261e1960d0d0bc9220c6b7ef501b7dd189141e6327377664";

        assert_eq!(to_canonical_json(&input).unwrap(), CANONICAL);
        assert_eq!(canonical_digest(&input).unwrap().to_hex(), HASH);
        // The hash is exactly SHA-256 over the published canonical bytes —
        // nothing else is mixed in.
        assert_eq!(Digest::sha256(CANONICAL.as_bytes()).to_hex(), HASH);
    }

    #[test]
    fn object_keys_sort_by_utf16_code_unit_not_utf8_bytes() {
        // U+10000 encodes as the surrogate pair 0xD800 0xDC00 in UTF-16, so it
        // sorts *below* U+E000; in UTF-8 byte order it sorts above. Rust's
        // `String: Ord` would get this backwards.
        let input = json!({ "\u{e000}": 1, "\u{10000}": 2 });
        let canonical = to_canonical_json(&input).unwrap();
        assert_eq!(canonical, "{\"\u{10000}\":2,\"\u{e000}\":1}");
        // Guard the premise: naive Rust ordering really does differ.
        assert!("\u{10000}" > "\u{e000}");
        assert_eq!(utf16_key_cmp("\u{10000}", "\u{e000}"), Ordering::Less);
    }

    #[test]
    fn ascii_keys_sort_the_obvious_way() {
        let input = json!({ "z": 1, "a": 2, "M": 3, "_": 4 });
        assert_eq!(
            to_canonical_json(&input).unwrap(),
            r#"{"M":3,"_":4,"a":2,"z":1}"#
        );
    }

    #[test]
    fn strings_use_minimal_rfc8785_escaping() {
        let input = json!({
            "k": "quote:\" backslash:\\ bs:\u{08} tab:\t nl:\n ff:\u{0c} cr:\r nul:\u{00} vt:\u{0b} slash:/ unicode:é"
        });
        assert_eq!(
            to_canonical_json(&input).unwrap(),
            "{\"k\":\"quote:\\\" backslash:\\\\ bs:\\b tab:\\t nl:\\n ff:\\f cr:\\r nul:\\u0000 vt:\\u000b slash:/ unicode:é\"}"
        );
    }

    #[test]
    fn floats_are_rejected() {
        let err = to_canonical_json(&json!({ "wall": 1.5 })).unwrap_err();
        assert_eq!(
            err,
            JcsError::FloatNotAllowed {
                path: "$.wall".into()
            }
        );
        // Integral floats are floats too — `1.0` is not an escape hatch.
        assert!(matches!(
            to_canonical_json(&json!({ "wall": 1.0f64 })),
            Err(JcsError::FloatNotAllowed { .. })
        ));
    }

    #[test]
    fn integers_at_or_above_2_pow_53_are_rejected() {
        assert_eq!(
            to_canonical_json(&json!({ "seq": MAX_SAFE_INTEGER })).unwrap(),
            r#"{"seq":9007199254740991}"#
        );
        let err = to_canonical_json(&json!({ "seq": MAX_SAFE_INTEGER + 1 })).unwrap_err();
        assert_eq!(
            err,
            JcsError::IntegerTooLarge {
                path: "$.seq".into(),
                value: "9007199254740992".into()
            }
        );
    }

    #[test]
    fn negative_integers_are_rejected() {
        assert_eq!(
            to_canonical_json(&json!({ "seq": -1 })).unwrap_err(),
            JcsError::NegativeInteger {
                path: "$.seq".into()
            }
        );
    }

    #[test]
    fn nulls_are_rejected_because_absent_means_omitted() {
        assert_eq!(
            to_canonical_json(&json!({ "grant_id": null })).unwrap_err(),
            JcsError::NullNotAllowed {
                path: "$.grant_id".into()
            }
        );
    }

    #[test]
    fn error_paths_point_at_the_offending_value() {
        let err = to_canonical_json(&json!({ "a": { "b": [1, 2.5] } })).unwrap_err();
        assert_eq!(
            err,
            JcsError::FloatNotAllowed {
                path: "$.a.b[1]".into()
            }
        );
    }

    #[test]
    fn arrays_keep_their_order() {
        assert_eq!(
            to_canonical_json(&json!({ "p": [3, 1, 2] })).unwrap(),
            r#"{"p":[3,1,2]}"#
        );
    }

    #[test]
    fn field_declaration_order_does_not_change_the_canonical_form() {
        #[derive(serde::Serialize)]
        struct Forward {
            alpha: u64,
            beta: u64,
        }
        #[derive(serde::Serialize)]
        struct Reverse {
            beta: u64,
            alpha: u64,
        }
        assert_eq!(
            to_canonical_json(&Forward { alpha: 1, beta: 2 }).unwrap(),
            to_canonical_json(&Reverse { beta: 2, alpha: 1 }).unwrap()
        );
    }

    #[test]
    fn booleans_and_empty_containers_canonicalize() {
        assert_eq!(
            to_canonical_json(&json!({ "t": true, "f": false, "o": {}, "a": [] })).unwrap(),
            r#"{"a":[],"f":false,"o":{},"t":true}"#
        );
    }
}
