//! The trust store: a file of public keys an auditor is willing to pin to
//! (AILAB-704).
//!
//! **Why this lives in the audit library and not in the CLI.** The dialect is
//! already normative — `spec/SPEC.md` § *The `aegis verify` command surface*
//! fixes it as one 64-lowercase-hex public key per line, with blank lines and
//! comment lines skipped — so it is a property of the record format, not of the
//! one program that happens to read it today. It belongs beside the walk it
//! feeds for the same reason the walk is not in the CLI: a second implementation
//! of a normative grammar inside a binary is a second thing to keep in agreement
//! with the spec forever, and the copy under test would not be the copy an
//! operator runs. Any other reader — a CI gate, a library caller, some later
//! verb that also takes an anchor — now gets the same parse from the same code.
//!
//! **Why a module of its own rather than [`crate::load_signing_key`]'s.**
//! `keyfile.rs` owns the *signing* key: one private 32-byte seed, exactly one
//! line, no comments, and — on Unix, where there is a portable mode to check —
//! refused outright if any other account can read it. This module owns a list
//! of *public* keys an operator edits by hand and annotates.
//! The two formats differ deliberately and their security properties are
//! opposites — one is a secret that must never leave its owner, the other is
//! published in every `open` Line — so folding them into one parser would invite
//! one dialect's rules to leak into the other, in the direction where "be
//! lenient about comments" meets "this file is a private key".
//!
//! **Nothing here decides trust.** This module turns a file into keys. Whether
//! an empty result is still a *requested* anchor is the caller's orchestration
//! fact: "no anchor was asked for" and "I accept these zero keys" are different
//! claims about what the operator wanted, and only the caller knows which was
//! made (ADR-0004).

use std::path::{Path, PathBuf};

use botzr_aegis_core::PublicKey;
use thiserror::Error;

/// Read a trust store into the public keys it names, in source order.
///
/// Duplicates are kept and source order preserved: this reports what the file
/// says, and collapsing a repeat would mean deciding on the caller's behalf
/// which spelling of "the same key" wins. The one in-repo caller today only
/// searches the result with `contains`, so a repeat costs it nothing — but that
/// is a fact about that caller, not a promise this function may assume of the
/// next one.
///
/// Whole-line comments only. A trailing note after the hex on the same line
/// stays malformed: it would make the end of the hex field ambiguous for no
/// benefit an operator asked for, and the grammar in `spec/SPEC.md` does not
/// offer it.
pub fn load_trust_store(path: &Path) -> Result<Vec<PublicKey>, TrustStoreError> {
    let text = std::fs::read_to_string(path).map_err(|source| TrustStoreError::Read {
        path: path.to_path_buf(),
        source,
    })?;

    let mut keys = Vec::new();
    for (index, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        keys.push(
            PublicKey::from_hex(line).map_err(|source| TrustStoreError::MalformedEntry {
                path: path.to_path_buf(),
                // One-based, and counted over *every* line including the ones
                // that were skipped, so the number matches what the operator's
                // editor shows next to the offending text.
                line: index + 1,
                detail: source.to_string(),
            })?,
        );
    }
    Ok(keys)
}

/// A trust store that could not be turned into a list of public keys.
///
/// Its own enum rather than two more [`AuditError`](crate::AuditError)
/// variants: that type is about emitting and reading records, and a caller who
/// only wants to load a key list should not have to consider a torn chain tail
/// to handle a typo in a text file.
///
/// The two cases stay distinct because callers answer them differently — a
/// store nobody can read is not the same failure as a store that reads fine and
/// holds something that is not a key. What each one *costs* a process is not
/// decided here: this type names no exit code and writes to no stream.
#[derive(Debug, Error)]
pub enum TrustStoreError {
    /// The named file could not be read as text — missing, unreadable, a
    /// directory, or not UTF-8. No key list exists, so no claim about which
    /// keys it names is made.
    #[error("read trust store {}: {source}", path.display())]
    Read {
        path: PathBuf,
        source: std::io::Error,
    },

    /// A line that is neither blank nor a comment is not a public key. The line
    /// number is one-based.
    #[error("trust store {} line {line} is not a public key: {detail}", path.display())]
    MalformedEntry {
        path: PathBuf,
        line: usize,
        detail: String,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{insecure_dev_key, SigningKey};

    /// A valid entry: the wire form an `open` Line publishes. Taken from a real
    /// key rather than hand-written hex, so the fixture cannot drift from what
    /// [`PublicKey::from_hex`] actually accepts.
    fn key_hex() -> String {
        insecure_dev_key().public_key().to_hex()
    }

    /// A second, different valid entry — order is only observable between two
    /// keys that are not equal.
    fn other_key_hex() -> String {
        SigningKey::from_seed([0x2a; 32]).public_key().to_hex()
    }

    fn store(dir: &tempfile::TempDir, body: &str) -> PathBuf {
        let path = dir.path().join("trusted-keys.txt");
        std::fs::write(&path, body).expect("write trust store");
        path
    }

    #[test]
    fn comment_and_blank_lines_are_skipped_and_the_real_keys_survive() {
        // Operators keep notes next to their keys. A store that parsed only when
        // it was a bare list of hex would be a store nobody could annotate.
        let dir = tempfile::tempdir().unwrap();
        let path = store(
            &dir,
            &format!(
                "# keys this auditor accepts\n\
                 \n\
                 {}\n\
                 \n\
                 # rotation goes below this line\n",
                key_hex()
            ),
        );

        assert_eq!(
            load_trust_store(&path).expect("parse"),
            vec![insecure_dev_key().public_key()]
        );
    }

    #[test]
    fn a_trailing_note_on_a_key_line_is_malformed() {
        // Whole-line comments only: the hex field runs to the end of the line,
        // and widening that here would widen a grammar `spec/SPEC.md` fixes.
        //
        // The commented spelling is the load-bearing half. A parser that
        // truncated a key line at the first marker character would accept it and
        // pin to whatever hex happened to precede the marker — so the fixture
        // has to actually carry one. Asserting only the uncommented spelling
        // would leave that widening green.
        let dir = tempfile::tempdir().unwrap();
        for body in [
            format!("{} # rotated in on tuesday\n", key_hex()),
            format!("{} rotated in on tuesday\n", key_hex()),
        ] {
            let path = store(&dir, &body);

            let error = load_trust_store(&path).expect_err("a note after the hex is not a key");
            assert!(
                matches!(error, TrustStoreError::MalformedEntry { line: 1, .. }),
                "{body:?} -> {error:?}"
            );
        }
    }

    #[test]
    fn surrounding_whitespace_is_trimmed_before_a_line_is_classified() {
        // Hand-edited files carry stray indentation, and every classification
        // this module makes happens *after* the trim. Without it an indented
        // note stops looking like a comment, a line of spaces stops looking
        // blank, and a padded key stops parsing — all three are asserted here so
        // that dropping the trim fails a test rather than quietly narrowing the
        // set of files an operator can write.
        let dir = tempfile::tempdir().unwrap();
        let path = store(
            &dir,
            &format!(
                "   # an indented note is still a whole-line comment\n\
                 \t   \n\
                 \t{}  \n",
                key_hex()
            ),
        );

        assert_eq!(
            load_trust_store(&path).expect("parse"),
            vec![insecure_dev_key().public_key()]
        );
    }

    #[test]
    fn a_malformed_entry_reports_its_one_based_line_number() {
        // The bad line sits at line 3, past a comment and a blank, so an
        // off-by-one or a count that skipped the skipped lines both show up.
        let dir = tempfile::tempdir().unwrap();
        let path = store(&dir, "# an annotated store\n\ndeadbeef\n");

        let error = load_trust_store(&path).expect_err("`deadbeef` is not 64 hex characters");
        let TrustStoreError::MalformedEntry {
            path: reported,
            line,
            detail,
        } = &error
        else {
            panic!("expected a malformed entry, got {error:?}");
        };
        assert_eq!(*line, 3);
        assert_eq!(reported, &path);
        assert!(!detail.is_empty(), "the parse failure is reported verbatim");
    }

    #[test]
    fn a_store_that_cannot_be_read_reports_a_read_error() {
        // Distinct from a malformed entry: nothing was read, so nothing is being
        // claimed about the file's contents.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("no-such-store.txt");

        let error = load_trust_store(&path).expect_err("the file does not exist");
        assert!(matches!(error, TrustStoreError::Read { .. }), "{error:?}");
        assert!(error.to_string().contains("read trust store"), "{error}");
    }

    #[test]
    fn duplicate_keys_are_kept_in_source_order() {
        // Collapsing the repeat would mean choosing which spelling of the same
        // key wins; reordering would make the caller's "flag values first, then
        // store entries" a lie. The fixture is deliberately *not* a palindrome
        // — `[a, b, a]` reads the same reversed, so it cannot tell a
        // source-order parser from one that hands back its input backwards.
        let dir = tempfile::tempdir().unwrap();
        let path = store(
            &dir,
            &format!("{}\n{}\n{}\n", key_hex(), other_key_hex(), other_key_hex()),
        );

        let first = insecure_dev_key().public_key();
        let second = SigningKey::from_seed([0x2a; 32]).public_key();
        assert_eq!(
            load_trust_store(&path).expect("parse"),
            vec![first, second, second]
        );
    }

    #[test]
    fn an_empty_file_parses_to_no_keys() {
        // An empty store is not an error here: it is a file that names zero
        // keys. Whether that still counts as a requested anchor — and therefore
        // fails the pin rather than going unpinned — is the CLI's call, not this
        // function's.
        let dir = tempfile::tempdir().unwrap();
        let path = store(&dir, "");

        assert_eq!(
            load_trust_store(&path).expect("parse"),
            Vec::<PublicKey>::new()
        );
    }
}
