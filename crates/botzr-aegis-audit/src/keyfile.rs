//! Where the signing key lives: a seed file on disk (AILAB-620).
//!
//! `signing.rs` is the primitive — it signs with a key it is handed. This module
//! is the lifecycle around it: one file, one explicit generate step, and a load
//! that fails closed. Every persistent audit sink gets its key from here, so
//! [`crate::insecure_dev_key`] can never sign a file an operator will later pin
//! a `Verified (pinned)` label to.
//!
//! **On-disk format.** One line: 64 lowercase hex characters, optional trailing
//! newline. That is the 32-byte ed25519 seed, in the same hex dialect as
//! [`botzr_aegis_core::PublicKey`]. No PEM, no PKCS#8, no JSON, no comments —
//! one dialect for one 32-byte value is the whole point of ADR-0003's canonical
//! rule applied to a key.
//!
//! **Permissions.** On Unix a key readable by group or others is refused, and a
//! generated key is created `0o600`. On other platforms the mode check is
//! skipped: there is no portable equivalent, and inventing an ACL check here
//! would make a claim this code cannot keep.
//!
//! **Generation is never implicit.** Nothing on the emit path generates a key.
//! A missing key is a loud failure, because silently minting one would publish a
//! brand-new public key in the `Open` line and quietly break every pin the
//! operator had against the old one.
//!
//! **Rotation** is already specified — `spec/SPEC.md` §8.4: a new `key_id` is
//! legal only on a Session `open` that publishes the matching public key, and a
//! `key_id` change mid-Session is `Tampered`. In terms of this file: rotating
//! means generating a *new* seed file and starting a *new* process, since one
//! `AuditWriter` is one Session and holds one key for its lifetime.
//!
//! The seed is not zeroized after use: `ed25519-dalek` is pinned
//! `default-features = false, features = ["fast"]` and pulling `zeroize` in is
//! out of this ticket's scope. The seed lives as long as the `SigningKey` does.

use std::fs;
use std::io::Write;
use std::path::Path;

use crate::error::AuditError;
use crate::signing::SigningKey;

/// The seed as it appears on disk: 32 bytes, two hex characters each.
const SEED_HEX_LEN: usize = 64;

/// Read a signing key from `path`, or fail.
///
/// There is no fallback. Not to [`crate::insecure_dev_key`], not to an
/// unsigned writer, not to a freshly generated key — a caller that cannot
/// produce the key it was configured with must not emit records at all.
pub fn load_signing_key(path: &Path) -> Result<SigningKey, AuditError> {
    // Metadata before contents: a key whose mode is wrong is refused without
    // its bytes ever being read into this process.
    let metadata = fs::metadata(path).map_err(|source| {
        if source.kind() == std::io::ErrorKind::NotFound {
            AuditError::KeyFileMissing {
                path: path.to_path_buf(),
            }
        } else {
            AuditError::KeyFileIo {
                path: path.to_path_buf(),
                source,
            }
        }
    })?;
    refuse_readable_beyond_owner(path, &metadata)?;

    let text = fs::read_to_string(path).map_err(|source| AuditError::KeyFileIo {
        path: path.to_path_buf(),
        source,
    })?;
    Ok(SigningKey::from_seed(parse_seed_hex(path, &text)?))
}

/// Generate a fresh key, write it to `path`, and return it.
///
/// `force` is the only way to write over an existing key: a key file replaced
/// by accident takes every signature made under the old key with it, and the
/// records that carry them can no longer be pinned to anything.
///
/// The caller gets the key back so it can print the `public_key` an operator
/// will pass to `aegis verify --key`.
pub fn generate_signing_key(path: &Path, force: bool) -> Result<SigningKey, AuditError> {
    if !force && path.exists() {
        return Err(AuditError::KeyFileExists {
            path: path.to_path_buf(),
        });
    }

    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent).map_err(|source| AuditError::KeyFileIo {
                path: path.to_path_buf(),
                source,
            })?;
        }
    }

    let mut seed = [0u8; 32];
    // `getrandom::fill` is the OS CSPRNG (getrandom 0.3 renamed 0.2's
    // `getrandom` to `fill`; see getrandom-0.3.4/src/lib.rs:66). Filling the
    // seed directly avoids flipping `ed25519-dalek` off its
    // `default-features = false, features = ["fast"]` pin to pull `rand`.
    getrandom::fill(&mut seed).map_err(|e| AuditError::Entropy {
        detail: e.to_string(),
    })?;

    write_owner_only(path, &hex_of_seed(&seed))?;
    Ok(SigningKey::from_seed(seed))
}

/// Create/truncate `path` as owner-only, write the seed, and fsync it.
///
/// The mode is set at `open` time *and* again after opening: `OpenOptions::mode`
/// applies only to a file this call creates, so a `--force` overwrite of an
/// existing `0o644` key would otherwise keep the loose mode and be refused by
/// the very next [`load_signing_key`].
fn write_owner_only(path: &Path, hex: &str) -> Result<(), AuditError> {
    let io = |source: std::io::Error| AuditError::KeyFileIo {
        path: path.to_path_buf(),
        source,
    };

    let mut options = fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path).map_err(io)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).map_err(io)?;
    }

    // Trailing newline so the file is a well-formed text line; `load` accepts
    // it either way.
    file.write_all(hex.as_bytes()).map_err(io)?;
    file.write_all(b"\n").map_err(io)?;
    // Same G3 durability rule the writer follows: a key that is only in the
    // page cache can be lost while records signed by it are already on disk.
    file.sync_all().map_err(io)?;
    Ok(())
}

/// Refuse a key any account other than its owner can read.
///
/// `0o077` covers group *and* other, read/write/execute alike — the question is
/// not "can they write it" but "does anyone else have any access to it at all".
#[cfg(unix)]
fn refuse_readable_beyond_owner(path: &Path, metadata: &fs::Metadata) -> Result<(), AuditError> {
    use std::os::unix::fs::MetadataExt;
    let mode = metadata.mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(AuditError::KeyFilePermissions {
            path: path.to_path_buf(),
            mode,
        });
    }
    Ok(())
}

/// Non-Unix: no portable mode to check. Documented rather than approximated.
#[cfg(not(unix))]
fn refuse_readable_beyond_owner(_path: &Path, _metadata: &fs::Metadata) -> Result<(), AuditError> {
    Ok(())
}

/// Parse the documented dialect and nothing else.
///
/// Uppercase hex is rejected rather than accepted-and-normalized: `PublicKey`
/// and `KeyId` are lowercase-only on the wire, and a key file that accepts a
/// second spelling is a second dialect to keep in agreement forever.
fn parse_seed_hex(path: &Path, text: &str) -> Result<[u8; 32], AuditError> {
    let malformed = |reason: String| AuditError::KeyFileMalformed {
        path: path.to_path_buf(),
        reason,
    };

    let body = text.strip_suffix('\n').unwrap_or(text);
    let body = body.strip_suffix('\r').unwrap_or(body);

    if body.len() != SEED_HEX_LEN {
        return Err(malformed(format!(
            "expected {SEED_HEX_LEN} characters, found {}",
            body.len()
        )));
    }
    if let Some(bad) = body
        .chars()
        .find(|c| !c.is_ascii_hexdigit() || c.is_ascii_uppercase())
    {
        return Err(malformed(format!("expected lowercase hex, found {bad:?}")));
    }

    let mut seed = [0u8; 32];
    for (byte, pair) in seed.iter_mut().zip(body.as_bytes().chunks(2)) {
        let pair = std::str::from_utf8(pair).map_err(|e| malformed(e.to_string()))?;
        *byte = u8::from_str_radix(pair, 16).map_err(|e| malformed(e.to_string()))?;
    }
    Ok(seed)
}

fn hex_of_seed(seed: &[u8; 32]) -> String {
    let mut out = String::with_capacity(SEED_HEX_LEN);
    for byte in seed {
        use std::fmt::Write as _;
        // `write!` to a String cannot fail; the result is discarded rather than
        // unwrapped so a formatting error can never panic a key generation.
        let _ = write!(out, "{byte:02x}");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_generated_seed_is_64_lowercase_hex_characters() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("key.hex");
        generate_signing_key(&path, false).expect("generate");

        let text = fs::read_to_string(&path).unwrap();
        let body = text.strip_suffix('\n').expect("trailing newline");
        assert_eq!(body.len(), SEED_HEX_LEN, "{body:?}");
        assert!(
            body.chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
            "{body:?}"
        );
    }

    #[test]
    fn two_generated_keys_differ() {
        // A generate that returned a fixed key would be `insecure_dev_key` with
        // extra steps, and every host would sign with the same secret.
        let dir = tempfile::tempdir().unwrap();
        let a = generate_signing_key(&dir.path().join("a"), false).unwrap();
        let b = generate_signing_key(&dir.path().join("b"), false).unwrap();
        assert_ne!(a.public_key(), b.public_key());
    }

    /// The dialect the doc comment on [`parse_seed_hex`] promises, asserted
    /// rather than described (AILAB-712).
    ///
    /// Uppercase hex is the interesting half: it is a *valid* 64-character
    /// encoding of a real seed, and accepting it would cost nothing today. It is
    /// refused because `PublicKey` and `KeyId` are lowercase-only on the wire, so
    /// a key file with a second accepted spelling is a second dialect that has to
    /// stay in agreement with the first forever. Nothing was holding that.
    #[test]
    fn a_key_file_is_rejected_unless_it_is_lowercase_hex() {
        let dir = tempfile::tempdir().unwrap();

        let cases = [
            ("uppercase", "A".repeat(SEED_HEX_LEN)),
            (
                "mixed case",
                format!("{}{}", "a".repeat(SEED_HEX_LEN - 1), "B"),
            ),
            ("non-hex", "z".repeat(SEED_HEX_LEN)),
            ("hex-adjacent punctuation", "-".repeat(SEED_HEX_LEN)),
        ];

        for (label, body) in cases {
            let path = dir.path().join(label.replace(' ', "-"));
            write_owner_only(&path, &body).expect("write fixture");
            let err = load_signing_key(&path).expect_err(label);
            assert!(
                matches!(err, AuditError::KeyFileMalformed { .. }),
                "{label}: expected KeyFileMalformed, got {err:?}"
            );
            assert!(
                err.to_string().contains("lowercase hex"),
                "{label}: the reason names the dialect: {err}"
            );
        }
    }

    /// A wrong-length body is refused by length before the character check, so
    /// the operator is told which of the two rules they broke.
    #[test]
    fn a_key_file_of_the_wrong_length_says_so_rather_than_naming_the_alphabet() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("short");
        write_owner_only(&path, &"ab".repeat(8)).expect("write fixture");

        let err = load_signing_key(&path).expect_err("a 16-character key is not a seed");
        let message = err.to_string();
        assert!(
            message.contains(&format!("expected {SEED_HEX_LEN} characters, found 16")),
            "the reason gives both the expected and the actual length: {message}"
        );
        // Not the alphabet complaint. The outer `KeyFileMalformed` Display
        // says "lowercase hex seed" for every reason, so the phrase that
        // actually distinguishes the two checks is the one to assert on.
        assert!(
            !message.contains("expected lowercase hex"),
            "length is reported before the alphabet check: {message}"
        );
    }

    /// `keygen --out` into a path whose parent does not exist yet creates it.
    ///
    /// An operator pointing at `~/.aegis/keys/signing.key` on a fresh machine is
    /// the ordinary case, and it was untested — `generate_signing_key`'s
    /// `create_dir_all` branch had no coverage at all (AILAB-712).
    #[test]
    fn generating_a_key_creates_the_directories_leading_to_it() {
        let dir = tempfile::tempdir().unwrap();
        let nested = dir.path().join("a").join("b").join("c").join("signing.key");

        let generated = generate_signing_key(&nested, false).expect("generate into a new tree");

        assert!(nested.exists(), "{}", nested.display());
        // Round-trips: what was written back is the key that was returned, so
        // the directory creation did not change the file that lands.
        let loaded = load_signing_key(&nested).expect("load what was just written");
        assert_eq!(generated.public_key(), loaded.public_key());
    }

    /// Without `force`, an existing key is never written over.
    ///
    /// Replacing a key silently takes every signature made under the old one
    /// with it: the records that carry them can no longer be pinned to anything.
    #[test]
    fn generating_over_an_existing_key_is_refused_unless_forced() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("signing.key");
        let first = generate_signing_key(&path, false).expect("first generate");

        let err = generate_signing_key(&path, false).expect_err("the second must refuse");
        assert!(
            matches!(err, AuditError::KeyFileExists { .. }),
            "got {err:?}"
        );
        assert_eq!(
            load_signing_key(&path).unwrap().public_key(),
            first.public_key(),
            "a refused generate must not have touched the file"
        );

        // `force` is the documented way through, and the replacement is a
        // different key — not the same bytes rewritten.
        let forced = generate_signing_key(&path, true).expect("force replaces");
        assert_ne!(forced.public_key(), first.public_key());
    }
}
