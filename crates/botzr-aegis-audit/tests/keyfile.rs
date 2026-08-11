//! The signing key's lifecycle on disk (AILAB-620): generate, load, and the
//! four ways a load must fail closed.
//!
//! Wrong-key / mutated-signature / stripped-signature verdicts live in
//! `verdict.rs` and are deliberately not cloned here — this file is about the
//! *file*, not about what a verifier makes of the records it signs.

use std::fs;
use std::path::Path;

use botzr_aegis_audit::{
    generate_signing_key, insecure_dev_key, load_signing_key, verify_line, AuditError, AuditWriter,
};

fn write_key_text(path: &Path, text: &str) {
    fs::write(path, text).expect("write key fixture");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).expect("chmod 600");
    }
}

#[test]
fn generate_then_load_yields_the_same_key() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("aegis-signing.key");

    let generated = generate_signing_key(&path, false).expect("generate");
    let loaded = load_signing_key(&path).expect("load");

    // Both identities have to survive the round trip: `public_key` is what the
    // `open` line publishes and what `aegis verify --key` pins, `key_id` is
    // what every signed line carries.
    assert_eq!(generated.public_key(), loaded.public_key());
    assert_eq!(generated.key_id(), loaded.key_id());
}

#[test]
fn a_generated_key_is_not_the_dev_key() {
    // The whole point of the ticket: a persistent sink must not be signed with
    // the seed compiled into the crate.
    let dir = tempfile::tempdir().unwrap();
    let key = generate_signing_key(&dir.path().join("k"), false).expect("generate");
    assert_ne!(key.public_key(), insecure_dev_key().public_key());
    assert_ne!(key.key_id(), insecure_dev_key().key_id());
}

#[test]
fn a_loaded_key_signs_records_that_verify_under_its_published_public_key() {
    // End to end for the file: the key that came off disk is the key the
    // Session publishes, and the lines it signs verify against it.
    let dir = tempfile::tempdir().unwrap();
    let key_path = dir.path().join("signing.key");
    let generated = generate_signing_key(&key_path, false).expect("generate");

    let chain = dir.path().join("session.jsonl");
    let writer = AuditWriter::open(&chain, load_signing_key(&key_path).expect("load"))
        .expect("open session");
    assert_eq!(writer.public_key(), generated.public_key());
    drop(writer);

    let text = fs::read_to_string(&chain).expect("chain readable");
    let open_line: botzr_aegis_core::AuditOpen = serde_json::from_str(
        text.lines()
            .next()
            .expect("the session emitted an open line"),
    )
    .expect("open line parses");
    assert_eq!(open_line.public_key, generated.public_key());
    assert_eq!(verify_line(&open_line, &generated.public_key()), Ok(()));
}

#[test]
fn a_missing_key_is_its_own_error_and_names_the_path() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("nope.key");

    let err = load_signing_key(&path).expect_err("a missing key must fail closed");
    assert!(
        matches!(&err, AuditError::KeyFileMissing { path: p } if *p == path),
        "{err:?}"
    );
    assert!(err.to_string().contains("nope.key"), "{err}");
}

#[test]
fn corrupt_key_files_fail_closed() {
    let dir = tempfile::tempdir().unwrap();
    let valid = "0".repeat(64);

    // Every case here is a file an operator could plausibly produce: a truncated
    // copy/paste, an uppercase hex dump, an empty file from a failed write, a
    // key with something else appended.
    for (label, body) in [
        ("truncated", "abc123".to_string()),
        ("uppercase", "A".repeat(64)),
        ("empty", String::new()),
        ("non-hex", "z".repeat(64)),
        ("too long", format!("{valid}00")),
        ("leading space", format!(" {}", &valid[1..])),
        ("second line", format!("{valid}\nextra\n")),
    ] {
        let path = dir.path().join("corrupt.key");
        write_key_text(&path, &body);
        assert!(
            load_signing_key(&path).is_err(),
            "{label}: expected a load failure, got a usable key"
        );
    }
}

#[test]
fn a_corrupt_key_reports_malformed_rather_than_io() {
    // The distinction is load-bearing for the operator: "this file is not a key"
    // and "I could not read this file" have different fixes.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("corrupt.key");
    write_key_text(&path, "abc123\n");

    let err = load_signing_key(&path).expect_err("truncated key must fail");
    assert!(
        matches!(err, AuditError::KeyFileMalformed { .. }),
        "{err:?}"
    );
}

#[test]
fn a_trailing_newline_is_optional() {
    let dir = tempfile::tempdir().unwrap();
    let bare = dir.path().join("bare.key");
    let terminated = dir.path().join("terminated.key");
    let seed = "11".repeat(32);

    write_key_text(&bare, &seed);
    write_key_text(&terminated, &format!("{seed}\n"));

    let a = load_signing_key(&bare).expect("bare seed loads");
    let b = load_signing_key(&terminated).expect("newline-terminated seed loads");
    assert_eq!(a.public_key(), b.public_key());
}

#[cfg(unix)]
#[test]
fn a_world_readable_key_is_refused() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("loose.key");
    generate_signing_key(&path, false).expect("generate");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).expect("chmod 644");

    let err = load_signing_key(&path).expect_err("0644 key must be refused");
    assert!(
        matches!(err, AuditError::KeyFilePermissions { mode: 0o644, .. }),
        "{err:?}"
    );
    assert!(err.to_string().contains("loose.key"), "{err}");

    // Group-only access is refused on the same rule — the question is whether
    // anyone but the owner has access at all, not whether it is world-wide.
    fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).expect("chmod 640");
    assert!(
        matches!(
            load_signing_key(&path),
            Err(AuditError::KeyFilePermissions { mode: 0o640, .. })
        ),
        "0640 must be refused too"
    );

    // And 0600 loads, so the check is not simply rejecting everything.
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("chmod 600");
    load_signing_key(&path).expect("0600 key loads");
}

#[cfg(unix)]
#[test]
fn generate_creates_the_file_owner_only() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("nested/deeper/signing.key");
    generate_signing_key(&path, false).expect("generate creates parent dirs");

    let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "generated key mode was {mode:04o}");
}

#[test]
fn generate_refuses_to_overwrite_without_force() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("signing.key");

    let first = generate_signing_key(&path, false).expect("first generate");
    let err = generate_signing_key(&path, false).expect_err("second generate must refuse");
    assert!(
        matches!(&err, AuditError::KeyFileExists { path: p } if *p == path),
        "{err:?}"
    );

    // The refusal left the original key untouched — otherwise the error would be
    // cosmetic and the pin would already be broken.
    assert_eq!(
        load_signing_key(&path)
            .expect("original still loads")
            .public_key(),
        first.public_key()
    );

    let forced = generate_signing_key(&path, true).expect("force overwrites");
    assert_ne!(forced.public_key(), first.public_key());
}

#[cfg(unix)]
#[test]
fn force_tightens_the_mode_of_an_existing_loose_file() {
    // `OpenOptions::mode` only applies to a file the call creates, so a forced
    // overwrite of a 0644 key would otherwise stay 0644 and be refused by the
    // next load — a generate that produces an unloadable key.
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("loose.key");
    write_key_text(&path, &"22".repeat(32));
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).expect("chmod 644");

    generate_signing_key(&path, true).expect("force generate");
    let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "forced key mode was {mode:04o}");
    load_signing_key(&path).expect("forced key loads");
}
