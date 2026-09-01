#![no_main]
use botzr_aegis_core::{canonical_digest, to_canonical_json};
use libfuzzer_sys::fuzz_target;
use serde_json::Value;

fuzz_target!(|data: &[u8]| {
    // Cap pathological inputs so CI smoke stays bounded — the same 64 KiB the
    // policy_yaml target uses.
    if data.len() > 64 * 1024 {
        return;
    }

    // A parse failure is a return, not a finding. The surface under test is the
    // canonicalizer; serde_json's parser is upstream of it, and every
    // attacker-reachable call site parses before it canonicalizes. Parsing
    // first also inherits serde_json's recursion limit, which is why this
    // target needs no depth guard of its own.
    let Ok(value) = serde_json::from_slice::<Value>(data) else {
        return;
    };

    // An `Err` is the value space refusing, not a crash. Floats, negative
    // integers, integers at or above 2^53 and explicit nulls are all outside
    // the space, and arbitrary JSON produces them constantly — treating that as
    // a finding would fail within seconds on correct behaviour. Same rule as
    // `Err(PolicyError)` in the policy_yaml target.
    let Ok(canonical) = to_canonical_json(&value) else {
        return;
    };

    // Anything that canonicalizes must also digest. `canonical_digest` is the
    // function the audit crate actually calls, so a disagreement between the
    // two — or any non-determinism across the second call — would move every
    // hash in the Chain while the canonical form still looked right.
    canonical_digest(&value).expect("a value that canonicalizes must also digest");

    // THE PROPERTY. The canonical form must be JSON, and it must be the *same*
    // JSON. A canonical form that reparses to a different value is a silent
    // corruption of what a third-party verifier will hash — the failure mode
    // that surfaces only as an unexplainable hash mismatch. Member order is
    // irrelevant here: `serde_json::Map` equality compares contents.
    let reparsed: Value =
        serde_json::from_str(&canonical).expect("the canonical form must be parseable JSON");
    assert_eq!(reparsed, value, "the canonical form must preserve the value");
});
