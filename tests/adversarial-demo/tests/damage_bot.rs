//! AEG-22 adversarial demo — real wasip2 guest through `Runtime::execute_tool_call`.
//!
//! Closes the three guest-level acceptance criteria carried from AEG-8:
//!   * `fs.write` under a read-only grant → trap/deny, never success
//!   * path outside preopen (`..`, symlink) → deny (cap-std containment)
//!   * Model B `http` import through the orchestrator → grant gate + audit

use std::path::Path;

use botzr_aegis_audit::to_json_line;
use botzr_aegis_capability::{
    FsNeeds, HttpNeed, NetNeeds, PathNeed, ToolInfo, ToolKind, ToolManifest,
};
use botzr_aegis_core::{
    AegisError, AuditRecord, CapabilityOutcome, ExecutionOutcome, PolicyOutcome, ToolId,
};
use botzr_aegis_runtime::Runtime;

const DAMAGE_BOT_WASM: &[u8] = include_bytes!("../../fixtures/damage-bot/damage-bot.wasm");

fn damage_bot_info() -> ToolInfo {
    ToolInfo {
        id: ToolId::new("damage-bot"),
        version: "0.1.0".into(),
        kind: ToolKind::Wasm,
    }
}

fn register_damage_bot(rt: &mut Runtime, manifest: ToolManifest) {
    rt.register(manifest, DAMAGE_BOT_WASM.to_vec())
        .expect("damage-bot registers");
}

fn attack_input(mode: &str) -> Vec<u8> {
    format!(r#"{{"attack":"{mode}"}}"#).into_bytes()
}

/// Read audit JSONL and return the outcome record.
fn outcome(rt: &Runtime) -> AuditRecord {
    let lines: Vec<String> = std::fs::read_to_string(rt.audit().path())
        .expect("audit readable")
        .lines()
        .map(str::to_owned)
        .collect();
    // Schema v2: the Session `Open` line is the file's first line, so the call's
    // intent and outcome sit at 1 and 2.
    assert_eq!(lines.len(), 3, "open + intent + outcome");
    assert!(lines[0].contains("\"line_type\":\"open\""));
    assert!(lines[1].contains("\"line_type\":\"intent\""));
    serde_json::from_str(&lines[2]).expect("outcome parses")
}

fn assert_refused_with_trap(record: &AuditRecord, needle: &str) {
    assert!(matches!(record.policy, PolicyOutcome::Allowed));
    assert!(matches!(
        record.capability,
        CapabilityOutcome::Granted { .. }
    ));
    match &record.execution {
        ExecutionOutcome::Trap { message } => {
            assert!(
                message.contains(needle),
                "expected trap containing {needle:?}, got {message}"
            );
        }
        other => panic!("expected trap, got {other:?}"),
    }
}

// ---- filesystem containment (Model A / WASI preopens) -----------------------

#[test]
fn guest_write_under_readonly_grant_is_refused() {
    let sandbox = tempfile::tempdir().unwrap();
    std::fs::write(sandbox.path().join("seed.txt"), b"safe").unwrap();

    let manifest = ToolManifest::new(damage_bot_info(), sandbox.path()).with_fs(FsNeeds {
        read: vec![PathNeed::new(".")],
        write: vec![],
    });

    let mut rt = Runtime::new();
    register_damage_bot(&mut rt, manifest);

    let input = attack_input("write_readonly");
    let err = rt
        .execute_tool_call(ToolId::new("damage-bot"), &input)
        .expect_err("write to ro preopen must fail");
    assert!(
        matches!(err, AegisError::Trap { .. }),
        "expected Trap, got {err:?}"
    );

    let record = outcome(&rt);
    assert_refused_with_trap(&record, "fs_write_denied");
    assert!(to_json_line(&record)
        .unwrap()
        .contains("\"status\":\"trap\""));
}

#[test]
fn guest_dotdot_escape_is_refused() {
    let sandbox = tempfile::tempdir().unwrap();
    std::fs::write(sandbox.path().join("seed.txt"), b"safe").unwrap();

    let manifest = ToolManifest::new(damage_bot_info(), sandbox.path()).with_fs(FsNeeds {
        read: vec![PathNeed::new(".")],
        write: vec![],
    });

    let mut rt = Runtime::new();
    register_damage_bot(&mut rt, manifest);

    let input = attack_input("dotdot_escape");
    let err = rt
        .execute_tool_call(ToolId::new("damage-bot"), &input)
        .expect_err("dotdot escape must fail");
    assert!(
        matches!(err, AegisError::Trap { .. }),
        "expected Trap, got {err:?}"
    );

    let record = outcome(&rt);
    assert_refused_with_trap(&record, "fs_escape_denied");
}

#[test]
fn guest_symlink_escape_is_refused() {
    let sandbox = tempfile::tempdir().unwrap();
    std::fs::write(sandbox.path().join("seed.txt"), b"safe").unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink("/etc/passwd", sandbox.path().join("escape")).unwrap();
    #[cfg(not(unix))]
    {
        eprintln!("skipping symlink_escape on non-unix");
        return;
    }

    let manifest = ToolManifest::new(damage_bot_info(), sandbox.path()).with_fs(FsNeeds {
        read: vec![PathNeed::new(".")],
        write: vec![],
    });

    let mut rt = Runtime::new();
    register_damage_bot(&mut rt, manifest);

    let input = attack_input("symlink_escape");
    let err = rt
        .execute_tool_call(ToolId::new("damage-bot"), &input)
        .expect_err("symlink escape must fail");
    assert!(
        matches!(err, AegisError::Trap { .. }),
        "expected Trap, got {err:?}"
    );

    let record = outcome(&rt);
    assert_refused_with_trap(&record, "symlink_denied");
}

// ---- Model B http import through orchestrator --------------------------------

#[test]
fn guest_http_without_net_grant_is_refused() {
    let base = Path::new(env!("CARGO_MANIFEST_DIR")).join("../fixtures/damage-bot");
    let manifest = ToolManifest::new(damage_bot_info(), &base);

    let mut rt = Runtime::new();
    register_damage_bot(&mut rt, manifest);

    let input = attack_input("http_exfil");
    let err = rt
        .execute_tool_call(ToolId::new("damage-bot"), &input)
        .expect_err("http without net grant must fail");
    assert!(
        matches!(err, AegisError::Trap { .. }),
        "expected Trap, got {err:?}"
    );

    let record = outcome(&rt);
    assert_refused_with_trap(&record, "no net grant");
}

#[test]
fn guest_http_to_disallowed_host_is_refused() {
    let base = Path::new(env!("CARGO_MANIFEST_DIR")).join("../fixtures/damage-bot");
    let manifest = ToolManifest::new(damage_bot_info(), &base).with_net(NetNeeds {
        http: vec![HttpNeed::get("api.example.com")],
    });

    let mut rt = Runtime::new();
    register_damage_bot(&mut rt, manifest);

    let input = attack_input("http_exfil");
    let err = rt
        .execute_tool_call(ToolId::new("damage-bot"), &input)
        .expect_err("http to evil host must fail");
    assert!(
        matches!(err, AegisError::Trap { .. }),
        "expected Trap, got {err:?}"
    );

    let record = outcome(&rt);
    assert_refused_with_trap(&record, "not in grant");
}

#[test]
fn guest_http_to_allowed_host_passes_grant_then_stubs() {
    let base = Path::new(env!("CARGO_MANIFEST_DIR")).join("../fixtures/damage-bot");
    let manifest = ToolManifest::new(damage_bot_info(), &base).with_net(NetNeeds {
        http: vec![HttpNeed::get("api.example.com")],
    });

    let mut rt = Runtime::new();
    register_damage_bot(&mut rt, manifest);

    let input = attack_input("http_allowed");
    let err = rt
        .execute_tool_call(ToolId::new("damage-bot"), &input)
        .expect_err("v1 http stub still denies the effect");
    assert!(
        matches!(err, AegisError::Trap { .. }),
        "expected Trap, got {err:?}"
    );

    let record = outcome(&rt);
    assert!(matches!(record.policy, PolicyOutcome::Allowed));
    assert!(matches!(
        record.capability,
        CapabilityOutcome::Granted { .. }
    ));
    assert_refused_with_trap(&record, "no network in v1 slice");
}
