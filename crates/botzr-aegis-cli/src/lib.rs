//! `aegis` CLI library — argument parsing and `run` pipeline wiring.

mod verify;

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use botzr_aegis_capability::{ToolInfo, ToolKind, ToolManifest};
use botzr_aegis_core::{AegisError, PublicKey, RequestDigest, ToolId};
use botzr_aegis_runtime::{Runtime, RuntimeBuilder};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    /// Print ready banner (legacy / default when no subcommand).
    Ready {
        policy: Option<PathBuf>,
        audit: Option<PathBuf>,
    },
    /// Register a WASM component and execute one call through the pipeline.
    Run(RunArgs),
    /// Verify a Chain file and report its verdict (ADR-0002 / ADR-0004).
    ///
    /// `keys` are `--key` values; `trust_store` is a file of the same. Their
    /// union is the trust slice, and supplying *neither* is an *unpinned* walk —
    /// a store that yields no keys is still a pin, and fails. The store is
    /// deliberately not read here — parsing arguments must not touch the
    /// filesystem, and an unreadable store is exit 2 while a bad `--key` is
    /// exit 1.
    Verify {
        path: PathBuf,
        keys: Vec<PublicKey>,
        trust_store: Option<PathBuf>,
    },
    Help,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunArgs {
    pub policy: Option<PathBuf>,
    pub audit: Option<PathBuf>,
    pub component: PathBuf,
    pub id: String,
    pub input: Option<String>,
    pub input_file: Option<PathBuf>,
    pub base_dir: Option<PathBuf>,
    pub sha256: Option<String>,
    pub version: String,
}

pub fn parse_args(args: &[String]) -> Result<Command, String> {
    if args.len() <= 1 {
        return Ok(Command::Ready {
            policy: None,
            audit: None,
        });
    }

    match args[1].as_str() {
        "--help" | "-h" | "help" => Ok(Command::Help),
        "run" => match parse_run(&args[2..]) {
            Ok(run) => Ok(Command::Run(run)),
            Err(e) if e == "__help_run__" => Ok(Command::Help),
            Err(e) => Err(e),
        },
        "verify" => match parse_verify(&args[2..]) {
            Ok(cmd) => Ok(cmd),
            Err(e) if e == "__help_verify__" => Ok(Command::Help),
            Err(e) => Err(e),
        },
        other if other.starts_with('-') => {
            // Global flags only → ready mode (backward compatible stub).
            match parse_global_flags(&args[1..]) {
                Ok((policy, audit)) => Ok(Command::Ready { policy, audit }),
                Err(e) if e == "__help__" => Ok(Command::Help),
                Err(e) => Err(e),
            }
        }
        other => Err(format!("unknown command: {other}\n{}", usage_text())),
    }
}

fn parse_global_flags(args: &[String]) -> Result<(Option<PathBuf>, Option<PathBuf>), String> {
    let mut policy = None;
    let mut audit = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--policy" => {
                i += 1;
                let v = args.get(i).ok_or("--policy needs a value")?;
                policy = Some(PathBuf::from(v));
            }
            "--audit" => {
                i += 1;
                let v = args.get(i).ok_or("--audit needs a value")?;
                audit = Some(PathBuf::from(v));
            }
            "--help" | "-h" => return Err("__help__".into()),
            other => return Err(format!("unknown flag: {other}")),
        }
        i += 1;
    }
    Ok((policy, audit))
}

fn parse_run(args: &[String]) -> Result<RunArgs, String> {
    let mut policy = None;
    let mut audit = None;
    let mut component = None;
    let mut id = None;
    let mut input = None;
    let mut input_file = None;
    let mut base_dir = None;
    let mut sha256 = None;
    let mut version = "0.1.0".to_string();

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--policy" => {
                i += 1;
                let v = args.get(i).ok_or("--policy needs a value")?;
                policy = Some(PathBuf::from(v));
            }
            "--audit" => {
                i += 1;
                let v = args.get(i).ok_or("--audit needs a value")?;
                audit = Some(PathBuf::from(v));
            }
            "--component" | "--wasm" => {
                i += 1;
                let v = args.get(i).ok_or("--component needs a value")?;
                component = Some(PathBuf::from(v));
            }
            "--id" | "--tool-id" => {
                i += 1;
                let v = args.get(i).ok_or("--id needs a value")?;
                id = Some(v.clone());
            }
            "--input" => {
                i += 1;
                let v = args.get(i).ok_or("--input needs a value")?;
                input = Some(v.clone());
            }
            "--input-file" => {
                i += 1;
                let v = args.get(i).ok_or("--input-file needs a value")?;
                input_file = Some(PathBuf::from(v));
            }
            "--base-dir" => {
                i += 1;
                let v = args.get(i).ok_or("--base-dir needs a value")?;
                base_dir = Some(PathBuf::from(v));
            }
            "--sha256" => {
                i += 1;
                let v = args.get(i).ok_or("--sha256 needs a value")?;
                sha256 = Some(v.clone());
            }
            "--version" => {
                i += 1;
                let v = args.get(i).ok_or("--version needs a value")?;
                version = v.clone();
            }
            "--help" | "-h" => return Err("__help_run__".into()),
            other => return Err(format!("unknown flag: {other}")),
        }
        i += 1;
    }

    if input.is_some() && input_file.is_some() {
        return Err("use only one of --input or --input-file".into());
    }

    Ok(RunArgs {
        policy,
        audit,
        component: component.ok_or("run requires --component <PATH>")?,
        id: id.ok_or("run requires --id <TOOL_ID>")?,
        input,
        input_file,
        base_dir,
        sha256,
        version,
    })
}

/// Parse `aegis verify [--key <HEX>]... [--trust-store <PATH>] <PATH>`.
///
/// Every error here is a usage error, which `main.rs` already maps to exit 1.
/// That includes bad hex: a key the operator mistyped is not evidence about the
/// file, so it must not be reported as a verdict about it.
fn parse_verify(args: &[String]) -> Result<Command, String> {
    let mut keys = Vec::new();
    let mut trust_store = None;
    let mut path: Option<PathBuf> = None;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--key" => {
                i += 1;
                let v = args.get(i).ok_or("--key needs a value")?;
                // LOAD-BEARING: `--key` takes the `public_key` an `open` line
                // publishes — 64 lowercase hex — and *not* the `key_id`
                // fingerprint the report prints. Pinning compares published
                // keys; accepting a fingerprint here would silently compare two
                // different things and pin nothing.
                let key = PublicKey::from_hex(v)
                    .map_err(|e| format!("--key needs a 64-hex public key: {e}"))?;
                keys.push(key);
            }
            "--trust-store" => {
                i += 1;
                let v = args.get(i).ok_or("--trust-store needs a value")?;
                trust_store = Some(PathBuf::from(v));
            }
            "--help" | "-h" => return Err("__help_verify__".into()),
            other if other.starts_with('-') => return Err(format!("unknown flag: {other}")),
            other => {
                // One Chain file per invocation. Two positionals is more likely
                // a forgotten flag value than a request to verify both, and
                // guessing would fold two verdicts into one exit code.
                if let Some(first) = &path {
                    return Err(format!(
                        "verify takes one PATH, got `{}` and `{other}`",
                        first.display()
                    ));
                }
                path = Some(PathBuf::from(other));
            }
        }
        i += 1;
    }

    Ok(Command::Verify {
        // The record file's name and extension are unresolved (SPEC.md, "Not
        // specified by this version", AILAB-623), so any path is accepted
        // as-is. Do not start validating an extension here — that would invent
        // the format's spelling by accident.
        path: path.ok_or("verify requires <PATH>")?,
        keys,
        trust_store,
    })
}

pub fn usage_text() -> String {
    format!(
        "aegis {} — research runtime for secure agent tool execution\n\
         \n\
         Usage:\n\
           aegis [--policy <PATH>] [--audit <PATH>]\n\
           aegis run --component <WASM> --id <TOOL_ID> [OPTIONS]\n\
           aegis verify [--key <HEX>]... [--trust-store <PATH>] <PATH>\n\
         \n\
         Run options:\n\
           --component, --wasm <PATH>  WASM component to register\n\
           --id, --tool-id <ID>        Tool id for policy/capability/audit\n\
           --input <TEXT>              Call input (default: empty)\n\
           --input-file <PATH>         Read call input from file\n\
           --policy <PATH>             Policy YAML (default: allow-all)\n\
           --audit <PATH>              Audit JSONL path (default: temp file)\n\
           --base-dir <PATH>           Manifest base dir (default: component parent)\n\
           --sha256 <HEX>              Optional component digest pin (G10)\n\
           --version <VER>             Tool version in manifest (default: 0.1.0)\n\
           --help, -h                  Print this help\n\
         \n\
         Verify options:\n\
           --key <HEX>                 Trusted public key, 64 lowercase hex (repeatable)\n\
           --trust-store <PATH>        File of trusted public keys, one hex per line\n\
           --help, -h                  Print this help\n\
         \n\
         Verify exit codes:\n\
           0  verified        2  could not read the record or the trust store\n\
           1  tampered, or a usage error                 3  indeterminate\n",
        env!("CARGO_PKG_VERSION")
    )
}

/// Build a configured runtime from optional policy/audit paths (no tools yet).
///
/// Construction is delegated to [`RuntimeBuilder`] so the CLI and the MCP
/// gateway cannot drift apart on how policy YAML is parsed or how the audit
/// sink is opened. An unset flag is *not* the same as a permissive default the
/// CLI invents: leaving the option `None` simply keeps the runtime's own
/// defaults (allow-all policy, temp-file audit sink), which is what the
/// pre-builder code did by never calling `with_policy` / `with_audit`.
///
/// [`BuildError`](botzr_aegis_runtime::BuildError) already carries the offending
/// path in its `Display`, so flattening it to `String` here preserves the error
/// text callers (and `dispatch`) print today.
pub fn build_runtime(policy: Option<&Path>, audit: Option<&Path>) -> Result<Runtime, String> {
    let mut builder = RuntimeBuilder::new();

    if let Some(path) = policy {
        builder = builder.policy_file(path).map_err(|e| e.to_string())?;
    }

    if let Some(path) = audit {
        builder = builder.audit_file(path).map_err(|e| e.to_string())?;
    }

    builder.build().map_err(|e| e.to_string())
}

pub fn execute_run(args: &RunArgs) -> Result<Vec<u8>, AegisError> {
    let mut rt = build_runtime(args.policy.as_deref(), args.audit.as_deref())
        .map_err(|e| AegisError::HostDenied { reason: e })?;

    let bytes = std::fs::read(&args.component).map_err(|e| AegisError::HostDenied {
        reason: format!("read component {}: {e}", args.component.display()),
    })?;

    let base = args.base_dir.clone().unwrap_or_else(|| {
        args.component
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .to_path_buf()
    });

    let mut manifest = ToolManifest::new(
        ToolInfo {
            id: ToolId::new(args.id.clone()),
            version: args.version.clone(),
            kind: ToolKind::Wasm,
        },
        &base,
    )
    .with_component_path(
        args.component
            .file_name()
            .map(PathBuf::from)
            .unwrap_or_else(|| args.component.clone()),
    );

    if let Some(pin) = &args.sha256 {
        manifest = manifest.with_sha256(pin.clone());
    }

    rt.register(manifest, bytes)
        .map_err(|e| AegisError::HostDenied {
            reason: format!("register {}: {e}", args.id),
        })?;

    let input = load_input(args).map_err(|e| AegisError::HostDenied { reason: e })?;

    eprintln!(
        "aegis {} — run {} through POLICY → CAPABILITY → SANDBOX → AUDIT",
        env!("CARGO_PKG_VERSION"),
        args.id
    );
    eprintln!("Audit: {}", rt.audit().path().display());
    // Diagnostic only — the digest is no longer an execute argument. The runtime
    // derives it internally for the audit record; we call the *same* constructor
    // here purely so the operator can eyeball-match this line against the
    // `request_digest` field in the emitted JSONL.
    eprintln!(
        "request_digest: {}",
        RequestDigest::of_request_bytes(&input)
    );

    rt.execute_tool_call(ToolId::new(args.id.clone()), &input)
}

fn load_input(args: &RunArgs) -> Result<Vec<u8>, String> {
    if let Some(path) = &args.input_file {
        return std::fs::read(path).map_err(|e| format!("read input {}: {e}", path.display()));
    }
    Ok(args.input.clone().unwrap_or_default().into_bytes())
}

pub fn dispatch(cmd: Command) -> ExitCode {
    match cmd {
        Command::Help => {
            eprint!("{}", usage_text());
            ExitCode::SUCCESS
        }
        Command::Ready { policy, audit } => {
            match build_runtime(policy.as_deref(), audit.as_deref()) {
                Ok(rt) => {
                    eprintln!(
                        "aegis {} — research runtime for secure agent tool execution",
                        env!("CARGO_PKG_VERSION")
                    );
                    eprintln!("Pipeline: policy → capability → sandbox → audit");
                    eprintln!("Audit: {}", rt.audit().path().display());
                    eprintln!(
                    "Runtime ready — use `aegis run --component <WASM> --id <TOOL_ID>` to execute"
                );
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("error: {e}");
                    ExitCode::from(1)
                }
            }
        }
        Command::Verify {
            path,
            keys,
            trust_store,
        } => verify::run(&path, &keys, trust_store.as_deref()),
        Command::Run(args) => match execute_run(&args) {
            Ok(out) => {
                if let Err(e) = std::io::Write::write_all(&mut std::io::stdout(), &out) {
                    eprintln!("stdout write error: {e}");
                    return ExitCode::from(1);
                }
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("error: {e}");
                // Audit may still have been written on pipeline deny/trap.
                ExitCode::from(1)
            }
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_run_minimal() {
        let args = vec![
            "aegis".into(),
            "run".into(),
            "--component".into(),
            "echo.wasm".into(),
            "--id".into(),
            "echo".into(),
            "--input".into(),
            "hi".into(),
        ];
        match parse_args(&args).unwrap() {
            Command::Run(r) => {
                assert_eq!(r.component, PathBuf::from("echo.wasm"));
                assert_eq!(r.id, "echo");
                assert_eq!(r.input.as_deref(), Some("hi"));
            }
            other => panic!("expected Run, got {other:?}"),
        }
    }

    #[test]
    fn parse_ready_flags() {
        let args = vec![
            "aegis".into(),
            "--policy".into(),
            "p.yaml".into(),
            "--audit".into(),
            "a.jsonl".into(),
        ];
        match parse_args(&args).unwrap() {
            Command::Ready { policy, audit } => {
                assert_eq!(policy, Some(PathBuf::from("p.yaml")));
                assert_eq!(audit, Some(PathBuf::from("a.jsonl")));
            }
            other => panic!("expected Ready, got {other:?}"),
        }
    }

    fn sv(args: &[&str]) -> Vec<String> {
        args.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn parse_run_all_optional_flags() {
        let args = sv(&[
            "aegis",
            "run",
            "--wasm",
            "e.wasm",
            "--tool-id",
            "echo",
            "--input-file",
            "in.txt",
            "--base-dir",
            "/tmp/base",
            "--sha256",
            "abc123",
            "--version",
            "9.9.9",
            "--policy",
            "p.yaml",
            "--audit",
            "a.jsonl",
        ]);
        match parse_args(&args).unwrap() {
            Command::Run(r) => {
                assert_eq!(r.component, PathBuf::from("e.wasm"));
                assert_eq!(r.id, "echo");
                assert_eq!(r.input, None);
                assert_eq!(r.input_file, Some(PathBuf::from("in.txt")));
                assert_eq!(r.base_dir, Some(PathBuf::from("/tmp/base")));
                assert_eq!(r.sha256.as_deref(), Some("abc123"));
                assert_eq!(r.version, "9.9.9");
                assert_eq!(r.policy, Some(PathBuf::from("p.yaml")));
                assert_eq!(r.audit, Some(PathBuf::from("a.jsonl")));
            }
            other => panic!("expected Run, got {other:?}"),
        }
    }

    #[test]
    fn parse_errors_and_help_paths() {
        // top-level help forms
        for args in [
            sv(&["aegis", "--help"]),
            sv(&["aegis", "-h"]),
            sv(&["aegis", "help"]),
        ] {
            assert_eq!(parse_args(&args).unwrap(), Command::Help);
        }
        // run --help
        assert_eq!(
            parse_args(&sv(&["aegis", "run", "--help"])).unwrap(),
            Command::Help
        );
        // no args → ready with defaults
        assert_eq!(
            parse_args(&sv(&["aegis"])).unwrap(),
            Command::Ready {
                policy: None,
                audit: None
            }
        );
        // unknown command / unknown flags / missing values
        assert!(parse_args(&sv(&["aegis", "frobnicate"]))
            .unwrap_err()
            .contains("unknown command"));
        assert!(parse_args(&sv(&["aegis", "--bogus"]))
            .unwrap_err()
            .contains("unknown flag"));
        assert!(parse_args(&sv(&["aegis", "run", "--bogus"]))
            .unwrap_err()
            .contains("unknown flag"));
        assert!(parse_args(&sv(&["aegis", "--policy"]))
            .unwrap_err()
            .contains("needs a value"));
        assert!(parse_args(&sv(&["aegis", "run", "--input-file"]))
            .unwrap_err()
            .contains("needs a value"));
        // exclusive inputs
        let err = parse_args(&sv(&[
            "aegis",
            "run",
            "--component",
            "e.wasm",
            "--id",
            "e",
            "--input",
            "x",
            "--input-file",
            "f",
        ]))
        .unwrap_err();
        assert!(err.contains("only one of"));
        // missing required flags
        assert!(parse_args(&sv(&["aegis", "run", "--id", "e"]))
            .unwrap_err()
            .contains("--component"));
        assert!(parse_args(&sv(&["aegis", "run", "--component", "e.wasm"]))
            .unwrap_err()
            .contains("--id"));
    }

    #[test]
    fn usage_text_names_every_flag() {
        let usage = usage_text();
        for flag in [
            "--component",
            "--id",
            "--input",
            "--input-file",
            "--policy",
            "--audit",
            "--base-dir",
            "--sha256",
            "--version",
            "--key",
            "--trust-store",
        ] {
            assert!(usage.contains(flag), "usage missing {flag}");
        }
        assert!(usage.contains("verify"), "usage missing the verify command");
    }

    /// The four exit codes are API (ADR-0002), so `--help` has to name them.
    #[test]
    fn usage_text_names_the_verify_exit_codes() {
        let usage = usage_text();
        for code in [
            "0  verified",
            "1  tampered",
            "2  could not read",
            "3  indeterminate",
        ] {
            assert!(usage.contains(code), "usage missing exit code line {code}");
        }
    }

    /// `--key` is the `public_key` wire form, so a real 64-hex key parses and a
    /// `key_id`-shaped typo does not silently become a pin.
    #[test]
    fn parse_verify_collects_keys_and_store() {
        let key_a = "0".repeat(64);
        let key_b = "a".repeat(64);
        let args = sv(&[
            "aegis",
            "verify",
            "--key",
            &key_a,
            "--key",
            &key_b,
            "--trust-store",
            "keys.txt",
            "session.log",
        ]);
        match parse_args(&args).unwrap() {
            Command::Verify {
                path,
                keys,
                trust_store,
            } => {
                assert_eq!(path, PathBuf::from("session.log"));
                assert_eq!(
                    keys,
                    vec![
                        PublicKey::from_hex(&key_a).unwrap(),
                        PublicKey::from_hex(&key_b).unwrap()
                    ]
                );
                assert_eq!(trust_store, Some(PathBuf::from("keys.txt")));
            }
            other => panic!("expected Verify, got {other:?}"),
        }
    }

    /// No `--key` and no store is the unpinned walk, not an error.
    #[test]
    fn parse_verify_bare_path_is_unpinned() {
        match parse_args(&sv(&["aegis", "verify", "session.log"])).unwrap() {
            Command::Verify {
                path,
                keys,
                trust_store,
            } => {
                assert_eq!(path, PathBuf::from("session.log"));
                assert!(keys.is_empty());
                assert_eq!(trust_store, None);
            }
            other => panic!("expected Verify, got {other:?}"),
        }
    }

    /// Any extension, including none: the record file's name is unresolved
    /// (AILAB-623) and the CLI must not invent one by validating here.
    #[test]
    fn parse_verify_accepts_any_extension() {
        for path in ["session.log", "session", "session.jsonl", "/var/log/a.b.c"] {
            match parse_args(&sv(&["aegis", "verify", path])).unwrap() {
                Command::Verify { path: parsed, .. } => assert_eq!(parsed, PathBuf::from(path)),
                other => panic!("expected Verify, got {other:?}"),
            }
        }
    }

    #[test]
    fn parse_verify_usage_errors() {
        // `verify --help` behaves like `run --help`.
        assert_eq!(
            parse_args(&sv(&["aegis", "verify", "--help"])).unwrap(),
            Command::Help
        );
        assert_eq!(
            parse_args(&sv(&["aegis", "verify", "-h"])).unwrap(),
            Command::Help
        );
        // Missing PATH.
        assert!(parse_args(&sv(&["aegis", "verify"]))
            .unwrap_err()
            .contains("requires <PATH>"));
        // A second positional is a forgotten flag value, not two files.
        assert!(parse_args(&sv(&["aegis", "verify", "a.log", "b.log"]))
            .unwrap_err()
            .contains("one PATH"));
        // Missing values and unknown flags.
        assert!(parse_args(&sv(&["aegis", "verify", "--key"]))
            .unwrap_err()
            .contains("needs a value"));
        assert!(parse_args(&sv(&["aegis", "verify", "--trust-store"]))
            .unwrap_err()
            .contains("needs a value"));
        assert!(parse_args(&sv(&["aegis", "verify", "--bogus", "a.log"]))
            .unwrap_err()
            .contains("unknown flag"));
        // Bad hex is a usage error (exit 1), never a verdict about the file.
        for bad in ["deadbeef", &"A".repeat(64), &"z".repeat(64)] {
            assert!(
                parse_args(&sv(&["aegis", "verify", "--key", bad, "a.log"]))
                    .unwrap_err()
                    .contains("64-hex public key"),
                "expected a hex usage error for {bad}"
            );
        }
    }

    #[test]
    fn dispatch_help_and_ready_paths() {
        let success = format!("{:?}", ExitCode::SUCCESS);
        assert_eq!(format!("{:?}", dispatch(Command::Help)), success);
        // Default runtime: allow-all policy, temp audit — builds cleanly.
        assert_eq!(
            format!(
                "{:?}",
                dispatch(Command::Ready {
                    policy: None,
                    audit: None
                })
            ),
            success
        );
        // Bad policy path → error arm.
        let failure = format!("{:?}", ExitCode::from(1));
        assert_eq!(
            format!(
                "{:?}",
                dispatch(Command::Ready {
                    policy: Some(PathBuf::from("/nonexistent/policy.yaml")),
                    audit: None,
                })
            ),
            failure
        );
    }
}
