//! `aegis` CLI library — argument parsing and `run` pipeline wiring.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use botzr_aegis_audit::AuditWriter;
use botzr_aegis_capability::{ToolInfo, ToolKind, ToolManifest};
use botzr_aegis_core::ToolId;
use botzr_aegis_policy::PolicyEngine;
use botzr_aegis_runtime::{sha256_hex, Runtime};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    /// Print ready banner (legacy / default when no subcommand).
    Ready {
        policy: Option<PathBuf>,
        audit: Option<PathBuf>,
    },
    /// Register a WASM component and execute one call through the pipeline.
    Run(RunArgs),
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

pub fn usage_text() -> String {
    format!(
        "aegis {} — research runtime for secure agent tool execution\n\
         \n\
         Usage:\n\
           aegis [--policy <PATH>] [--audit <PATH>]\n\
           aegis run --component <WASM> --id <TOOL_ID> [OPTIONS]\n\
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
           --help, -h                  Print this help\n",
        env!("CARGO_PKG_VERSION")
    )
}

/// Build a configured runtime from optional policy/audit paths (no tools yet).
pub fn build_runtime(policy: Option<&Path>, audit: Option<&Path>) -> Result<Runtime, String> {
    let mut rt = Runtime::new();

    if let Some(path) = policy {
        let yaml = std::fs::read_to_string(path)
            .map_err(|e| format!("read policy {}: {e}", path.display()))?;
        let engine = PolicyEngine::from_yaml(&yaml)
            .map_err(|e| format!("parse policy {}: {e}", path.display()))?;
        rt = rt.with_policy(engine);
    }

    if let Some(path) = audit {
        let writer =
            AuditWriter::open(path).map_err(|e| format!("open audit {}: {e}", path.display()))?;
        rt = rt.with_audit(writer);
    }

    Ok(rt)
}

pub fn execute_run(args: &RunArgs) -> Result<Vec<u8>, String> {
    let mut rt = build_runtime(args.policy.as_deref(), args.audit.as_deref())?;

    let bytes = std::fs::read(&args.component)
        .map_err(|e| format!("read component {}: {e}", args.component.display()))?;

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
        .map_err(|e| format!("register {}: {e}", args.id))?;

    let input = load_input(args)?;
    let digest = sha256_hex(&input);

    eprintln!(
        "aegis {} — run {} through POLICY → CAPABILITY → SANDBOX → AUDIT",
        env!("CARGO_PKG_VERSION"),
        args.id
    );
    eprintln!("Audit: {}", rt.audit().path().display());
    eprintln!("input_digest: {digest}");

    rt.execute_tool_call(ToolId::new(args.id.clone()), digest, &input)
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
}
