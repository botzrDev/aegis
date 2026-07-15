//! stdio MCP binary — CLI flags mirror `aegis` (`--policy`, `--audit`).

use std::env;
use std::io::{self, BufRead, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use botzr_aegis_mcp::{build_runtime, handle_line};

fn print_help() {
    eprintln!(
        "botzr-aegis-mcp {} — Phase 2 MCP stdio gateway for Aegis",
        env!("CARGO_PKG_VERSION")
    );
    eprintln!();
    eprintln!("Usage: botzr-aegis-mcp [OPTIONS]");
    eprintln!();
    eprintln!("Options:");
    eprintln!("  --policy <PATH>  Path to policy YAML (default: allow-all except exfil)");
    eprintln!("  --audit  <PATH>  Path for audit JSONL output (default: temp file)");
    eprintln!("  --help, -h       Print this help");
    eprintln!();
    eprintln!("Transport: MCP JSON-RPC on stdio (newline-delimited). Logs go to stderr.");
    eprintln!("See crates/botzr-aegis-mcp/DECISIONS.md (D17) and docs/threat-model.md.");
}

fn parse_args(args: &[String]) -> Result<(Option<PathBuf>, Option<PathBuf>), i32> {
    let mut policy_path = None;
    let mut audit_path = None;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--policy" => {
                i += 1;
                let Some(v) = args.get(i) else {
                    eprintln!("--policy needs a value");
                    return Err(1);
                };
                policy_path = Some(PathBuf::from(v));
            }
            "--audit" => {
                i += 1;
                let Some(v) = args.get(i) else {
                    eprintln!("--audit needs a value");
                    return Err(1);
                };
                audit_path = Some(PathBuf::from(v));
            }
            "--help" | "-h" => {
                print_help();
                return Err(0);
            }
            other => {
                eprintln!("unknown flag: {other}");
                eprintln!("Usage: botzr-aegis-mcp [--policy <PATH>] [--audit <PATH>]");
                return Err(1);
            }
        }
        i += 1;
    }
    Ok((policy_path, audit_path))
}

fn main() -> ExitCode {
    let args: Vec<String> = env::args().collect();
    let (policy_path, audit_path) = match parse_args(&args) {
        Ok(paths) => paths,
        Err(0) => return ExitCode::SUCCESS,
        Err(_) => return ExitCode::from(1),
    };

    let runtime = match build_runtime(policy_path.as_deref(), audit_path.as_deref()) {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::from(1);
        }
    };

    eprintln!(
        "botzr-aegis-mcp {} — MCP stdio gateway",
        env!("CARGO_PKG_VERSION")
    );
    eprintln!("Pipeline: policy → capability → sandbox → audit");
    eprintln!("Audit: {}", runtime.audit().path().display());
    eprintln!("Tools: echo (allow) + exfil (policy-denied by default) — Model A WASM");

    let stdin = io::stdin();
    let mut stdout = io::stdout();
    for line in stdin.lock().lines() {
        let line = match line {
            Ok(l) => l,
            Err(e) => {
                eprintln!("stdin read error: {e}");
                return ExitCode::from(1);
            }
        };
        if let Some(response) = handle_line(&runtime, &line) {
            if let Err(e) = writeln!(stdout, "{response}") {
                eprintln!("stdout write error: {e}");
                return ExitCode::from(1);
            }
            if let Err(e) = stdout.flush() {
                eprintln!("stdout flush error: {e}");
                return ExitCode::from(1);
            }
        }
    }
    ExitCode::SUCCESS
}
