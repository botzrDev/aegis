use std::env;
use std::path::PathBuf;

use botzr_aegis_runtime::Runtime;

fn main() {
    let args: Vec<String> = env::args().collect();

    let mut policy_path: Option<PathBuf> = None;
    let mut audit_path: Option<PathBuf> = None;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--policy" => {
                i += 1;
                policy_path = Some(PathBuf::from(args.get(i).expect("--policy needs a value")));
            }
            "--audit" => {
                i += 1;
                audit_path = Some(PathBuf::from(args.get(i).expect("--audit needs a value")));
            }
            "--help" | "-h" => {
                eprintln!(
                    "aegis {} — research runtime for secure agent tool execution",
                    env!("CARGO_PKG_VERSION")
                );
                eprintln!();
                eprintln!("Usage: aegis [OPTIONS]");
                eprintln!();
                eprintln!("Options:");
                eprintln!("  --policy <PATH>  Path to policy YAML (default: allow-all)");
                eprintln!("  --audit  <PATH>  Path for audit JSONL output (default: temp file)");
                eprintln!("  --help, -h       Print this help");
                return;
            }
            _ => {
                eprintln!("unknown flag: {}", args[i]);
                eprintln!("Usage: aegis [--policy <PATH>] [--audit <PATH>]");
                std::process::exit(1);
            }
        }
        i += 1;
    }

    let mut rt = Runtime::new();

    if let Some(path) = policy_path {
        let yaml = match std::fs::read_to_string(&path) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("error reading policy {}: {e}", path.display());
                std::process::exit(1);
            }
        };
        let engine = match botzr_aegis_policy::PolicyEngine::from_yaml(&yaml) {
            Ok(e) => e,
            Err(e) => {
                eprintln!("error parsing policy {}: {e}", path.display());
                std::process::exit(1);
            }
        };
        rt = rt.with_policy(engine);
    }

    if let Some(path) = audit_path {
        let writer = match botzr_aegis_audit::AuditWriter::open(&path) {
            Ok(w) => w,
            Err(e) => {
                eprintln!("error opening audit {}: {e}", path.display());
                std::process::exit(1);
            }
        };
        rt = rt.with_audit(writer);
    }

    eprintln!(
        "aegis {} — research runtime for secure agent tool execution",
        env!("CARGO_PKG_VERSION")
    );
    eprintln!("Pipeline: policy → capability → sandbox → audit");
    eprintln!("Audit: {}", rt.audit().path().display());
    eprintln!("Runtime ready (no tools registered — use the library API in your agent framework)");
}
