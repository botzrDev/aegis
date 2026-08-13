//! `aegis` CLI library — argument parsing and `run` pipeline wiring.
//!
//! `aegis __confine-exec` is an internal re-exec target (ADR-0007 / AILAB-628),
//! not operator surface: it is the first match arm in [`parse_args`] and is
//! kept out of [`usage_text()`].

mod confine_exec;
mod recheck;
mod verify;
mod wrap;

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
        signing_key: Option<PathBuf>,
    },
    /// Generate an audit signing key and write it to a file (AILAB-620).
    ///
    /// Its own command because generation must never be implicit: a key minted
    /// on the emit path would publish a brand-new `public_key` in the Session's
    /// `open` line and silently invalidate every pin an operator held.
    Keygen {
        out: PathBuf,
        force: bool,
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
    /// Re-evaluate every recorded outcome in a record file against a *new*
    /// Policy Set and print the would-block diff (AILAB-622).
    ///
    /// `policy` is required, unlike `run`'s: the whole question is "what would
    /// *these* rules have done?", and an implicit allow-all default would answer
    /// a question nobody asked while looking like a finding. Nothing is
    /// executed, no grant is minted, no signature is checked — a record
    /// `aegis verify` would call `Tampered` is still a legitimate subject for
    /// the what-if.
    Recheck {
        policy: PathBuf,
        path: PathBuf,
    },
    /// Interpose on an existing stdio MCP server and record each single
    /// `tools/call` it carries (AILAB-625).
    ///
    /// "Single" is load-bearing: a `tools/call` sent inside a JSON-RPC **batch
    /// array** is relayed and **not** recorded. Wrap names that bypass on
    /// stderr when it happens rather than hiding it — see
    /// `crates/botzr-aegis-wrap/README.md`.
    ///
    /// Its own verb rather than a mode of `Run`: `run` executes a WASM component
    /// through POLICY → CAPABILITY → SANDBOX → AUDIT, while `wrap` relays an
    /// ordinary OS process. Wrap's only *always-on* station is AUDIT; Landlock
    /// and seccomp apply only when `--confine` is given (AILAB-628). One verb
    /// spanning both trust models is how "Aegis ran it" comes to mean two
    /// incompatible things.
    Wrap(WrapArgs),
    /// Internal re-exec target. Not operator surface (ADR-0007).
    ConfineExec {
        child_argv: Vec<String>,
    },
    Help,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunArgs {
    pub policy: Option<PathBuf>,
    pub audit: Option<PathBuf>,
    /// Path to the ed25519 seed file signing this Session. Required whenever
    /// `audit` is set, and meaningless without it (AILAB-620).
    pub signing_key: Option<PathBuf>,
    pub component: PathBuf,
    pub id: String,
    pub input: Option<String>,
    pub input_file: Option<PathBuf>,
    pub base_dir: Option<PathBuf>,
    pub sha256: Option<String>,
    pub version: String,
}

/// `aegis wrap --audit <PATH> --signing-key <PATH> -- <CMD> [ARGS…]`.
///
/// Both paths are required, unlike `run`'s optional pair, because wrap has no
/// temp-sink mode: the only thing an interposer produces is its record, so a
/// wrap session writing to a throwaway file signed by the dev key would be a
/// process that stood in the middle and proved nothing (AILAB-620).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WrapArgs {
    pub audit: PathBuf,
    /// Path to the ed25519 seed file signing this Session. Required here rather
    /// than conditional, for the reason above.
    pub signing_key: PathBuf,
    /// Everything after the literal `--`: `[0]` is the program, the rest are its
    /// arguments. Never empty — `parse_wrap` refuses an argv with nothing in it.
    pub child_argv: Vec<String>,
    /// Opt-in OS confinement (AILAB-628). Off unless asked for.
    pub confine: bool,
    pub allow_read: Vec<PathBuf>,
    pub allow_write: Vec<PathBuf>,
    /// `(host, port)` from `--allow-net HOST:PORT`.
    pub allow_net: Vec<(String, u16)>,
    /// Operator opt-in to partial enforcement. Meaningless without `--confine`.
    pub best_effort: bool,
}

pub fn parse_args(args: &[String]) -> Result<Command, String> {
    if args.len() <= 1 {
        return Ok(Command::Ready {
            policy: None,
            audit: None,
            signing_key: None,
        });
    }

    match args[1].as_str() {
        // Internal re-exec target (ADR-0007). First so it cannot be shadowed
        // by `--help` or an unknown-command path, and so it stays reachable
        // before any heavier dispatch.
        "__confine-exec" => parse_confine_exec(&args[2..]),
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
        "recheck" => match parse_recheck(&args[2..]) {
            Ok(cmd) => Ok(cmd),
            Err(e) if e == "__help_recheck__" => Ok(Command::Help),
            Err(e) => Err(e),
        },
        "keygen" => match parse_keygen(&args[2..]) {
            Ok(cmd) => Ok(cmd),
            Err(e) if e == "__help_keygen__" => Ok(Command::Help),
            Err(e) => Err(e),
        },
        "wrap" => match parse_wrap(&args[2..]) {
            Ok(wrap) => Ok(Command::Wrap(wrap)),
            Err(e) if e == "__help_wrap__" => Ok(Command::Help),
            Err(e) => Err(e),
        },
        other if other.starts_with('-') => {
            // Global flags only → ready mode (backward compatible stub).
            match parse_global_flags(&args[1..]) {
                Ok((policy, audit, signing_key)) => Ok(Command::Ready {
                    policy,
                    audit,
                    signing_key,
                }),
                Err(e) if e == "__help__" => Ok(Command::Help),
                Err(e) => Err(e),
            }
        }
        other => Err(format!("unknown command: {other}\n{}", usage_text())),
    }
}

type GlobalFlags = (Option<PathBuf>, Option<PathBuf>, Option<PathBuf>);

fn parse_global_flags(args: &[String]) -> Result<GlobalFlags, String> {
    let mut policy = None;
    let mut audit = None;
    let mut signing_key = None;
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
            "--signing-key" => {
                i += 1;
                let v = args.get(i).ok_or("--signing-key needs a value")?;
                signing_key = Some(PathBuf::from(v));
            }
            "--help" | "-h" => return Err("__help__".into()),
            other => return Err(format!("unknown flag: {other}")),
        }
        i += 1;
    }
    check_audit_key_pair(audit.as_deref(), signing_key.as_deref())?;
    Ok((policy, audit, signing_key))
}

/// `--audit` and `--signing-key` travel together, or neither is given.
///
/// A usage error, not a default (AILAB-620): a persistent record file signed by
/// a key the CLI picked on its own is exactly the situation `Verified (pinned)`
/// must never be able to describe. Without `--audit` the sink is a temp file
/// signed by the loudly-named dev key, and a signing key for it would be
/// pointing at nothing.
fn check_audit_key_pair(audit: Option<&Path>, signing_key: Option<&Path>) -> Result<(), String> {
    match (audit, signing_key) {
        (Some(_), None) => Err(
            "--audit requires --signing-key <PATH>; generate one with `aegis keygen --out <PATH>`"
                .into(),
        ),
        (None, Some(_)) => Err(
            "--signing-key only applies with --audit <PATH> (the default sink is a temp file)"
                .into(),
        ),
        _ => Ok(()),
    }
}

/// Parse `aegis keygen --out <PATH> [--force]`.
fn parse_keygen(args: &[String]) -> Result<Command, String> {
    let mut out = None;
    let mut force = false;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--out" => {
                i += 1;
                let v = args.get(i).ok_or("--out needs a value")?;
                out = Some(PathBuf::from(v));
            }
            "--force" => force = true,
            "--help" | "-h" => return Err("__help_keygen__".into()),
            other => return Err(format!("unknown flag: {other}")),
        }
        i += 1;
    }

    Ok(Command::Keygen {
        // No default path. An implicit `~/.config/aegis/...` would make a
        // missing key silently resolvable, and the point of this surface is that
        // key location is a decision the operator states out loud.
        out: out.ok_or("keygen requires --out <PATH>")?,
        force,
    })
}

fn parse_run(args: &[String]) -> Result<RunArgs, String> {
    let mut policy = None;
    let mut audit = None;
    let mut signing_key = None;
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
            "--signing-key" => {
                i += 1;
                let v = args.get(i).ok_or("--signing-key needs a value")?;
                signing_key = Some(PathBuf::from(v));
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
    check_audit_key_pair(audit.as_deref(), signing_key.as_deref())?;

    Ok(RunArgs {
        policy,
        audit,
        signing_key,
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

/// Parse `aegis recheck --policy <YAML> <PATH>`.
///
/// Every error here is a usage error, which `main.rs` maps to exit 1 — kept
/// clear of recheck's own 0/1/2/3, exactly as `parse_verify` is. A missing
/// `--policy` is refused here rather than defaulted: `run` may fall back to an
/// allow-all set because its job is to execute something, but a *diff* against
/// a policy nobody named would print `newly_allowed` for every recorded denial
/// and look like a finding.
fn parse_recheck(args: &[String]) -> Result<Command, String> {
    let mut policy: Option<PathBuf> = None;
    let mut path: Option<PathBuf> = None;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--policy" => {
                i += 1;
                let v = args.get(i).ok_or("--policy needs a value")?;
                policy = Some(PathBuf::from(v));
            }
            "--help" | "-h" => return Err("__help_recheck__".into()),
            other if other.starts_with('-') => return Err(format!("unknown flag: {other}")),
            other => {
                // One record file per invocation, for `parse_verify`'s reason:
                // two positionals is more likely a forgotten flag value than a
                // request to diff both, and guessing would fold two reports
                // into one exit code.
                if let Some(first) = &path {
                    return Err(format!(
                        "recheck takes one PATH, got `{}` and `{other}`",
                        first.display()
                    ));
                }
                path = Some(PathBuf::from(other));
            }
        }
        i += 1;
    }

    Ok(Command::Recheck {
        policy: policy.ok_or("recheck requires --policy <PATH>")?,
        // Any extension, like `verify`: the record file's name is unresolved
        // (SPEC.md, AILAB-623), and validating one here would invent the
        // format's spelling by accident.
        path: path.ok_or("recheck requires <PATH>")?,
    })
}

/// Parse `aegis wrap --audit <PATH> --signing-key <PATH> -- <CMD> [ARGS…]`.
///
/// The literal `--` ends *wrap's* parsing and takes everything after it verbatim
/// as the child's argv. That is load-bearing rather than conventional: the child
/// is a foreign program whose flags Aegis does not control, so
/// `aegis wrap … -- npx some-server --help` has to hand `--help` to npx instead
/// of printing this CLI's usage, and `--audit` after the separator has to reach
/// the child rather than silently redirect Aegis's own record file. Nothing
/// after `--` is inspected, reordered, or shell-split.
///
/// Both paths are required here, unlike `run`'s. [`check_audit_key_pair`] still
/// runs first so the pairing mistake keeps its shared wording, but its
/// "neither was given" arm — legal for `run`, whose default sink is a temp file
/// — is a usage error for this verb.
fn parse_wrap(args: &[String]) -> Result<WrapArgs, String> {
    let mut audit = None;
    let mut signing_key = None;
    let mut child_argv: Vec<String> = Vec::new();
    let mut confine = false;
    let mut allow_read = Vec::new();
    let mut allow_write = Vec::new();
    let mut allow_net = Vec::new();
    let mut best_effort = false;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--audit" => {
                i += 1;
                let v = args.get(i).ok_or("--audit needs a value")?;
                audit = Some(PathBuf::from(v));
            }
            "--signing-key" => {
                i += 1;
                let v = args.get(i).ok_or("--signing-key needs a value")?;
                signing_key = Some(PathBuf::from(v));
            }
            "--confine" => confine = true,
            "--best-effort" => best_effort = true,
            "--allow-read" => {
                i += 1;
                let v = args.get(i).ok_or("--allow-read needs a value")?;
                allow_read.push(PathBuf::from(v));
            }
            "--allow-write" => {
                i += 1;
                let v = args.get(i).ok_or("--allow-write needs a value")?;
                allow_write.push(PathBuf::from(v));
            }
            "--allow-net" => {
                i += 1;
                let v = args.get(i).ok_or("--allow-net needs a value")?;
                allow_net.push(parse_allow_net(v)?);
            }
            "--help" | "-h" => return Err("__help_wrap__".into()),
            "--" => {
                child_argv = args[i + 1..].to_vec();
                break;
            }
            // A bare word before the separator is a forgotten `--`, not a flag.
            // Reporting it as `unknown flag: npx` would name the child program
            // as the mistake and hide the one character that is actually
            // missing.
            other if !other.starts_with('-') => {
                return Err(format!(
                    "wrap takes no positional arguments; put the child command after `--` (got `{other}`)"
                ))
            }
            other => return Err(format!("unknown flag: {other}")),
        }
        i += 1;
    }

    check_audit_key_pair(audit.as_deref(), signing_key.as_deref())?;
    let audit = audit.ok_or("wrap requires --audit <PATH>")?;
    let signing_key = signing_key.ok_or(
        "wrap requires --signing-key <PATH>; generate one with `aegis keygen --out <PATH>`",
    )?;
    // An empty argv is refused here rather than passed on: relaying a client's
    // stdin to a child that was never named would look like a working session
    // that records nothing.
    if child_argv.is_empty() {
        return Err("wrap requires a child command after `--`".into());
    }

    // `--allow-*` / `--best-effort` without `--confine` is a usage error, not
    // a silent no-op — same pairing shape as `check_audit_key_pair`.
    if !confine
        && (!allow_read.is_empty()
            || !allow_write.is_empty()
            || !allow_net.is_empty()
            || best_effort)
    {
        return Err(
            "--allow-read, --allow-write, --allow-net and --best-effort require --confine".into(),
        );
    }

    Ok(WrapArgs {
        audit,
        signing_key,
        child_argv,
        confine,
        allow_read,
        allow_write,
        allow_net,
        best_effort,
    })
}

/// `HOST:PORT`, split on the last colon so a v6 literal can wait for a later
/// ticket. Empty host or a non-u16 port is a usage error.
fn parse_allow_net(value: &str) -> Result<(String, u16), String> {
    let (host, port) = value
        .rsplit_once(':')
        .ok_or_else(|| format!("--allow-net needs HOST:PORT, got `{value}`"))?;
    if host.is_empty() {
        return Err(format!("--allow-net needs a host, got `{value}`"));
    }
    let port: u16 = port
        .parse()
        .map_err(|_| format!("--allow-net needs a port 0–65535, got `{value}`"))?;
    Ok((host.to_string(), port))
}

/// Parse `aegis __confine-exec -- <CMD> [ARGS…]`.
fn parse_confine_exec(args: &[String]) -> Result<Command, String> {
    match args.first().map(String::as_str) {
        Some("--") => {
            let child_argv = args[1..].to_vec();
            if child_argv.is_empty() {
                return Err("__confine-exec requires a child command after `--`".into());
            }
            Ok(Command::ConfineExec { child_argv })
        }
        Some(other) => Err(format!(
            "__confine-exec takes no flags; put the child command after `--` (got `{other}`)"
        )),
        None => Err("__confine-exec requires a child command after `--`".into()),
    }
}

pub fn usage_text() -> String {
    format!(
        "aegis {} — research runtime for secure agent tool execution\n\
         \n\
         Usage:\n\
           aegis [--policy <PATH>] [--audit <PATH> --signing-key <PATH>]\n\
           aegis run --component <WASM> --id <TOOL_ID> [OPTIONS]\n\
           aegis wrap --audit <PATH> --signing-key <PATH> [--confine] -- <CMD> [ARGS…]\n\
           aegis verify [--key <HEX>]... [--trust-store <PATH>] <PATH>\n\
           aegis recheck --policy <YAML> <PATH>\n\
           aegis keygen --out <PATH> [--force]\n\
         \n\
         Run options:\n\
           --component, --wasm <PATH>  WASM component to register\n\
           --id, --tool-id <ID>        Tool id for policy/capability/audit\n\
           --input <TEXT>              Call input (default: empty)\n\
           --input-file <PATH>         Read call input from file\n\
           --policy <PATH>             Policy YAML (default: allow-all)\n\
           --audit <PATH>              Audit JSONL path (default: temp file)\n\
           --signing-key <PATH>        ed25519 seed file signing the audit\n\
                                       Session; required with --audit\n\
           --base-dir <PATH>           Manifest base dir (default: component parent)\n\
           --sha256 <HEX>              Optional component digest pin (G10)\n\
           --version <VER>             Tool version in manifest (default: 0.1.0)\n\
           --help, -h                  Print this help\n\
         \n\
         Wrap options:\n\
           --audit <PATH>              Record file for the wrapped session (required)\n\
           --signing-key <PATH>        ed25519 seed file signing the Session (required)\n\
           --confine                   Apply Landlock + seccomp from --allow-* (Linux)\n\
           --allow-read <PATH>         Grant read (repeatable; requires --confine)\n\
           --allow-write <PATH>        Grant write (repeatable; requires --confine)\n\
           --allow-net <HOST:PORT>     Grant network (repeatable; requires --confine)\n\
           --best-effort               Opt in to partial enforcement (requires --confine)\n\
           --                          End of wrap's flags; the rest is the child argv\n\
           --help, -h                  Print this help\n\
         \n\
         Wrap confines only when --confine is given, on Linux, and records what\n\
         was enforced. Without --confine the child is an ordinary OS process\n\
         with the authority of the account that started it.\n\
         \n\
         Keygen options:\n\
           --out <PATH>                Write a new signing key here (mode 0600)\n\
           --force                     Overwrite an existing key file\n\
           --help, -h                  Print this help\n\
         \n\
         Verify options:\n\
           --key <HEX>                 Trusted public key, 64 lowercase hex (repeatable)\n\
           --trust-store <PATH>        File of trusted public keys, one hex per line\n\
           --help, -h                  Print this help\n\
         \n\
         Verify exit codes:\n\
           0  verified        2  could not read the record or the trust store\n\
           1  tampered, or a usage error                 3  indeterminate\n\
         \n\
         Recheck options:\n\
           --policy <PATH>             Policy YAML to re-evaluate against (required)\n\
           --help, -h                  Print this help\n\
         \n\
         Recheck exit codes:\n\
           0  every call unchanged     2  could not read the policy or the record\n\
           1  a call is newly blocked, allowed or parked      3  indeterminate\n",
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
pub fn build_runtime(
    policy: Option<&Path>,
    audit: Option<&Path>,
    signing_key: Option<&Path>,
) -> Result<Runtime, String> {
    let mut builder = RuntimeBuilder::new();

    if let Some(path) = policy {
        builder = builder.policy_file(path).map_err(|e| e.to_string())?;
    }

    // The pairing rule is re-checked here rather than trusted from `parse_*`:
    // this function is public, so a library caller reaches it without going
    // through argument parsing, and "persistent sink with no provisioned key"
    // must be unrepresentable from every direction (AILAB-620).
    check_audit_key_pair(audit, signing_key)?;
    if let (Some(path), Some(key)) = (audit, signing_key) {
        builder = builder.audit_file(path, key).map_err(|e| e.to_string())?;
    }

    builder.build().map_err(|e| e.to_string())
}

pub fn execute_run(args: &RunArgs) -> Result<Vec<u8>, AegisError> {
    let mut rt = build_runtime(
        args.policy.as_deref(),
        args.audit.as_deref(),
        args.signing_key.as_deref(),
    )
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

/// `aegis keygen --out <PATH> [--force]` — write a signing key and print its
/// public identity.
///
/// Two stdout lines, `public_key <hex>` and `key_id <hex>`, and nothing else: no
/// timestamp, no path echo, no banner. The `public_key` is what
/// `aegis verify --key` pins, so it has to be greppable and stable across runs
/// of different keys. Everything else goes to stderr.
fn keygen(out: &Path, force: bool) -> ExitCode {
    match botzr_aegis_audit::generate_signing_key(out, force) {
        Ok(key) => {
            println!("public_key {}", key.public_key().to_hex());
            println!("key_id {}", key.key_id().to_hex());
            eprintln!("signing key written to {}", out.display());
            eprintln!(
                "pin records from this key with: aegis verify --key {} <PATH>",
                key.public_key().to_hex()
            );
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::from(1)
        }
    }
}

pub fn dispatch(cmd: Command) -> ExitCode {
    match cmd {
        Command::Help => {
            eprint!("{}", usage_text());
            ExitCode::SUCCESS
        }
        Command::Keygen { out, force } => keygen(&out, force),
        Command::Ready {
            policy,
            audit,
            signing_key,
        } => match build_runtime(policy.as_deref(), audit.as_deref(), signing_key.as_deref()) {
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
        },
        Command::Verify {
            path,
            keys,
            trust_store,
        } => verify::run(&path, &keys, trust_store.as_deref()),
        Command::Recheck { policy, path } => recheck::run(&policy, &path),
        Command::Wrap(args) => wrap::run(&args),
        Command::ConfineExec { child_argv } => confine_exec::run(&child_argv),
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
            "--signing-key".into(),
            "k.key".into(),
        ];
        match parse_args(&args).unwrap() {
            Command::Ready {
                policy,
                audit,
                signing_key,
            } => {
                assert_eq!(policy, Some(PathBuf::from("p.yaml")));
                assert_eq!(audit, Some(PathBuf::from("a.jsonl")));
                assert_eq!(signing_key, Some(PathBuf::from("k.key")));
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
            "--signing-key",
            "signing.key",
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
                assert_eq!(r.signing_key, Some(PathBuf::from("signing.key")));
            }
            other => panic!("expected Run, got {other:?}"),
        }
    }

    /// LOAD-BEARING (AILAB-620): a persistent audit path with no provisioned key
    /// is a usage error on every surface that accepts one. The old behaviour
    /// signed the file with the seed published inside `botzr-aegis-audit`, so
    /// defaulting here would restore exactly the hole this ticket closed.
    #[test]
    fn audit_without_a_signing_key_is_a_usage_error() {
        for args in [
            sv(&["aegis", "--audit", "a.jsonl"]),
            sv(&[
                "aegis",
                "run",
                "--component",
                "e.wasm",
                "--id",
                "echo",
                "--audit",
                "a.jsonl",
            ]),
        ] {
            let err = parse_args(&args).expect_err("--audit alone must not parse");
            assert!(err.contains("--signing-key"), "{err}");
        }

        // And the mirror: a key with no persistent sink points at nothing.
        for args in [
            sv(&["aegis", "--signing-key", "k.key"]),
            sv(&[
                "aegis",
                "run",
                "--component",
                "e.wasm",
                "--id",
                "echo",
                "--signing-key",
                "k.key",
            ]),
        ] {
            let err = parse_args(&args).expect_err("--signing-key alone must not parse");
            assert!(err.contains("--audit"), "{err}");
        }

        // The pairing rule also holds for a library caller that never parsed
        // arguments. `Runtime` has no `Debug`, so the error is destructured
        // rather than pulled out with `expect_err`.
        let Err(err) = build_runtime(None, Some(Path::new("a.jsonl")), None) else {
            panic!("build_runtime must refuse an unsigned persistent sink");
        };
        assert!(err.contains("--signing-key"), "{err}");
    }

    #[test]
    fn parse_keygen_flags() {
        match parse_args(&sv(&["aegis", "keygen", "--out", "k.key"])).unwrap() {
            Command::Keygen { out, force } => {
                assert_eq!(out, PathBuf::from("k.key"));
                assert!(!force, "force must default off");
            }
            other => panic!("expected Keygen, got {other:?}"),
        }
        match parse_args(&sv(&["aegis", "keygen", "--out", "k.key", "--force"])).unwrap() {
            Command::Keygen { force, .. } => assert!(force),
            other => panic!("expected Keygen, got {other:?}"),
        }
        assert_eq!(
            parse_args(&sv(&["aegis", "keygen", "--help"])).unwrap(),
            Command::Help
        );
        // No default path: keygen with no --out is a usage error, never a write
        // to a location the CLI picked.
        assert!(parse_args(&sv(&["aegis", "keygen"]))
            .unwrap_err()
            .contains("--out"));
        assert!(parse_args(&sv(&["aegis", "keygen", "--out"]))
            .unwrap_err()
            .contains("needs a value"));
        assert!(parse_args(&sv(&["aegis", "keygen", "--bogus"]))
            .unwrap_err()
            .contains("unknown flag"));
    }

    /// `keygen` writes an owner-only key and prints the two fields an operator
    /// needs, on stdout, in a fixed order.
    #[test]
    fn keygen_writes_a_loadable_key_and_prints_its_identity() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("signing.key");

        let success = format!("{:?}", ExitCode::SUCCESS);
        assert_eq!(format!("{:?}", keygen(&path, false)), success);

        // The key on disk is the one that was announced, and it loads.
        let loaded = botzr_aegis_audit::load_signing_key(&path).expect("generated key loads");
        assert_ne!(
            loaded.public_key(),
            botzr_aegis_audit::insecure_dev_key().public_key(),
            "keygen must not hand back the dev key"
        );

        // A second keygen without --force refuses rather than replacing it.
        let failure = format!("{:?}", ExitCode::from(1));
        assert_eq!(format!("{:?}", keygen(&path, false)), failure);
        assert_eq!(
            botzr_aegis_audit::load_signing_key(&path)
                .unwrap()
                .public_key(),
            loaded.public_key()
        );
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
                audit: None,
                signing_key: None,
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
            "--signing-key",
            "--out",
            "--force",
            "--confine",
            "--allow-read",
            "--allow-write",
            "--allow-net",
            "--best-effort",
        ] {
            assert!(usage.contains(flag), "usage missing {flag}");
        }
        for command in ["verify", "recheck", "keygen", "wrap"] {
            assert!(
                usage.contains(command),
                "usage missing the {command} command"
            );
        }
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

    /// `--policy` is required and the record path is positional, so the two
    /// cannot be swapped by accident.
    #[test]
    fn parse_recheck_requires_a_policy_and_a_path() {
        match parse_args(&sv(&[
            "aegis",
            "recheck",
            "--policy",
            "p.yaml",
            "session.jsonl",
        ]))
        .unwrap()
        {
            Command::Recheck { policy, path } => {
                assert_eq!(policy, PathBuf::from("p.yaml"));
                assert_eq!(path, PathBuf::from("session.jsonl"));
            }
            other => panic!("expected Recheck, got {other:?}"),
        }
        // Flag order does not matter.
        assert_eq!(
            parse_args(&sv(&[
                "aegis",
                "recheck",
                "session.jsonl",
                "--policy",
                "p.yaml"
            ]))
            .unwrap(),
            Command::Recheck {
                policy: PathBuf::from("p.yaml"),
                path: PathBuf::from("session.jsonl"),
            }
        );
        // Any extension, for `verify`'s reason (AILAB-623).
        for path in ["session.log", "session", "session.jsonl", "/var/log/a.b.c"] {
            match parse_args(&sv(&["aegis", "recheck", "--policy", "p.yaml", path])).unwrap() {
                Command::Recheck { path: parsed, .. } => assert_eq!(parsed, PathBuf::from(path)),
                other => panic!("expected Recheck, got {other:?}"),
            }
        }
    }

    #[test]
    fn parse_recheck_usage_errors() {
        for args in [
            sv(&["aegis", "recheck", "--help"]),
            sv(&["aegis", "recheck", "-h"]),
        ] {
            assert_eq!(parse_args(&args).unwrap(), Command::Help);
        }
        // LOAD-BEARING: no allow-all default. A diff against a policy nobody
        // named would report every recorded denial as `newly_allowed`.
        assert!(parse_args(&sv(&["aegis", "recheck", "session.jsonl"]))
            .unwrap_err()
            .contains("--policy"));
        assert!(parse_args(&sv(&["aegis", "recheck", "--policy", "p.yaml"]))
            .unwrap_err()
            .contains("requires <PATH>"));
        assert!(parse_args(&sv(&["aegis", "recheck", "--policy"]))
            .unwrap_err()
            .contains("needs a value"));
        assert!(parse_args(&sv(&[
            "aegis", "recheck", "--policy", "p.yaml", "a.log", "b.log"
        ]))
        .unwrap_err()
        .contains("one PATH"));
        assert!(parse_args(&sv(&["aegis", "recheck", "--bogus", "a.log"]))
            .unwrap_err()
            .contains("unknown flag"));
        // `recheck` never takes a signing key: it checks no signatures.
        assert!(parse_args(&sv(&[
            "aegis",
            "recheck",
            "--policy",
            "p.yaml",
            "--signing-key",
            "k.key",
            "a.log"
        ]))
        .unwrap_err()
        .contains("unknown flag"));
    }

    /// The four exit codes are API here too, so `--help` has to name them.
    #[test]
    fn usage_text_names_the_recheck_exit_codes() {
        let usage = usage_text();
        for code in [
            "0  every call unchanged",
            "1  a call is newly blocked",
            "2  could not read the policy",
            "3  indeterminate",
        ] {
            assert!(usage.contains(code), "usage missing exit code line {code}");
        }
    }

    /// LOAD-BEARING: `--` ends *wrap's* parsing. The child is a foreign program
    /// whose flags Aegis does not own, so a `--help` or an `--audit` after the
    /// separator belongs to it — otherwise wrap cannot interpose on any server
    /// whose CLI happens to overlap with this one.
    #[test]
    fn parse_wrap_takes_everything_after_the_separator_verbatim() {
        match parse_args(&sv(&[
            "aegis",
            "wrap",
            "--audit",
            "a.jsonl",
            "--signing-key",
            "k.key",
            "--",
            "npx",
            "-y",
            "some-server",
            "--help",
            "--audit",
            "childs-own.jsonl",
        ]))
        .unwrap()
        {
            Command::Wrap(w) => {
                assert_eq!(w.audit, PathBuf::from("a.jsonl"));
                assert_eq!(w.signing_key, PathBuf::from("k.key"));
                assert_eq!(
                    w.child_argv,
                    sv(&[
                        "npx",
                        "-y",
                        "some-server",
                        "--help",
                        "--audit",
                        "childs-own.jsonl"
                    ]),
                    "the child's argv must survive byte for byte"
                );
            }
            other => panic!("expected Wrap, got {other:?}"),
        }

        // Flag order does not matter, and a lone program is a complete argv.
        match parse_args(&sv(&[
            "aegis",
            "wrap",
            "--signing-key",
            "k.key",
            "--audit",
            "a.jsonl",
            "--",
            "some-server",
        ]))
        .unwrap()
        {
            Command::Wrap(w) => assert_eq!(w.child_argv, sv(&["some-server"])),
            other => panic!("expected Wrap, got {other:?}"),
        }
    }

    #[test]
    fn parse_wrap_usage_errors() {
        // Help *before* the separator is still wrap's own.
        for args in [
            sv(&["aegis", "wrap", "--help"]),
            sv(&["aegis", "wrap", "-h"]),
        ] {
            assert_eq!(parse_args(&args).unwrap(), Command::Help);
        }

        // LOAD-BEARING (AILAB-620): no temp-sink mode. An interposer's only
        // product is its record, so both paths are required rather than
        // defaulted.
        assert!(parse_args(&sv(&["aegis", "wrap", "--", "cat"]))
            .unwrap_err()
            .contains("--audit"));
        assert!(
            parse_args(&sv(&["aegis", "wrap", "--audit", "a.jsonl", "--", "cat"]))
                .unwrap_err()
                .contains("--signing-key")
        );
        assert!(parse_args(&sv(&[
            "aegis",
            "wrap",
            "--signing-key",
            "k.key",
            "--",
            "cat"
        ]))
        .unwrap_err()
        .contains("--audit"));

        // A child command is not optional — whether the separator is missing…
        assert!(parse_args(&sv(&[
            "aegis",
            "wrap",
            "--audit",
            "a.jsonl",
            "--signing-key",
            "k.key"
        ]))
        .unwrap_err()
        .contains("child command"));
        // …or present with nothing after it.
        assert!(parse_args(&sv(&[
            "aegis",
            "wrap",
            "--audit",
            "a.jsonl",
            "--signing-key",
            "k.key",
            "--"
        ]))
        .unwrap_err()
        .contains("child command"));

        // Missing values and unknown flags, as everywhere else.
        assert!(parse_args(&sv(&["aegis", "wrap", "--audit"]))
            .unwrap_err()
            .contains("needs a value"));
        assert!(parse_args(&sv(&["aegis", "wrap", "--signing-key"]))
            .unwrap_err()
            .contains("needs a value"));
        assert!(parse_args(&sv(&["aegis", "wrap", "--bogus", "--", "cat"]))
            .unwrap_err()
            .contains("unknown flag"));

        // A forgotten `--` names the missing separator rather than blaming the
        // child program for being an unknown flag.
        assert!(parse_args(&sv(&["aegis", "wrap", "npx", "some-server"]))
            .unwrap_err()
            .contains("after `--`"));

        // `--allow-*` without `--confine` is a usage error, not a silent no-op.
        let err = parse_args(&sv(&[
            "aegis",
            "wrap",
            "--audit",
            "a.jsonl",
            "--signing-key",
            "k.key",
            "--allow-read",
            "/tmp",
            "--",
            "cat",
        ]))
        .unwrap_err();
        assert!(err.contains("--confine"), "{err}");
    }

    #[test]
    fn parse_wrap_confine_flags() {
        match parse_args(&sv(&[
            "aegis",
            "wrap",
            "--audit",
            "a.jsonl",
            "--signing-key",
            "k.key",
            "--confine",
            "--allow-read",
            "/tmp/r",
            "--allow-write",
            "/tmp/w",
            "--allow-net",
            "example.com:443",
            "--best-effort",
            "--",
            "npx",
            "some-server",
        ]))
        .unwrap()
        {
            Command::Wrap(w) => {
                assert!(w.confine);
                assert!(w.best_effort);
                assert_eq!(w.allow_read, vec![PathBuf::from("/tmp/r")]);
                assert_eq!(w.allow_write, vec![PathBuf::from("/tmp/w")]);
                assert_eq!(w.allow_net, vec![("example.com".into(), 443)]);
                assert_eq!(w.child_argv, sv(&["npx", "some-server"]));
            }
            other => panic!("expected Wrap, got {other:?}"),
        }

        // `--confine` with no `--allow-*` is legal (deny everything).
        match parse_args(&sv(&[
            "aegis",
            "wrap",
            "--audit",
            "a.jsonl",
            "--signing-key",
            "k.key",
            "--confine",
            "--",
            "cat",
        ]))
        .unwrap()
        {
            Command::Wrap(w) => {
                assert!(w.confine);
                assert!(w.allow_read.is_empty());
                assert!(w.allow_net.is_empty());
            }
            other => panic!("expected Wrap, got {other:?}"),
        }
    }

    #[test]
    fn parse_confine_exec_is_first_and_hidden_from_usage() {
        match parse_args(&sv(&["aegis", "__confine-exec", "--", "/bin/true"])).unwrap() {
            Command::ConfineExec { child_argv } => {
                assert_eq!(child_argv, sv(&["/bin/true"]))
            }
            other => panic!("expected ConfineExec, got {other:?}"),
        }
        assert!(
            !usage_text().contains("__confine-exec"),
            "internal re-exec target must stay out of usage_text"
        );
        assert!(
            !usage_text().contains("does not confine"),
            "old absolute claim must be gone"
        );
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
                    audit: None,
                    signing_key: None,
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
                    signing_key: None,
                })
            ),
            failure
        );
        // A key that will not load fails the ready path too — no fallback key,
        // so no Session opens (AILAB-620).
        assert_eq!(
            format!(
                "{:?}",
                dispatch(Command::Ready {
                    policy: None,
                    audit: Some(PathBuf::from("/nonexistent/audit.jsonl")),
                    signing_key: Some(PathBuf::from("/nonexistent/signing.key")),
                })
            ),
            failure
        );
    }
}
