//! `aegis wrap` — the CLI surface over the stdio interposer in
//! `botzr-aegis-wrap` (AILAB-625).
//!
//! **Argument shim and exit mapping only.** The relay — the reader threads, the
//! event loop, the audit sessions, the bounded reap — lives in
//! [`botzr_aegis_wrap::run_wrap`] and stays there. A second pump in the CLI
//! would be a second thing to keep deadlock-free, and the one in the library is
//! the one the relay tests drive against a real child process.
//!
//! Wrap's only *always-on* station is AUDIT. `--confine` (AILAB-628) is a grant
//! source: flags → `ToolManifest` → resolver → `ConfinementProfile`. Going
//! through the resolver rather than constructing a grant directly is the point
//! of one authority source.
//!
//! **`--policy` is where POLICY enters a wrap session (AILAB-793).** The engine
//! lives here, not in `botzr-aegis-wrap`: that crate's graph is audit, core and
//! confine, and it does not grow a `PolicyEngine` (ADR-0015 *Consequences*,
//! CLAUDE.md *Enforcement scope*). This module implements wrap's
//! [`botzr_aegis_wrap::CallGate`] over `PolicyEngine::evaluate`, and wrap asks
//! it. Presence of the flag is the whole opt-in — there is no `--enforce`.
//!
//! The exit code is the child's, passed through. An operator who scripts
//! `aegis wrap -- some-server` gets the same code they would have got running
//! `some-server` directly, so putting Aegis in the middle does not rewrite the
//! meaning of a failure. Exit 1 is reserved for wrap itself failing to start or
//! to record — which, since a wrap session that cannot record is a session with
//! no reason to exist, is a refusal rather than a degraded run.

use std::process::ExitCode;
use std::sync::Arc;

use botzr_aegis_capability::{
    CapabilityResolver, FsNeeds, HttpNeed, NetNeeds, PathNeed, ToolInfo, ToolKind, ToolManifest,
};
use botzr_aegis_confine::ConfinementProfile;
use botzr_aegis_core::{CapabilityOutcome, ToolId};
use botzr_aegis_policy::{PolicyEngine, PolicyRequest};
use botzr_aegis_wrap::{run_wrap, CallGate, GateVerdict, WrapConfig, WrapMode};

use crate::WrapArgs;

pub(crate) fn run(args: &WrapArgs) -> ExitCode {
    let mode = match build_mode(args) {
        Ok(mode) => mode,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::from(1);
        }
    };

    let config = WrapConfig {
        child_argv: args.child_argv.clone(),
        audit_path: args.audit.clone(),
        signing_key_path: args.signing_key.clone(),
        mode,
    };

    match run_wrap(&config) {
        Ok(code) => ExitCode::from(code),
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::from(1)
        }
    }
}

/// Flags → the one enum that says what this session does.
///
/// Three flag states, three variants, and no pair of `Option`s to keep
/// consistent: `--policy` alone enforces without confining, `--confine` alone
/// confines without evaluating, and together they do both.
///
/// **The policy file is loaded here, before `run_wrap`.** A `FlagSpec` cannot
/// stat a path, so a missing or unparseable YAML is a start error rather than a
/// parse error — and it must be a start error that happens *before* the child
/// is spawned. A wrap process that started a third-party server and only then
/// discovered it could not evaluate policy would have already handed that
/// server the operator's authority, and has nothing to say about the calls it
/// then fails to gate.
fn build_mode(args: &WrapArgs) -> Result<WrapMode, String> {
    let confinement = build_confinement(args)?;
    let Some(policy) = args.policy.as_deref() else {
        return Ok(match confinement {
            Some(profile) => WrapMode::Confine(profile),
            None => WrapMode::Record,
        });
    };
    let engine = PolicyEngine::load(policy)
        .map_err(|e| format!("could not load policy `{}`: {e}", policy.display()))?;
    Ok(WrapMode::Enforce {
        gate: Arc::new(EngineGate { engine }),
        confinement,
    })
}

/// The policy engine, behind wrap's [`CallGate`] seam.
///
/// The whole of the wrap → policy coupling, and it points this way round on
/// purpose: the CLI already depends on `botzr-aegis-policy` (for `run` and
/// `recheck`), and wrap does not. Reversing it would put an engine, a rate
/// limiter and a YAML parser inside a crate whose stated graph is three.
struct EngineGate {
    engine: PolicyEngine,
}

impl CallGate for EngineGate {
    fn decide(&self, tool_id: &ToolId) -> GateVerdict {
        // `for_tool`, not a request with axes: wrap has no caller role to
        // assert and does not read `params.arguments`, so tool identity is
        // genuinely all it knows. Asserting a role here would feed a fabricated
        // matcher input to the engine and then sign it into the record.
        let request = PolicyRequest::for_tool(tool_id);
        // `evaluate`, not `preview`: this is the live path, and it is what
        // bumps the rate limiter. A `preview` here would let a rate-limited
        // tool be called without ever advancing its counter.
        let decision = self.engine.evaluate(&request);
        GateVerdict {
            // The set's **content** hash, not `active_digest` — that one is
            // FNV-1a over YAML text and self-documented as not a security
            // digest. This is the value a record names so the verdict can be
            // rechecked against the rules that produced it.
            policy_set_hash: self.engine.active_content_hash(),
            action: decision.action,
            matched_rule: decision.matched_rule,
        }
    }
}

/// `--confine` with no `--allow-*` is legal and means deny everything.
fn build_confinement(args: &WrapArgs) -> Result<Option<ConfinementProfile>, String> {
    if !args.confine {
        return Ok(None);
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = args;
        return Err("confinement (--confine) is only implemented on Linux".into());
    }

    #[cfg(target_os = "linux")]
    {
        let base = std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("."));
        // A confined native child is neither Model A (Wasm) nor Model B (host
        // function). ToolKind has no third variant; widening it would quietly
        // reclassify the trust boundary (docs/trust-models.md). Host is the
        // closer of the two: the effect runs outside wasmtime.
        let mut manifest = ToolManifest::new(
            ToolInfo {
                id: ToolId::new("wrap-child"),
                version: "0.0.0".into(),
                kind: ToolKind::Host,
            },
            base,
        );

        if !args.allow_read.is_empty() || !args.allow_write.is_empty() {
            let fs = FsNeeds {
                read: args
                    .allow_read
                    .iter()
                    .map(|p| PathNeed::recursive(p.to_string_lossy().into_owned()))
                    .collect(),
                write: args
                    .allow_write
                    .iter()
                    .map(|p| PathNeed::recursive(p.to_string_lossy().into_owned()))
                    .collect(),
            };
            manifest = manifest.with_fs(fs);
        }

        if !args.allow_net.is_empty() {
            let net = NetNeeds {
                http: args
                    .allow_net
                    .iter()
                    .map(|(host, port)| HttpNeed {
                        host: host.clone(),
                        ports: vec![*port],
                        // Mint requires a method. Confinement does not filter
                        // HTTP methods; a non-empty net grant means "do not
                        // deny network syscalls".
                        methods: vec!["GET".into()],
                    })
                    .collect(),
            };
            manifest = manifest.with_net(net);
        }

        match CapabilityResolver::new().resolve_manifest(&manifest) {
            // `with_exec_support` is applied to the *profile*, after the grant,
            // deliberately. The loader paths are not authority the tool asked
            // for and must never enter the manifest — a need is a claim the
            // resolver mints from, and minting them would make the widening
            // look like something the grant justified.
            CapabilityOutcome::Granted { grant } => Ok(Some(
                ConfinementProfile::from_grant(&grant)
                    .with_best_effort(args.best_effort)
                    .with_exec_support(args.allow_exec_support),
            )),
            CapabilityOutcome::Denied { reason, .. } => {
                Err(format!("could not mint a confinement grant: {reason}"))
            }
        }
    }
}
