//! `aegis wrap` — the CLI surface over the stdio interposer in
//! `botzr-aegis-wrap` (AILAB-625).
//!
//! **Argument shim and exit mapping only.** The relay — the reader threads, the
//! event loop, the audit sessions, the bounded reap — lives in
//! [`botzr_aegis_wrap::run_wrap`] and stays there. A second pump in the CLI
//! would be a second thing to keep deadlock-free, and the one in the library is
//! the one the relay tests drive against a real child process.
//!
//! Wrap's only *always-on* station is AUDIT. `--confine` (AILAB-628) is the
//! grant source this ticket introduces: flags → `ToolManifest` → resolver →
//! `ConfinementProfile`. Going through the resolver rather than constructing a
//! grant directly is the point of one authority source.
//!
//! The exit code is the child's, passed through. An operator who scripts
//! `aegis wrap -- some-server` gets the same code they would have got running
//! `some-server` directly, so putting Aegis in the middle does not rewrite the
//! meaning of a failure. Exit 1 is reserved for wrap itself failing to start or
//! to record — which, since a wrap session that cannot record is a session with
//! no reason to exist, is a refusal rather than a degraded run.

use std::process::ExitCode;

use botzr_aegis_capability::{
    CapabilityResolver, FsNeeds, HttpNeed, NetNeeds, PathNeed, ToolInfo, ToolKind, ToolManifest,
};
use botzr_aegis_confine::ConfinementProfile;
use botzr_aegis_core::{CapabilityOutcome, ToolId};
use botzr_aegis_wrap::{run_wrap, WrapConfig};

use crate::WrapArgs;

pub(crate) fn run(args: &WrapArgs) -> ExitCode {
    let confinement = match build_confinement(args) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::from(1);
        }
    };

    let config = WrapConfig {
        child_argv: args.child_argv.clone(),
        audit_path: args.audit.clone(),
        signing_key_path: args.signing_key.clone(),
        confinement,
    };

    match run_wrap(&config) {
        Ok(code) => ExitCode::from(code),
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::from(1)
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
