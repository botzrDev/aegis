//! Authority choke point for Aegis-owned Model B effects.
//!
//! Structural grant enforcement applies only to methods on [`HostEffectContext`].
//! Callers that bypass it via the raw [`execute_host_call`](crate::Runtime::execute_host_call)
//! closure escape hatch are responsible for their own checks (research only).

use std::path::{Path, PathBuf};

use botzr_aegis_core::http_get_allowed;
use cap_std::ambient_authority;

use crate::HostEffectError;

/// Maximum log message size enforced host-side (bytes).
const MAX_LOG_MESSAGE_BYTES: usize = 4096;

/// A cap-std directory handle paired with its resolved root path.
struct FsDir {
    root: PathBuf,
    dir: cap_std::fs::Dir,
}

/// Authority choke point for Aegis-owned Model B effects.
///
/// Structural grant enforcement applies only to methods on this type.
/// Callers that bypass it via the raw `execute_host_call` closure escape
/// hatch are responsible for their own checks (research only).
pub struct HostEffectContext<'a> {
    grant: &'a botzr_aegis_core::CapabilityGrant,
    read_dirs: Vec<FsDir>,
    write_dirs: Vec<FsDir>,
}

/// Stub HTTP response returned by [`HostEffectContext::http_get`] in the v1
/// slice (no real network I/O).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpStubResponse {
    pub status: u16,
    pub body: String,
}

/// Log severity level for [`HostEffectContext::log_emit`].
pub enum LogLevel {
    Debug,
    Info,
    Warn,
    Error,
}

/// Open a cap-std `Dir` per grant path, skipping paths that cannot be opened.
fn open_dirs(paths: &[String]) -> Vec<FsDir> {
    paths
        .iter()
        .filter_map(|p| {
            let path = PathBuf::from(p);
            // Ambient authority is used exactly once, here, to turn a grant
            // path into a preopened Dir. Every later FS effect is relative to
            // one of these handles — cap-std, never `path.starts_with`.
            cap_std::fs::Dir::open_ambient_dir(&path, ambient_authority())
                .ok()
                .map(|dir| FsDir { root: path, dir })
        })
        .collect()
}

/// Candidate (preopen, relative path) pairs for `path`.
///
/// Absolute paths must fall under a granted root. Relative paths are
/// preopen-relative (cap-std style) and are tried against every granted root.
/// An empty result means no granted root can serve the path — fail closed.
fn candidates<'d>(dirs: &'d [FsDir], path: &Path) -> Vec<(&'d FsDir, PathBuf)> {
    dirs.iter()
        .filter_map(|entry| {
            if path.is_absolute() {
                path.strip_prefix(&entry.root)
                    .ok()
                    .map(|rel| (entry, rel.to_path_buf()))
            } else {
                Some((entry, path.to_path_buf()))
            }
        })
        .collect()
}

/// Map a cap-std I/O error onto the typed host-effect surface.
///
/// cap-std reports an attempt to escape a preopen as `PermissionDenied`; that
/// is a grant denial, not an I/O failure, so it fails closed as `GrantDenied`.
fn map_fs_error(op: &str, path: &Path, err: std::io::Error) -> HostEffectError {
    if err.kind() == std::io::ErrorKind::PermissionDenied {
        HostEffectError::GrantDenied {
            reason: format!("{op} denied: {} escapes grant root", path.display()),
        }
    } else {
        HostEffectError::Failed {
            reason: format!("{op} {}: {err}", path.display()),
        }
    }
}

impl<'a> HostEffectContext<'a> {
    /// Build a context from a minted grant.
    ///
    /// Opens cap-std `Dir` handles for each grant FS path. Grant paths are
    /// already canonicalized (absolute) by the capability resolver at mint
    /// time. If a grant path directory does not exist, it is silently skipped
    /// — the corresponding FS operation will fail closed with `GrantDenied`.
    pub fn new(grant: &'a botzr_aegis_core::CapabilityGrant) -> Self {
        let (read_dirs, write_dirs) = match grant.fs.as_ref() {
            Some(fs) => (open_dirs(&fs.read_paths), open_dirs(&fs.write_paths)),
            None => (Vec::new(), Vec::new()),
        };

        Self {
            grant,
            read_dirs,
            write_dirs,
        }
    }

    /// Issue an HTTP GET after checking the grant's NetGrant.
    ///
    /// v1 slice: the grant check is enforced; the effect is still a stub
    /// ("no network in v1"). Returns a stub response on success.
    pub fn http_get(&self, url: &str) -> Result<HttpStubResponse, HostEffectError> {
        http_get_allowed(self.grant, url)
            .map_err(|reason| HostEffectError::GrantDenied { reason })?;
        // v1: no real network — grant check passed, effect is stubbed.
        Ok(HttpStubResponse {
            status: 200,
            body: "stub: no network in v1 slice".into(),
        })
    }

    /// Emit a log message after checking the size gate.
    ///
    /// v1 slice (product decision, AEG-43): there is **no log grant axis**. Any
    /// tool that got a grant at all may emit; the only enforcement is this
    /// message size cap, matching the sandbox `log.emit` host import. Requiring
    /// an explicit axis is deferred future work — until then this method is a
    /// size gate, not an authority gate.
    pub fn log_emit(&self, _level: LogLevel, message: &str) -> Result<(), HostEffectError> {
        if message.len() > MAX_LOG_MESSAGE_BYTES {
            return Err(HostEffectError::GrantDenied {
                reason: format!("log denied: message exceeds {MAX_LOG_MESSAGE_BYTES} bytes"),
            });
        }
        // v1: no sink wired — any granted tool may emit.
        Ok(())
    }

    /// Open a file for reading under a grant-allowed read path.
    ///
    /// `path` is either absolute (and must fall under a granted read root) or
    /// relative to one (preopen-style). Returns `GrantDenied` when no granted
    /// root can serve it, or when cap-std rejects the path as escaping its
    /// preopen. Returns `Failed` when the file cannot be opened (e.g. missing).
    pub fn open_read(&self, path: &Path) -> Result<cap_std::fs::File, HostEffectError> {
        let candidates = candidates(&self.read_dirs, path);
        if candidates.is_empty() {
            return Err(HostEffectError::GrantDenied {
                reason: format!("read denied: {} outside grant", path.display()),
            });
        }

        let mut last = None;
        for (entry, rel) in candidates {
            match entry.dir.open(&rel) {
                Ok(file) => return Ok(file),
                Err(err) => last = Some(err),
            }
        }
        Err(map_fs_error(
            "read",
            path,
            last.expect("candidates non-empty"),
        ))
    }

    /// Open a file for appending under a grant-allowed write path.
    ///
    /// Creates the file — and any missing parent directories *inside* the
    /// preopen — if they do not exist. `path` follows the same absolute or
    /// preopen-relative rule as [`Self::open_read`]; a relative path resolves
    /// against the first granted write root that accepts it. Returns
    /// `GrantDenied` when no granted root can serve the path.
    pub fn open_write_append(&self, path: &Path) -> Result<cap_std::fs::File, HostEffectError> {
        let candidates = candidates(&self.write_dirs, path);
        if candidates.is_empty() {
            return Err(HostEffectError::GrantDenied {
                reason: format!("write denied: {} outside grant", path.display()),
            });
        }

        let mut options = cap_std::fs::OpenOptions::new();
        options.create(true).append(true);

        let mut last = None;
        for (entry, rel) in candidates {
            // Parent creation goes through the same Dir handle — a `..` that
            // would escape the preopen fails here and again on open_with.
            if let Some(parent) = rel.parent().filter(|p| !p.as_os_str().is_empty()) {
                let _ = entry.dir.create_dir_all(parent);
            }
            match entry.dir.open_with(&rel, &options) {
                Ok(file) => return Ok(file),
                Err(err) => last = Some(err),
            }
        }
        Err(map_fs_error(
            "write",
            path,
            last.expect("candidates non-empty"),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use botzr_aegis_core::{CapabilityGrant, FsGrant, HttpGrant, NetGrant, ToolId};

    fn grant(fs: Option<FsGrant>, net: Option<NetGrant>) -> CapabilityGrant {
        CapabilityGrant {
            grant_id: "g1".into(),
            tool_id: ToolId::new("ctx-tool"),
            fs,
            net,
            max_memory_bytes: 1 << 20,
            max_wall_ms: 1_000,
            max_output_bytes: 1 << 20,
        }
    }

    fn allow_get(host: &str) -> NetGrant {
        NetGrant {
            http: vec![HttpGrant {
                host: host.into(),
                ports: vec![443],
                methods: vec!["GET".into()],
            }],
        }
    }

    #[test]
    fn http_get_without_net_grant_denies() {
        // Adversarial: the net axis is absent, so the context must refuse
        // before any effect — not stub a 200 back.
        let grant = grant(None, None);
        let ctx = HostEffectContext::new(&grant);
        let err = ctx
            .http_get("https://api.example.com/data")
            .expect_err("no net grant must deny");
        assert_eq!(
            err,
            HostEffectError::GrantDenied {
                reason: "network denied: no net grant".into()
            }
        );
    }

    #[test]
    fn http_get_host_outside_allowlist_denies() {
        let grant = grant(None, Some(allow_get("api.example.com")));
        let ctx = HostEffectContext::new(&grant);
        let err = ctx
            .http_get("https://evil.example.com/exfil")
            .expect_err("host outside the allow-list must deny");
        assert!(
            matches!(&err, HostEffectError::GrantDenied { reason } if reason.contains("not in grant")),
            "{err}"
        );
    }

    #[test]
    fn http_get_within_grant_passes_check_then_stubs() {
        // Proves the denial above is the grant gate, not a blanket "http off".
        let grant = grant(None, Some(allow_get("api.example.com")));
        let ctx = HostEffectContext::new(&grant);
        let res = ctx
            .http_get("https://api.example.com/data")
            .expect("allow-listed host clears the grant check");
        assert_eq!(res.status, 200);
        assert!(res.body.contains("no network in v1"), "{}", res.body);
    }

    #[test]
    fn open_write_without_write_paths_denies() {
        // Adversarial: a read-only FS grant must not yield a writable handle,
        // even for a path inside the granted read root.
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().to_string_lossy().into_owned();
        let grant = grant(
            Some(FsGrant {
                read_paths: vec![root],
                write_paths: vec![],
            }),
            None,
        );
        let ctx = HostEffectContext::new(&grant);
        let err = ctx
            .open_write_append(Path::new("notes.jsonl"))
            .expect_err("read-only grant must deny writes");
        assert!(
            matches!(&err, HostEffectError::GrantDenied { reason } if reason.contains("write denied")),
            "{err}"
        );
        assert!(!dir.path().join("notes.jsonl").exists());
    }

    #[test]
    fn open_read_without_fs_grant_denies() {
        // No fs axis at all — no preopen exists, so every read fails closed.
        let grant = grant(None, None);
        let ctx = HostEffectContext::new(&grant);
        let err = ctx
            .open_read(Path::new("/etc/passwd"))
            .expect_err("no fs grant must deny");
        assert!(
            matches!(&err, HostEffectError::GrantDenied { reason } if reason.contains("read denied")),
            "{err}"
        );
    }

    #[test]
    fn open_read_absolute_path_outside_grant_denies() {
        let dir = tempfile::tempdir().unwrap();
        let grant = grant(
            Some(FsGrant {
                read_paths: vec![dir.path().to_string_lossy().into_owned()],
                write_paths: vec![],
            }),
            None,
        );
        let ctx = HostEffectContext::new(&grant);
        let err = ctx
            .open_read(Path::new("/etc/passwd"))
            .expect_err("absolute path outside every preopen must deny");
        assert!(
            matches!(&err, HostEffectError::GrantDenied { reason } if reason.contains("outside grant")),
            "{err}"
        );
    }

    #[test]
    fn open_read_escaping_preopen_denies() {
        // cap-std refuses `..` traversal out of the preopen; the context maps
        // that to GrantDenied rather than a generic I/O failure.
        let dir = tempfile::tempdir().unwrap();
        let inner = dir.path().join("inner");
        std::fs::create_dir(&inner).unwrap();
        std::fs::write(dir.path().join("secret.txt"), b"top secret").unwrap();
        let grant = grant(
            Some(FsGrant {
                read_paths: vec![inner.to_string_lossy().into_owned()],
                write_paths: vec![],
            }),
            None,
        );
        let ctx = HostEffectContext::new(&grant);
        let err = ctx
            .open_read(Path::new("../secret.txt"))
            .expect_err("traversal out of the preopen must deny");
        assert!(
            matches!(&err, HostEffectError::GrantDenied { reason } if reason.contains("escapes grant root")),
            "{err}"
        );
    }

    #[test]
    fn open_write_append_within_grant_creates_missing_parents() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().to_string_lossy().into_owned();
        let grant = grant(
            Some(FsGrant {
                read_paths: vec![root.clone()],
                write_paths: vec![root],
            }),
            None,
        );
        let ctx = HostEffectContext::new(&grant);

        use std::io::Write;
        let mut file = ctx
            .open_write_append(Path::new("personal/notes.jsonl"))
            .expect("write inside the grant is allowed");
        writeln!(file, "hello").unwrap();
        drop(file);

        let written = std::fs::read_to_string(dir.path().join("personal/notes.jsonl")).unwrap();
        assert_eq!(written, "hello\n");
    }

    #[test]
    fn open_read_missing_file_is_failed_not_denied() {
        // dreamd relies on this split: a missing recall index is an empty
        // result, while a denied path is a hard error.
        let dir = tempfile::tempdir().unwrap();
        let grant = grant(
            Some(FsGrant {
                read_paths: vec![dir.path().to_string_lossy().into_owned()],
                write_paths: vec![],
            }),
            None,
        );
        let ctx = HostEffectContext::new(&grant);
        let err = ctx
            .open_read(Path::new("absent.jsonl"))
            .expect_err("missing file cannot be opened");
        assert!(matches!(err, HostEffectError::Failed { .. }), "{err}");
    }

    #[test]
    fn log_emit_is_size_gated_only_in_v1() {
        // Product decision (AEG-43): no log grant axis in v1 — a grant with no
        // fs and no net axis may still emit; only the size cap denies.
        let grant = grant(None, None);
        let ctx = HostEffectContext::new(&grant);
        assert!(ctx.log_emit(LogLevel::Info, "hello").is_ok());

        let oversize = "x".repeat(MAX_LOG_MESSAGE_BYTES + 1);
        let err = ctx
            .log_emit(LogLevel::Error, &oversize)
            .expect_err("oversize message must deny");
        assert!(
            matches!(&err, HostEffectError::GrantDenied { reason } if reason.contains("log denied")),
            "{err}"
        );
    }
}
