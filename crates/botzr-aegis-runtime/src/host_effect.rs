//! Authority choke point for Aegis-owned Model B effects.
//!
//! Structural grant enforcement applies only to methods on [`HostEffectContext`].
//! Callers that bypass it via the raw [`execute_host_call`](crate::Runtime::execute_host_call)
//! closure escape hatch are responsible for their own checks (research only).

use std::path::{Path, PathBuf};

use botzr_aegis_core::http_get_allowed;

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

impl<'a> HostEffectContext<'a> {
    /// Build a context from a minted grant.
    ///
    /// Opens cap-std `Dir` handles for each grant FS path. Grant paths are
    /// already canonicalized (absolute) by the capability resolver at mint
    /// time. If a grant path directory does not exist, it is silently skipped
    /// — the corresponding FS operation will fail closed with `GrantDenied`.
    pub fn new(grant: &'a botzr_aegis_core::CapabilityGrant) -> Self {
        let read_dirs = grant
            .fs
            .as_ref()
            .map(|fs| {
                fs.read_paths
                    .iter()
                    .filter_map(|p| {
                        let path = PathBuf::from(p);
                        cap_std::fs::Dir::open(&path)
                            .ok()
                            .map(|dir| FsDir { root: path, dir })
                    })
                    .collect()
            })
            .unwrap_or_default();

        let write_dirs = grant
            .fs
            .as_ref()
            .map(|fs| {
                fs.write_paths
                    .iter()
                    .filter_map(|p| {
                        let path = PathBuf::from(p);
                        cap_std::fs::Dir::open(&path)
                            .ok()
                            .map(|dir| FsDir { root: path, dir })
                    })
                    .collect()
            })
            .unwrap_or_default();

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
    /// v1 slice: any granted tool may emit; the only enforcement is a message
    /// size cap. No explicit grant axis is required (future work).
    pub fn log_emit(&self, _level: LogLevel, message: &str) -> Result<(), HostEffectError> {
        if message.len() > MAX_LOG_MESSAGE_BYTES {
            return Err(HostEffectError::GrantDenied {
                reason: format!("log message exceeds {MAX_LOG_MESSAGE_BYTES} bytes"),
            });
        }
        // v1: no sink wired — any granted tool may emit.
        Ok(())
    }

    /// Open a file for reading under a grant-allowed read path.
    ///
    /// Returns `GrantDenied` when `path` is outside every preopened Dir.
    /// Returns `Failed` when the file cannot be opened (e.g. not found).
    pub fn open_read(&self, path: &Path) -> Result<cap_std::fs::File, HostEffectError> {
        for entry in &self.read_dirs {
            if let Ok(rel) = path.strip_prefix(&entry.root) {
                return entry.dir.read(rel).map_err(|e| HostEffectError::Failed {
                    reason: format!("read {}: {e}", rel.display()),
                });
            }
        }
        Err(HostEffectError::GrantDenied {
            reason: format!("read denied: path outside grant"),
        })
    }

    /// Open a file for appending under a grant-allowed write path.
    ///
    /// Creates the file if it does not exist. Returns `GrantDenied` when `path`
    /// is outside every preopened Dir.
    pub fn open_write_append(&self, path: &Path) -> Result<cap_std::fs::File, HostEffectError> {
        for entry in &self.write_dirs {
            if let Ok(rel) = path.strip_prefix(&entry.root) {
                return cap_std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(&entry.dir, rel)
                    .map_err(|e| HostEffectError::Failed {
                        reason: format!("write {}: {e}", rel.display()),
                    });
            }
        }
        Err(HostEffectError::GrantDenied {
            reason: "write denied: path outside grant".into(),
        })
    }
}
