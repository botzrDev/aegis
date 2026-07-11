//! Native reference implementation of the Stage 2 path-scan detector.
//!
//! Pure host Rust (no wasmtime). This reimplements the **same** scan semantics
//! as the wasip2 guest in `tests/fixtures/path-detector/src/lib.rs`, from
//! scratch — the scorecard asserts `scan_native` findings == the guest's findings
//! on a shared fixture tree (design doc D10 equivalence). uveddi is a functional spec
//! only — no uveddi code or dependency is used here (do not import it).

use std::path::Path;

use serde_json::{json, Value};

/// One scanned file. `path` is relative to the scan root, `/`-separated.
struct Finding {
    path: String,
    size: u64,
}

/// Walk `root/<scan_root>` recursively (files only, stable sort by relative
/// path) and return `{"findings":[{"path","size"},...]}`. Mirrors the guest's
/// `scan`: `root` is the host directory the sandbox preopens read-only at
/// `/ro0`, and `scan_root` selects the subtree to walk.
pub fn scan_native(root: &Path, scan_root: &str) -> Value {
    let base = root.join(scan_root);
    let mut findings: Vec<Finding> = Vec::new();
    walk(&base, "", &mut findings);
    findings.sort_by(|a, b| a.path.cmp(&b.path));

    let items: Vec<Value> = findings
        .iter()
        .map(|f| json!({ "path": f.path, "size": f.size }))
        .collect();
    json!({ "findings": items })
}

/// Recurse into `dir`, accumulating a `/`-separated relative path in `prefix`.
/// Directory-read or stat errors yield no findings for that entry (the guest
/// does the same, so an unreadable tree stays equivalent).
fn walk(dir: &Path, prefix: &str, out: &mut Vec<Finding>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        let rel = if prefix.is_empty() {
            name
        } else {
            format!("{prefix}/{name}")
        };
        let Ok(meta) = entry.metadata() else {
            continue;
        };
        if meta.is_dir() {
            walk(&entry.path(), &rel, out);
        } else if meta.is_file() {
            out.push(Finding {
                path: rel,
                size: meta.len(),
            });
        }
    }
}
