# search_nodes overhead (AEG-20 / D5)

**Harness:** `dreamd-poc` JSONL substring stub (not Tantivy)  
**Date:** 2026-07-10  
**Command:** `cargo bench -p dreamd-poc --bench search_overhead`

| Variant | Median time | Notes |
|---------|-------------|-------|
| `bare` | **~5.5 µs** | Direct JSONL scan, no Aegis |
| `aegis_wrapped` | **~22 ms** | POLICY + CAPABILITY + audit JSONL emit per call |

**Interpretation:** Wrapped overhead is dominated by **audit sink I/O** (temp JSONL append + fsync path), not policy eval (<100 µs target). Policy+capability alone is sub-millisecond per `hot_path` benches.

**D5 gate (lock for Stage 1):** **Mutating-only full wrap** (`append_node`, `dream`); `search_nodes` uses policy allow + **lightweight audit** or sampled audit in production. Re-benchmark with real dreamd Tantivy recall + production audit batching before `v0.1.0`.
