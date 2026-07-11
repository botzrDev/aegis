//! D5 benchmark — `search_nodes` with vs without Aegis wrapper.
//!
//! Run: `cargo bench -p dreamd-poc --bench search_overhead`

use std::hint::black_box;
use std::path::PathBuf;

use botzr_aegis_core::ToolId;
use botzr_aegis_policy::PolicyRequest;
use botzr_aegis_runtime::{sha256_hex, HostCallRequest, Runtime};
use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use dreamd_poc::{
    init_agent_store, policy_engine, register_dreamd_tools, search_nodes_bare, search_nodes_effect,
    AppendInput, AppendZone, CAP_FS_EPISODIC, TOOL_APPEND, TOOL_SEARCH,
};
use serde_json::json;
use tempfile::TempDir;

fn seed_store(dir: &TempDir) -> (Runtime, PathBuf, Vec<u8>) {
    init_agent_store(dir.path());
    let mut rt = Runtime::new().with_policy(policy_engine());
    register_dreamd_tools(rt.capabilities(), dir.path());
    let root = dir.path().to_path_buf();

    for i in 0..50 {
        let input = AppendInput {
            content: format!("learning entry {i} about rust async patterns and channels"),
            source_harness: "bench".into(),
            skill_action: "rust::async".into(),
            zone: AppendZone::Episodic,
        };
        let bytes = serde_json::to_vec(&input).unwrap();
        let tool = ToolId::new(TOOL_APPEND);
        rt.execute_host_call(
            HostCallRequest::new(
                tool.clone(),
                sha256_hex(&bytes),
                &bytes,
                PolicyRequest::for_tool(&tool).with_capability(CAP_FS_EPISODIC),
            ),
            |grant, input| dreamd_poc::append_node_effect(grant, &root, input),
        )
        .expect("seed append");
    }

    let query = json!({ "query": "rust async", "k": 5 });
    let query_bytes = serde_json::to_vec(&query).unwrap();
    (rt, root, query_bytes)
}

fn bench_search_overhead(c: &mut Criterion) {
    let dir = TempDir::new().expect("tempdir");
    let (rt, root, query_bytes) = seed_store(&dir);
    let tool = ToolId::new(TOOL_SEARCH);

    let mut group = c.benchmark_group("search_nodes");
    group.throughput(Throughput::Bytes(query_bytes.len() as u64));

    group.bench_function("bare", |b| {
        b.iter(|| black_box(search_nodes_bare(&root, black_box(&query_bytes))));
    });

    group.bench_function("aegis_wrapped", |b| {
        b.iter(|| {
            black_box(
                rt.execute_host_call(
                    HostCallRequest::new(
                        tool.clone(),
                        sha256_hex(&query_bytes),
                        black_box(&query_bytes),
                        PolicyRequest::for_tool(&tool),
                    ),
                    |grant, input| search_nodes_effect(grant, &root, input),
                )
                .expect("wrapped search"),
            )
        });
    });

    group.finish();
}

criterion_group!(benches, bench_search_overhead);
criterion_main!(benches);
