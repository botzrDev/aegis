# aegis-stress-suite

AILAB-602: proves the audit exactly-once contract under concurrency — ≥1,000
calls through one shared `Runtime` across every outcome class (success, policy
deny, pending approval, capability deny, guest trap, wall/memory caps, Model B
success, host panic), then asserts on the JSONL sink: one intent + one outcome
per call, gap-free `call-1..call-N` by set equality, frozen audit schema v1.

Soak locally with `AEGIS_STRESS_MULTIPLIER=10 cargo test -p aegis-stress-suite`
— the multiplier scales every class count (default `1` ≈ 1,100 calls).
