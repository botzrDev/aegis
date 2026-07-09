# Hot-path Criterion results (AEG-16 / OQ-15 T5)

## Hardware / OS

```
uname -a
Linux botzrDev 6.6.87.2-microsoft-standard-WSL2 #1 SMP PREEMPT_DYNAMIC Thu Jun  5 18:30:46 UTC 2025 x86_64 x86_64 x86_64 GNU/Linux

lscpu (selected):
Architecture:                         x86_64
Model name:                           AMD Ryzen AI 5 340 w/ Radeon 840M
CPU(s):                               4
Thread(s) per core:                   2
Core(s) per socket:                   2
Hypervisor vendor:                    Microsoft
Virtualization type:                  full

rustc -Vv:
rustc 1.96.0 (ac68faa20 2026-05-25)
host: x86_64-unknown-linux-gnu
```

**Environment notes:** WSL2 / Linux; Criterion 0.5.1; Gnuplot not installed (plotters backend). Date: 2026-07-09.

## Command

```bash
cargo bench -p botzr-aegis-policy -p botzr-aegis-capability -p botzr-aegis-runtime
```

## Summary vs targets

| Group | Median (approx.) | Target | Status |
|---|---|---|---|
| `policy_eval/allow_all` | **13.4 ns** | < 100 µs | **pass** |
| `policy_eval/multi_rule` | **31.8 ns** | < 100 µs | **pass** |
| `policy_eval/rate_limit` | **183 ns** | informational (mutex) | n/a |
| `capability_resolve/registered_tool` | **2.43 µs** | no hard gate | n/a |
| `hot_path/allow_all` | **2.67 µs** | (floor) | n/a |
| `hot_path/multi_rule` | **2.71 µs** | < 1 ms | **pass** |

Criterion reports `[lower median upper]` as time/op; medians above are the middle sample.

## Criterion text tables

```
capability_resolve/registered_tool
                        time:   [2.3959 µs 2.4329 µs 2.4751 µs]

policy_eval/allow_all   time:   [13.240 ns 13.408 ns 13.582 ns]
policy_eval/multi_rule  time:   [31.025 ns 31.775 ns 32.898 ns]
policy_eval/rate_limit  time:   [181.31 ns 182.74 ns 184.38 ns]

hot_path/allow_all      time:   [2.6091 µs 2.6727 µs 2.7417 µs]
hot_path/multi_rule     time:   [2.6453 µs 2.7136 µs 2.7872 µs]
```

## Notes

- Combined hot path is dominated by capability grant minting (~2.4 µs alone); policy eval is tens of nanoseconds.
- Rate-limit path is ~6× multi-rule policy eval but still far below 100 µs; kept informational because it takes a `Mutex`.
- HTML reports live under `target/criterion/` and are **not** committed.
