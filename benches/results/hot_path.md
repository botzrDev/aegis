# Hot-path benchmark results — AEG-16 / OQ-15 T5

Library-mode enforcement hot path (`PolicyEngine::evaluate` +
`CapabilityResolver::resolve_with_ceiling`), measured with Criterion. Numbers
below are the committed publication claim for the machine cited in the hardware
block. Regenerate with the command in [`../README.md`](../README.md).

> Criterion's text line is `time: [lower_bound estimate upper_bound]` — a 95 %
> confidence interval around its point estimate (middle value). AEG-16 states its
> targets as "median"; every group clears its target by 2–4 orders of magnitude,
> so the mean/median distinction is immaterial to pass/fail. Values pasted
> verbatim from `cargo bench`.

## Hardware / OS / toolchain

```
$ uname -a
Linux botzrDev 6.6.87.2-microsoft-standard-WSL2 #1 SMP PREEMPT_DYNAMIC Thu Jun  5 18:30:46 UTC 2025 x86_64 x86_64 x86_64 GNU/Linux

$ lscpu | head -20
Architecture:                         x86_64
CPU op-mode(s):                       32-bit, 64-bit
Byte Order:                           Little Endian
CPU(s):                               4
On-line CPU(s) list:                  0-3
Vendor ID:                            AuthenticAMD
Model name:                           AMD Ryzen AI 5 340 w/ Radeon 840M
CPU family:                           26
Model:                                96
Thread(s) per core:                   2
Core(s) per socket:                   2
Socket(s):                            1
Stepping:                             0
BogoMIPS:                             3992.41
Virtualization:                       AMD-V
Hypervisor vendor:                    Microsoft
Virtualization type:                  full
L1d cache:                            96 KiB (2 instances)

$ rustc -Vv | head -5
rustc 1.96.0 (ac68faa20 2026-05-25)
binary: rustc
commit-hash: ac68faa20c58cbccd01ee7208bf3b6e93a7d7f96
commit-date: 2026-05-25
host: x86_64-unknown-linux-gnu
```

**Environment caveat:** this is a **WSL2** guest (Microsoft Hyper-V) on an AMD
Ryzen AI 5 340, not bare metal. Absolute timings include hypervisor overhead and
should be read as an order-of-magnitude ceiling, not a tuned lab figure. Cited
honestly per OQ-15 T5. `cargo bench` builds in `release`.

## Results (Criterion, 100 samples/group)

### Policy crate — `cargo bench -p botzr-aegis-policy`

```
policy_eval/allow_all   time:   [14.344 ns 14.728 ns 15.121 ns]
policy_eval/multi_rule  time:   [29.802 ns 30.361 ns 31.059 ns]
policy_eval/rate_limit  time:   [185.31 ns 188.90 ns 192.95 ns]
```

### Capability crate — `cargo bench -p botzr-aegis-capability`

```
capability_resolve/registered_tool
                        time:   [2.3869 µs 2.4233 µs 2.4594 µs]
```

### Combined hot path — `cargo bench -p botzr-aegis-runtime`

```
hot_path/allow_all      time:   [2.5138 µs 2.5638 µs 2.6191 µs]
hot_path/multi_rule     time:   [2.4649 µs 2.5067 µs 2.5535 µs]
```

## Targets vs. measured (point estimate)

| Group | Estimate | Target | Result |
|---|---|---|---|
| `policy_eval/allow_all` | **14.73 ns** | < 100 µs (median) | ✅ pass (~6800× under) |
| `policy_eval/multi_rule` | **30.36 ns** | < 100 µs (median) | ✅ pass (~3300× under) |
| `policy_eval/rate_limit` | 188.9 ns | informational — mutex path, no gate | ℹ️ takes `RateLimiter` mutex |
| `capability_resolve/registered_tool` | 2.42 µs | no hard gate (isolation/regression) | ℹ️ baseline |
| `hot_path/allow_all` | **2.56 µs** | < 1 ms (median) | ✅ pass (~390× under) |
| `hot_path/multi_rule` | **2.51 µs** | < 1 ms (median) | ✅ pass (~400× under) |

Both gated claims — policy `evaluate` < 100 µs and combined policy+capability
< 1 ms — hold with large margins on the cited hardware. No hot-path code was
changed to hit these numbers (AEG-16 scope: benches only).
