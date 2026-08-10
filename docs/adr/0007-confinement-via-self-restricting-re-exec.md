# Confinement applies via a self-restricting re-exec, and needs no `unsafe`

**Status:** accepted (2026-08-09) · lands in AILAB-628 · deletes a clause from Execution Report §5

Native MCP servers are confined by re-executing `aegis` as a hidden subcommand (`aegis __confine-exec -- <target>`). That process applies Landlock and seccomp **to itself** using safe wrapper APIs, then replaces its own image with the target. Landlock domains and seccomp filters are preserved across `execve`, so the target runs confined. Nothing in the workspace needs `unsafe`, and `unsafe_code = forbid` stays workspace-wide.

## The mechanism both documents missed

Execution Report §5 names `aegis-confine` as *"the single documented exception (raw syscall surface)"*. Binding decision 3 (2026-08-09) says forbid stays workspace-wide via vetted safe wrappers. These read as a contradiction only because both assume confinement must happen between `fork` and `exec`.

`CommandExt::pre_exec` is `unsafe`. **`CommandExt::exec` is not.** It performs no fork — it replaces the current process image via `execvp` and does not return on success — so there is no window of async-signal-unsafe execution to make the caller responsible for. That asymmetry is the entire answer, and it means **the §5 exception clause should be deleted, not honoured.** The contradiction dissolves; it does not resolve toward either document.

## `pre_exec` would not merely be unsafe, it would be wrong

This is the stronger argument, and the ADR leads with it so the choice reads as technical rather than procedural.

Code between `fork` and `exec` must be async-signal-safe: no allocation, no lock acquisition, no non-reentrant calls. Building a Landlock ruleset does all three — it allocates, and path rules require `open()`ing each path for an fd. Performed in a forked child of a multithreaded process, that risks deadlocking on an allocator lock held by a thread that does not exist in the child.

So the exception would be spent to do something genuinely hazardous, in the crate that most needs to be trustworthy. The helper does identical work in an ordinary process context, where allocating and opening files is simply normal.

## One artifact, not two

A separate `aegis-confine-exec` binary would cost the single-static-binary distribution channel that report §2.3 makes the whole wedge strategy. `std::env::current_exe()` is safe, so `aegis` re-execs **itself** under a hidden subcommand. Same artifact, same crate, no distribution change.

Two constraints follow: dispatch `__confine-exec` at the very top of `main`, before any tokio runtime or thread pool exists — `restrict_self` applies to the calling thread, and a single-threaded process avoids the question — and keep that path dependency-minimal, since it is reachable before any interposer machinery.

## Profile transport

`stdin`/`stdout` are the MCP transport and must pass through untouched. An inherited fd would need `dup2` in `pre_exec`, reintroducing the problem. **argv is visible to any local user via `/proc/<pid>/cmdline`**, which would publish the confinement profile including its paths. So the profile travels in the environment (`/proc/<pid>/environ` is owner-readable) and is stripped with `env_remove` before exec.

## The helper cannot be abused

It is **authority-reducing only**: it holds no privilege, is not setuid, and its sole powers are to narrow itself and then exec. An attacker invoking it with an empty profile gets an unconfined child — which they could have obtained by running the target directly.

Same shape as [ADR-0006](./0006-matchers-target-derived-capability-parameters.md)'s bindings-cannot-grant-authority rule, and it is what separates this from the setuid sandbox helpers that have historically been a vulnerability class. State it explicitly, because "we ship a sandbox helper binary" otherwise reads alarming.

## The record must not overclaim what was enforced

Landlock's ABI varies by kernel and the crate's default posture is best-effort. That creates a failure worse than no confinement: the helper execs on an old kernel with partial restriction and the audit record says the call was confined.

- **Fail closed by default.** If the requested confinement cannot be fully applied, refuse to exec. `--best-effort` is an explicit operator opt-in, and the opt-in is itself recorded.
- **Record what was actually enforced** — the negotiated Landlock ABI level, whether the seccomp filter applied — not what was requested. Same rule as [ADR-0002](./0002-verify-reports-coverage-not-pass-fail.md) and [ADR-0004](./0004-embedded-key-with-labelled-trust.md), arriving in the confinement station.
- **A seccomp kill is distinct evidence.** The child dies on `SIGSYS`, detectable via `ExitStatus::signal()` (safe API). Map it to its own audit outcome rather than folding it into a generic crash — a seccomp kill and a segfault mean different things.

## On the alternatives

**A crate owning the fork/exec/restrict sequence** is this design implemented by someone else, and would equally preserve `forbid`. Rejected because it moves the security-critical step into a dependency for roughly two hundred lines of code, and the `landlock` crate already ships a `sandboxer` example doing exactly this. Nothing is being invented.

**Spiking first** is not triggered: decision 3's escape hatch is *"if a spike shows safe wrappers are impossible"*, and they are not. A smoke test across the supported kernel range is implementation work, not a decision gate.

**macOS inherits the architecture.** Seatbelt's `sandbox_init` is a deprecated-adjacent C API that may genuinely need a crate or an exception, but restrict-self-then-exec carries over unchanged. That is AILAB-630's call, not this one.

## Unverified — confirm by smoke test before SPEC.md or the threat model cites them

1. Landlock domains preserved across `execve` on the minimum supported kernel (documented, but ABI level affects what is enforceable)
2. Whether `restrict_self()` sets `PR_SET_NO_NEW_PRIVS`, or the helper must
3. Whether `seccompiler::apply_filter` sets `NO_NEW_PRIVS`
4. That the filter permits `execve` and the dynamic loader's syscalls — a filter correct for node's steady state will kill it at startup otherwise
