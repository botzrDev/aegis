# Policy YAML

Station 1 of the pipeline. YAML is parsed **once** into an immutable
`PolicySet` held behind an `ArcSwap`. Evaluation is synchronous and
targets <100 µs. The engine never parses at call time.

**Matchers today are `tool`, `capability`, and `role` only.** Policy does
not inspect call arguments. Argument-level matching is not shipped.

**Both trust models reach all three.** The caller names the axes it asserts
on the request it hands to `execute_tool_call` (Model A) or
`execute_host_call` (Model B). A rule constrained on an axis the caller left
unset does not match, so a role gate fires only where a role is actually
claimed. `session` rides along on the request and is recorded on the Agent
Action Record, but it is not a match axis — no rule can be written against
it.

Neither `aegis run` nor the MCP gateway claims a role or a capability: both
pass tool identity and nothing else, because neither has been told who is
calling. Role-scoped rules are reachable from the library entry points,
where the embedding application knows.

## On-disk shape (`version: 1`)

Copied from the parser in `crates/botzr-aegis-policy/src/parse.rs`:

```yaml
version: 1
default: allow          # allow (default) | deny
rules:
  - id: deny-exec
    action: deny        # allow | deny | rate_limit | pending_approval
    tool: exec-runner   # match axes (omitted or "*" = wildcard)
    capability: exec.command
    role: "*"
    priority: 10        # tie-break among equally-specific rules
    reason: "exec disabled in this environment"
  - id: rate-search
    action: rate_limit
    tool: search
    rate: { max: 100, per_seconds: 60 }
  - id: approve-dream
    action: pending_approval
    tool: dream
  - id: cap-writer
    action: allow
    tool: writer
    limits: { max_memory_bytes: 33554432, max_wall_ms: 5000 }
```

`limits` accepts a third key the example above omits, `max_output_bytes`,
which caps a single call's returned bytes.

Unknown fields are rejected. Duplicate `id` values are rejected.
`rate_limit` requires a `rate` block with `max > 0` and `per_seconds > 0`.
`rate` is invalid on any other action.

## Conflict resolution (G5)

No implicit file ordering:

1. **Deny-overrides** — any matching `deny` wins outright.
2. Among the rest, **most-specific wins** (more constrained match axes).
3. Ties broken by explicit rule **`priority`** (higher wins).
4. No match → the set's `default` action.

## `pending_approval`

Reject-with-resume-token: the call is **not executed** and no grant is
minted. This is not a parked in-flight call. Parking a live MCP request
across an approval is a D3 ticket, not this language.

## Worked example

Three rules excerpted from the seven in
[`examples/dreamd-poc/fixtures/dreamd-policy.yaml`](https://github.com/botzrDev/aegis/blob/main/examples/dreamd-poc/fixtures/dreamd-policy.yaml)
— the file also carries a role-gated write, a read-only recall allow, and
two rate limits:

```yaml
version: 1
default: deny
rules:
  - id: allow-episodic-append
    action: allow
    tool: append_node
    capability: fs:episodic
  - id: deny-net
    action: deny
    tool: "*"
    capability: net
    reason: "network denied for dreamd integration"
  - id: approve-dream
    action: pending_approval
    tool: dream
```

Parse-surface seeds (including invalid documents the fuzzer keeps) live in
[`fuzz/corpus/policy_yaml/`](https://github.com/botzrDev/aegis/tree/main/fuzz/corpus/policy_yaml).

## Recheck

`aegis recheck --policy <YAML> <PATH>` re-evaluates recorded outcomes
against a *different* Policy Set. It uses the same G5 selection. It
executes nothing. See [CLI](cli.md).
