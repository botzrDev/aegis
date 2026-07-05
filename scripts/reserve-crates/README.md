# Reserve `botzr-aegis-*` on crates.io (AEG-7)

Placeholder publish of all eight v1 crate names. crates.io has no separate “reserve” API — the first `cargo publish` claims the name.

**Prerequisite:** GitHub org + public repo already exist ([botzrDev/aegis](https://github.com/botzrDev/aegis)). OQ-1 (MIT) and OQ-14 (`botzr-aegis-*` prefix) are closed.

## Crates (8)

| Crate | Type | Notes |
|---|---|---|
| `botzr-aegis-core` | lib | shared types/traits |
| `botzr-aegis-policy` | lib | YAML policy eval |
| `botzr-aegis-capability` | lib | grant resolver |
| `botzr-aegis-sandbox` | lib | wasmtime sandbox |
| `botzr-aegis-audit` | lib | audit records |
| `botzr-aegis-runtime` | lib | pipeline orchestrator |
| `botzr-aegis-cli` | bin | binary name **`aegis`** (not `botzr-aegis-cli`) |
| `botzr-aegis-sidecar` | lib | Phase 2 sidecar |

Each stub publishes as **`0.0.0`** with a README stating the name is reserved pending M1 implementation.

## One-time setup

1. Create a crates.io account (or use an existing one tied to the botzr org).
2. Generate an API token: [crates.io/settings/tokens](https://crates.io/settings/tokens) — scope **Publish new**, **Publish update**, **Change default version**.
3. Log in locally:

   ```bash
   cargo login
   # paste token when prompted
   ```

4. If this is your **first ever publish** on this account, accept the ToS at [crates.io/me](https://crates.io/me) once in a browser.

## Run

From the repo root:

```bash
# 1. Verify names are still free + manifests pass `cargo package`
./scripts/reserve-crates/reserve.sh --check

# 2. Dry-run publish (no upload)
./scripts/reserve-crates/reserve.sh --dry-run

# 3. Publish all eight (irreversible — claims the names)
./scripts/reserve-crates/reserve.sh --publish
```

The script skips crates already on crates.io and waits **120s** between uploads (crates.io rate-limits new-crate publishes aggressively). Override with `--delay 180` or `PUBLISH_DELAY=180`.

If you hit **429 Too Many Requests**, wait until the time in the error message, then re-run `--publish` — it resumes where you left off.

Expected output on success: eight lines like `published botzr-aegis-core 0.0.0`.

## Verify

```bash
for c in botzr-aegis-core botzr-aegis-policy botzr-aegis-capability \
         botzr-aegis-sandbox botzr-aegis-audit botzr-aegis-runtime \
         botzr-aegis-cli botzr-aegis-sidecar; do
  cargo search "$c" --limit 1
done
```

Or open each crate page, e.g. `https://crates.io/crates/botzr-aegis-core`.

## After publish

- Mark **AEG-7** Done in Linear.
- These stubs are **not** the M1 workspace — AEG-4 will scaffold `crates/botzr-aegis-*` under the real workspace. When v1 ships, publish `0.1.0+` from that layout (yanking `0.0.0` is optional; most projects leave it).

## Troubleshooting

| Error | Fix |
|---|---|
| `403` / `must verify email` | Confirm email on crates.io |
| `429 Too Many Requests` | Wait for the GMT time in the error, then `./scripts/reserve-crates/reserve.sh --publish` (auto-resumes) |
| `crate name is already taken` | Someone beat us — stop, pick a new prefix, reopen OQ-14 |
| `missing README` | Stub README missing — re-run from a clean checkout |
| `timeout waiting for crate upload` | Retry single crate: `cd scripts/reserve-crates/stubs/botzr-aegis-core && cargo publish` |
