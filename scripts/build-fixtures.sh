#!/usr/bin/env bash
# Build checked-in wasip2 fixture components for integration / adversarial tests.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

rustup target add wasm32-wasip2 >/dev/null 2>&1 || true

build_fixture() {
  local crate="$1"
  local out_name="$2"
  echo "==> building ${crate} -> ${out_name}"
  cargo component build --release --target wasm32-wasip2 -p "${crate}"
  cp "${ROOT}/target/wasm32-wasip2/release/${crate//-/_}.wasm" \
    "${ROOT}/tests/fixtures/${crate}/${out_name}"
}

build_fixture echo-tool echo.wasm
build_fixture damage-bot damage-bot.wasm

echo "Fixtures built:"
ls -la "${ROOT}/tests/fixtures/echo-tool/echo.wasm" \
       "${ROOT}/tests/fixtures/damage-bot/damage-bot.wasm"
