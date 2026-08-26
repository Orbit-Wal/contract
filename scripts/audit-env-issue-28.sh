#!/usr/bin/env bash
# Audita que el entorno local cumple con las herramientas requeridas para
# trabajar en la Issue #28 (globe-wallet, soroban-sdk 21.7.7, wasm32-unknown-unknown).
# No instala nada ni modifica el sistema; solo reporta versiones y falla (exit 1)
# si falta una herramienta obligatoria.
set -euo pipefail

REQUIRED_RUST_EDITION="2021"
REQUIRED_SOROBAN_SDK="21.7.7"
WASM_TARGET="wasm32-unknown-unknown"

fail=0

section() { printf '\n== %s ==\n' "$1"; }

check_bin() {
  local name="$1"
  if command -v "$name" >/dev/null 2>&1; then
    printf '  [ok] %s -> %s\n' "$name" "$(command -v "$name")"
  else
    printf '  [FALTA] %s no encontrado en PATH\n' "$name"
    fail=1
  fi
}

section "Binarios requeridos"
check_bin cargo
check_bin rustc
# soroban-cli fue renombrado a "stellar" a partir de versiones recientes del CLI.
if command -v stellar >/dev/null 2>&1; then
  printf '  [ok] stellar-cli (sustituye a soroban-cli) -> %s\n' "$(command -v stellar)"
elif command -v soroban >/dev/null 2>&1; then
  printf '  [ok] soroban-cli -> %s\n' "$(command -v soroban)"
else
  printf '  [FALTA] ni "stellar" ni "soroban" CLI encontrados en PATH\n'
  fail=1
fi

section "Versiones"
rustc --version 2>&1 || true
cargo --version 2>&1 || true
(stellar --version 2>&1 || soroban --version 2>&1) || true

section "Target wasm32-unknown-unknown"
if rustup target list --installed 2>/dev/null | grep -q "^${WASM_TARGET}\$"; then
  echo "  [ok] ${WASM_TARGET} instalado"
else
  echo "  [FALTA] ${WASM_TARGET} no instalado. Ejecutar: rustup target add ${WASM_TARGET}"
  fail=1
fi

section "Coherencia de manifiestos (Cargo.toml)"
pinned=$(grep -E '^\s*soroban-sdk\s*=' Cargo.toml | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1 || true)
if [ "$pinned" = "$REQUIRED_SOROBAN_SDK" ]; then
  echo "  [ok] soroban-sdk pineado a ${pinned} en el workspace Cargo.toml"
else
  echo "  [ADVERTENCIA] soroban-sdk pineado a '${pinned:-desconocido}', se esperaba ${REQUIRED_SOROBAN_SDK}"
fi

section "Build de verificación (wasm, sin desplegar)"
echo "  Sugerido tras pasar los checks anteriores:"
echo "  cargo build --target ${WASM_TARGET} --release -p globe-wallet"
echo "  cargo test -p globe-wallet"

if [ "$fail" -ne 0 ]; then
  echo
  echo "AUDITORÍA FALLIDA: instalar/ajustar PATH para las herramientas marcadas [FALTA]." >&2
  exit 1
fi

echo
echo "AUDITORÍA OK: entorno listo para trabajar en la Issue #28."
