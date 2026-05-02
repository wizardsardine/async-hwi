#!/usr/bin/env bash
#
# Local Speculos integration runner. Mirrors the CI `ledger_app` + `speculos`
# jobs in .github/workflows/main.yml so the same .elf, automation rules, and
# Speculos version pin are used in both places.
#
# Usage:
#   tests/speculos/run.sh [device] [-- <extra cargo test args>]
#
#   device : nanox (default) | nanosp | stax | flex
#
# Examples:
#   tests/speculos/run.sh                       # nanox, all ignored tests
#   tests/speculos/run.sh stax
#   tests/speculos/run.sh nanosp -- speculos_master_fingerprint
#
# Caching: built .elf binaries are stored in target/speculos-cache/<device>/
# keyed by app version + builder image. Bumping versions.env invalidates them.
#
# Prerequisites:
#   - docker (to build the Ledger app .elf)
#   - python3 + pip (auto-installs speculos at the pinned version into a
#     local venv at target/speculos-cache/venv if speculos is not on PATH)

set -euo pipefail

DEVICE="${1:-nanox}"
shift || true
if [[ "${1:-}" == "--" ]]; then
    shift
fi
EXTRA_ARGS=("$@")

case "$DEVICE" in
    nanox)  SDK_VAR=NANOX_SDK ;;
    nanosp) SDK_VAR=NANOSP_SDK ;;
    *)
        echo "unknown device: $DEVICE (expected: nanox, nanosp)" >&2
        echo "stax / flex are supported by the speculos crate but not yet wired into these tests." >&2
        exit 1
        ;;
esac

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

# Speculos shells out to qemu-arm-static to emulate the Ledger ARM target.
# Catch the missing-binary case here so the failure is obvious instead of
# surfacing as a cryptic speculos traceback after the .elf has been built.
command -v qemu-arm-static >/dev/null || {
    echo "qemu-arm-static not found on PATH" >&2
    echo "  install with:  sudo apt-get install -y qemu-user-static" >&2
    exit 1
}

# shellcheck disable=SC1091
set -a; . tests/speculos/versions.env; set +a

CACHE_KEY="${LEDGER_APP_VERSION}_$(echo "$LEDGER_APP_BUILDER_IMAGE" | tr -c '[:alnum:]' '_')"
CACHE_DIR="target/speculos-cache/$DEVICE/$CACHE_KEY"
ELF="$CACHE_DIR/app.elf"
LOG="target/speculos-cache/speculos-$DEVICE.log"
mkdir -p target/speculos-cache

# ---------------------------------------------------------------------------
# 1. Build the Ledger Bitcoin app .elf (cached)
# ---------------------------------------------------------------------------
if [[ ! -f "$ELF" ]]; then
    echo "==> Building Ledger Bitcoin app for $DEVICE (~1 min)"
    command -v docker >/dev/null || {
        echo "docker not found on PATH" >&2
        exit 1
    }
    BUILD_DIR="$(mktemp -d -p target speculos-build.XXXXXX)"
    trap 'rm -rf "$BUILD_DIR"' EXIT
    docker run --rm \
        -v "$ROOT/$BUILD_DIR:/work" -w /work \
        -e SDK_VAR="$SDK_VAR" \
        -e HOST_UID="$(id -u)" -e HOST_GID="$(id -g)" \
        "$LEDGER_APP_BUILDER_IMAGE" \
        bash -c '
            set -e
            git clone --branch "'"$LEDGER_APP_VERSION"'" --depth 1 \
              https://github.com/LedgerHQ/app-bitcoin-new.git
            cd app-bitcoin-new
            make DEBUG=1 BOLOS_SDK="${!SDK_VAR}"
            chown -R "$HOST_UID:$HOST_GID" /work
        '
    mkdir -p "$CACHE_DIR"
    cp "$BUILD_DIR/app-bitcoin-new/bin/app.elf" "$ELF"
    echo "==> Cached $ELF"
else
    echo "==> Using cached $ELF"
fi

# ---------------------------------------------------------------------------
# 2. Ensure speculos is available at the pinned version
# ---------------------------------------------------------------------------
# The Rust `speculos` crate `exec`s `speculos` from $PATH, so we only need
# to ensure the binary is present and prepend our local venv if necessary.
SPECULOS_BIN="$(command -v speculos || true)"
if [[ -z "$SPECULOS_BIN" ]]; then
    VENV="target/speculos-cache/venv"
    if [[ ! -x "$VENV/bin/speculos" ]]; then
        echo "==> Installing speculos==$SPECULOS_VERSION into $VENV"
        python3 -m venv "$VENV"
        "$VENV/bin/pip" install --upgrade pip >/dev/null
        "$VENV/bin/pip" install "speculos==$SPECULOS_VERSION"
    fi
    export PATH="$ROOT/$VENV/bin:$PATH"
    SPECULOS_BIN="$VENV/bin/speculos"
fi
echo "==> Using speculos: $SPECULOS_BIN"

# ---------------------------------------------------------------------------
# 3. Defensive cleanup of stale speculos / qemu children, then run cargo.
#    The Rust test binary spawns speculos itself via the `speculos` crate
#    and tears it down at process exit; we only need to make sure 9999/5000
#    aren't held by a previous run that was killed mid-flight.
# ---------------------------------------------------------------------------
# Match the speculos python entrypoint specifically (not e.g. "tests/speculos/run.sh"
# itself, which would kill us). Speculos's actual cmdline ends with `speculos` followed
# by flags, so we anchor on `bin/speculos`.
pkill -f 'bin/speculos' 2>/dev/null || true
pkill -f qemu-arm-static 2>/dev/null || true

# ---------------------------------------------------------------------------
# 4. Run the ignored speculos tests
# ---------------------------------------------------------------------------
export SPECULOS_ELF="$ROOT/$ELF"
export SPECULOS_MODEL="$DEVICE"
echo "==> SPECULOS_ELF=$SPECULOS_ELF SPECULOS_MODEL=$SPECULOS_MODEL"
cargo test --features ledger --test ledger_speculos -- \
    --ignored --nocapture --test-threads=1 \
    "${EXTRA_ARGS[@]}"
