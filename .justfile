# Stax / Flex are supported by the speculos crate but not yet wired in.
# Run Ledger speculos integration tests against nanox, nanosp (in order).
test-ledger:
    #!/usr/bin/env bash
    set -euo pipefail
    for device in nanox nanosp; do
        echo "==> $device"
        tests/speculos/run.sh "$device"
    done

# Wipe cargo build outputs and the speculos cache (built .elfs, venv, logs).
clean:
    cargo clean
