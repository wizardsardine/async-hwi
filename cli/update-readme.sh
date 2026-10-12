#!/usr/bin/env bash
set -euo pipefail

# Generate cli/README.md from cli/README.md.template.
#
# The usage section is rendered from the release CLI help output so the
# committed documentation matches the actual binary. Pass --check in CI to
# compare the generated file with the committed README without modifying it.

if [ "${1:-}" != "" ] && [ "${1:-}" != "--check" ]; then
    printf 'usage: %s [--check]\n' "$0" >&2
    exit 2
fi

script_dir="$(cd "$(dirname "$0")" && pwd)"
repo_dir="$(cd "$script_dir/.." && pwd)"
template="$script_dir/README.md.template"
readme="$script_dir/README.md"
bin="$repo_dir/target/release/hwi"
tmp="$(mktemp)"
help_tmp="$(mktemp)"
trap 'rm -f "$tmp" "$help_tmp"' EXIT

cd "$repo_dir"
cargo build --release -p async-hwi-cli --bin hwi >/dev/null

# Keep this list explicit so newly added commands must opt in to the generated
# docs and the CI check catches missing README updates.
commands=(
    ""
    "address"
    "address display"
    "device"
    "device list"
    "psbt"
    "psbt sign"
    "wallet"
    "wallet register"
    "wallet is-registered"
    "bitbox"
    "state"
    "state edit"
    "state rm"
    "persist"
    "xpub"
    "xpub get"
)

for command in "${commands[@]}"; do
    if [ "$command" = "" ]; then
        args=()
    else
        read -r -a args <<< "$command"
    fi

    printf '```shell\n' >> "$help_tmp"
    printf '$ hwi' >> "$help_tmp"
    if [ "$command" != "" ]; then
        printf ' %s' "$command" >> "$help_tmp"
    fi
    printf ' -h\n' >> "$help_tmp"
    "$bin" "${args[@]}" -h >> "$help_tmp"
    printf '```\n' >> "$help_tmp"

    if [ "$command" != "${commands[-1]}" ]; then
        printf '\n' >> "$help_tmp"
    fi
done

# Replace only the usage placeholder. The rest of the README stays authored in
# the template.
awk '
    $0 == "{{CLI_HELP}}" {
        while ((getline line < help) > 0) {
            sub(/[[:blank:]]+$/, "", line)
            print line
        }
        close(help)
        next
    }
    {
        sub(/[[:blank:]]+$/, "")
        print
    }
' help="$help_tmp" "$template" > "$tmp"

if [ "${1:-}" = "--check" ]; then
    if ! cmp -s "$tmp" "$readme"; then
        printf 'cli/README.md is not up to date. Run cli/update-readme.sh.\n' >&2
        exit 1
    fi
else
    cp "$tmp" "$readme"
fi
