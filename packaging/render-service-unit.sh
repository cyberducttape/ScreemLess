#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 ]]; then
    echo "Usage: $0 UNIT_FILE ABSOLUTE_EXECUTABLE" >&2
    exit 3
fi

UNIT_FILE="$1"
EXECUTABLE="$2"
if [[ ! "$EXECUTABLE" =~ ^(/[[:alnum:]_.-]+)+$ ]]; then
    echo "Executable path contains characters unsupported by the systemd unit renderer" >&2
    exit 3
fi
case "$EXECUTABLE" in
    */../*|*/..|*/./*|*/.)
        echo "Executable path must not contain dot segments" >&2
        exit 3
        ;;
esac
if [[ ! -f "$UNIT_FILE" ]]; then
    echo "Service unit not found: $UNIT_FILE" >&2
    exit 1
fi

exec_start_count="$(grep -c '^ExecStart=/usr/local/bin/screamless ' "$UNIT_FILE" || true)"
if [[ "$exec_start_count" != 1 ]]; then
    echo "Expected exactly one default Screamless ExecStart in service unit" >&2
    exit 1
fi

sed "s#^ExecStart=/usr/local/bin/screamless #ExecStart=${EXECUTABLE} #" "$UNIT_FILE"
