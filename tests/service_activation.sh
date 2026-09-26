#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$ROOT_DIR/packaging/service-activation.sh"

CALLS=()
ACTIVE_STATUS=0
systemctl() {
    CALLS+=("$*")
    if [[ "$1" == "is-active" ]]; then
        return "$ACTIVE_STATUS"
    fi
}

activate_screamless_service
expected_active=$'daemon-reload\nenable screamless-agent.service\nis-active --quiet screamless-agent.service\nrestart screamless-agent.service'
actual_active="$(printf '%s\n' "${CALLS[@]}")"
[[ "$actual_active" == "$expected_active" ]] || {
    echo "Active-service upgrade did not restart in the expected order" >&2
    exit 1
}

CALLS=()
ACTIVE_STATUS=3
activate_screamless_service
expected_inactive=$'daemon-reload\nenable screamless-agent.service\nis-active --quiet screamless-agent.service\nstart screamless-agent.service'
actual_inactive="$(printf '%s\n' "${CALLS[@]}")"
[[ "$actual_inactive" == "$expected_inactive" ]] || {
    echo "Fresh install did not start the inactive service in the expected order" >&2
    exit 1
}

echo "Service activation tests passed"
