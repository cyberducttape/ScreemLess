#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TEST_DIR="$(mktemp -d)"
trap 'rm -rf "$TEST_DIR"' EXIT

mkdir -p "$TEST_DIR/bin"
cat > "$TEST_DIR/bin/systemctl" <<'MOCK'
#!/usr/bin/env sh
printf '%s\n' "$*" >> "$SCREAMLESS_SYSTEMCTL_CALLS"
case "$*" in
    "is-active --quiet screamless-agent.service"|"is-enabled --quiet screamless-agent.service")
        exit 0
        ;;
esac
MOCK
chmod +x "$TEST_DIR/bin/systemctl"
export SCREAMLESS_SYSTEMCTL_CALLS="$TEST_DIR/systemctl.calls"
export PATH="$TEST_DIR/bin:$PATH"

# Debian and RPM upgrades must not stop the service after new postinstall.
"$ROOT_DIR/packaging/preremove.sh" upgrade
"$ROOT_DIR/packaging/preremove.sh" 1
[[ ! -s "$SCREAMLESS_SYSTEMCTL_CALLS" ]]

# Removal stops and disables the service; the database is intentionally kept.
"$ROOT_DIR/packaging/preremove.sh" remove
"$ROOT_DIR/packaging/preremove.sh" 0
expected=$'is-active --quiet screamless-agent.service\nstop screamless-agent.service\nis-enabled --quiet screamless-agent.service\ndisable screamless-agent.service\nis-active --quiet screamless-agent.service\nstop screamless-agent.service\nis-enabled --quiet screamless-agent.service\ndisable screamless-agent.service'
[[ "$(<"$SCREAMLESS_SYSTEMCTL_CALLS")" == "$expected" ]]

: > "$SCREAMLESS_SYSTEMCTL_CALLS"
"$ROOT_DIR/packaging/postremove.sh"
[[ "$(<"$SCREAMLESS_SYSTEMCTL_CALLS")" == "daemon-reload" ]]

echo "Package removal lifecycle tests passed"
