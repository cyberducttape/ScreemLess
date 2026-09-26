#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RENDERER="$ROOT_DIR/packaging/render-service-unit.sh"
UNIT="$ROOT_DIR/packaging/screamless-agent.service"

rendered="$(bash "$RENDERER" "$UNIT" /opt/screamless/bin/screamless)"
grep -Fqx 'ExecStart=/opt/screamless/bin/screamless observe --db /var/lib/screamless/screamless.db --duration 3650d --interval 1m' <<< "$rendered"
[[ "$(grep -c '^ExecStart=' <<< "$rendered")" == 1 ]]

if bash "$RENDERER" "$UNIT" '/opt/screamless custom/bin/screamless' >/dev/null 2>&1; then
    echo "Renderer accepted a path that systemd cannot safely parse" >&2
    exit 1
fi
if bash "$RENDERER" "$UNIT" /opt/screamless/../tmp/screamless >/dev/null 2>&1; then
    echo "Renderer accepted a path containing dot segments" >&2
    exit 1
fi

for install_dir in /tmp/screamless /var/tmp/screamless /tmp /var/tmp; do
    if INSTALL_DIR="$install_dir" "$ROOT_DIR/install.sh" >/dev/null 2>&1; then
        echo "Installer accepted a path hidden by the systemd PrivateTmp namespace: $install_dir" >&2
        exit 1
    else
        status=$?
        if [[ "$status" != 3 ]]; then
            echo "Installer rejected $install_dir for an unexpected reason (exit $status)" >&2
            exit 1
        fi
    fi
done

echo "Installer service path tests passed"
