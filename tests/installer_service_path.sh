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

echo "Installer service path tests passed"
