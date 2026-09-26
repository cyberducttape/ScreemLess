#!/usr/bin/env sh
set -eu
install -d -m 0750 /var/lib/screamless
if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload
    systemctl enable --now screamless-agent.service
fi
