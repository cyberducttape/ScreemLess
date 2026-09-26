#!/usr/bin/env sh
set -eu

activate_screamless_service() {
    systemctl daemon-reload
    systemctl enable screamless-agent.service
    if systemctl is-active --quiet screamless-agent.service; then
        systemctl restart screamless-agent.service
    else
        systemctl start screamless-agent.service
    fi
}

if [ "${1:-}" = "--run" ]; then
    activate_screamless_service
fi
