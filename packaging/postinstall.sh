#!/usr/bin/env sh
set -eu
install -d -m 0750 /var/lib/screamless
if command -v systemctl >/dev/null 2>&1; then
    if [ -d /run/systemd/system ]; then
        systemctl daemon-reload
        systemctl enable screamless-agent.service
        if systemctl is-active --quiet screamless-agent.service; then
            systemctl restart screamless-agent.service
        else
            systemctl start screamless-agent.service
        fi
    fi
fi
