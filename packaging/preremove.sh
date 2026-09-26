#!/usr/bin/env sh
set -eu

action="${1:-remove}"
case "$action" in
    upgrade|1)
        # nFPM passes "upgrade" for Debian upgrades and 1 for RPM upgrades.
        # Keep the agent running; the new package's postinstall manages it.
        exit 0
        ;;
    remove|0|purge)
        ;;
    *) exit 0 ;;
esac

if command -v systemctl >/dev/null 2>&1; then
    if systemctl is-active --quiet screamless-agent.service >/dev/null 2>&1; then
        systemctl stop screamless-agent.service
    fi
    if systemctl is-enabled --quiet screamless-agent.service >/dev/null 2>&1; then
        systemctl disable screamless-agent.service
    fi
fi
