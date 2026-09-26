#!/usr/bin/env sh
set -eu

if command -v systemctl >/dev/null 2>&1; then
    # During upgrades the replacement unit has already been installed. During
    # removal this drops the now-removed unit from systemd's in-memory cache.
    systemctl daemon-reload >/dev/null 2>&1 || true
fi
