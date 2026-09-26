#!/usr/bin/env sh
set -eu
install -d -m 0750 /var/lib/screamless
if command -v systemctl >/dev/null 2>&1; then
    if [ -d /run/systemd/system ]; then
        if [ ! -x /usr/lib/screamless/service-activation.sh ]; then
            echo "Screamless service activation helper is missing" >&2
            exit 1
        fi
        /usr/lib/screamless/service-activation.sh --run
    fi
fi
