#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 || ! "$1" =~ ^(/[[:alnum:]_.-]+)+/?$ ]]; then
    echo "Usage: $0 ABSOLUTE_INSTALL_DIRECTORY" >&2
    exit 3
fi

directory="${1%/}"
[[ -n "$directory" ]] || directory=/
case "$directory" in
    */../*|*/..|*/./*|*/.)
        echo "Install directory must not contain dot segments" >&2
        exit 3
        ;;
esac

current=""
IFS='/' read -r -a components <<< "${directory#/}"
for component in "${components[@]}"; do
    [[ -n "$component" ]] || continue
    current+="/$component"
    if [[ -L "$current" ]]; then
        echo "Service install path must not traverse symlinks: $current" >&2
        exit 3
    fi
    if [[ -e "$current" ]]; then
        if [[ ! -d "$current" ]]; then
            echo "Service install path component is not a directory: $current" >&2
            exit 3
        fi
        read -r owner mode < <(stat -c '%u %a' -- "$current")
        if [[ "$owner" != 0 ]] || (( (8#$mode & 0022) != 0 )); then
            echo "Service install path must be root-owned and not group/world-writable: $current" >&2
            exit 3
        fi
    else
        # Later components cannot exist if this one does not.
        break
    fi
done
