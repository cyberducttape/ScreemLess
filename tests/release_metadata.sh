#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CHECKER="$ROOT_DIR/packaging/verify-release-version.sh"

result="$(cd "$ROOT_DIR" && bash "$CHECKER")"
printf '%s\n' "$result"
version="${result##* }"
(cd "$ROOT_DIR" && bash "$CHECKER" "v$version")

if (cd "$ROOT_DIR" && bash "$CHECKER" v99.99.99) >/dev/null 2>&1; then
    echo "Release checker accepted a tag that disagrees with Cargo.toml" >&2
    exit 1
fi

if (cd "$ROOT_DIR" && bash "$CHECKER" release-1.1.0) >/dev/null 2>&1; then
    echo "Release checker accepted a malformed tag" >&2
    exit 1
fi

published_quick_start="$(awk '/# Install the published release/{reading=1} reading{print} reading && /^```$/{exit}' "$ROOT_DIR/README.md")"
if [[ "$published_quick_start" == *"./target/release/screamless"* ]] || [[ "$published_quick_start" != *$'\nscreamless observe'* ]]; then
    echo "Published-release quick start contains source-build-only commands" >&2
    exit 1
fi

echo "Release metadata tests passed"
