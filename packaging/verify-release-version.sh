#!/usr/bin/env bash
set -euo pipefail

if [[ $# -gt 1 ]]; then
    echo "Usage: $0 [VERSION_TAG]" >&2
    exit 3
fi

package_version="$(cargo metadata --locked --offline --no-deps --format-version 1 | python3 -c '
import json, sys
packages = [package["version"] for package in json.load(sys.stdin)["packages"] if package["name"] == "screamless"]
if len(packages) != 1:
    raise SystemExit("expected exactly one screamless package in cargo metadata")
print(packages[0])
')"

if [[ $# -eq 1 ]]; then
    release_tag="$1"
    if [[ ! "$release_tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$ ]]; then
        echo "Release tag must be v<semver>" >&2
        exit 1
    fi
    if [[ "${release_tag#v}" != "$package_version" ]]; then
        echo "Release tag ${release_tag#v} does not match Cargo package version $package_version" >&2
        exit 1
    fi
fi

installer_version="$(sed -nE 's/^VERSION="\$\{VERSION:-([^}]+)\}"$/\1/p' install.sh)"
if [[ "$installer_version" != "$package_version" ]]; then
    echo "Installer default version '$installer_version' does not match Cargo version $package_version" >&2
    exit 1
fi

python3 - "$package_version" CHANGELOG.md README.md QUICKSTART.md <<'PY'
import re
import sys

expected = sys.argv[1]
changelog = open(sys.argv[2], encoding="utf-8").read()
heading = re.compile(r"^## \[" + re.escape(expected) + r"\] - \d{4}-\d{2}-\d{2}$", re.MULTILINE)
if not heading.search(changelog):
    raise SystemExit(f"CHANGELOG.md has no dated heading for version {expected}")

patterns = (
    re.compile(r"(?:/v|--branch v)(\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?)"),
    re.compile(r"screamless[-_](\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?)(?=-(?:linux-|source)|_(?:amd64|arm64)|-1\.)"),
)
for path in sys.argv[3:]:
    text = open(path, encoding="utf-8").read()
    for pattern in patterns:
        for version in pattern.findall(text):
            if version != expected:
                raise SystemExit(f"{path} references release {version}, expected {expected}")
PY

echo "Release metadata is consistent at version $package_version"
