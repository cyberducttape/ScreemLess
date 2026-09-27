#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PACKAGE_VERSION="$(awk -F '"' '/^version = / { print $2; exit }' "$ROOT/Cargo.toml")"
SMOKE_DIR="$(mktemp -d)"
trap 'rm -rf "$SMOKE_DIR"' EXIT

[[ -x "$ROOT/target/release/screamless" ]] || {
    echo "Build target/release/screamless before running package smoke tests" >&2
    exit 1
}

cd "$ROOT"
VERSION="$PACKAGE_VERSION" go run github.com/goreleaser/nfpm/v2/cmd/nfpm@v2.47.0 \
    package --packager deb --config packaging/nfpm.yaml --target "$SMOKE_DIR"
VERSION="$PACKAGE_VERSION" go run github.com/goreleaser/nfpm/v2/cmd/nfpm@v2.47.0 \
    package --packager rpm --config packaging/nfpm.yaml --target "$SMOKE_DIR"

DEB="$SMOKE_DIR/screamless_${PACKAGE_VERSION}_amd64.deb"
RPM="$SMOKE_DIR/screamless-${PACKAGE_VERSION}-1.x86_64.rpm"
[[ -s "$DEB" && -s "$RPM" ]]
[[ "$(dpkg-deb --field "$DEB" Package)" == screamless ]]
[[ "$(dpkg-deb --field "$DEB" Version)" == "$PACKAGE_VERSION" ]]
[[ "$(dpkg-deb --field "$DEB" Architecture)" == amd64 ]]

EXTRACTED="$SMOKE_DIR/extracted"
CONTROL="$SMOKE_DIR/control"
dpkg-deb --extract "$DEB" "$EXTRACTED"
dpkg-deb --control "$DEB" "$CONTROL"
[[ -x "$EXTRACTED/usr/local/bin/screamless" ]]
[[ -f "$EXTRACTED/etc/systemd/system/screamless-agent.service" ]]
[[ -x "$EXTRACTED/usr/lib/screamless/service-activation.sh" ]]
for script in postinst prerm postrm; do
    [[ -x "$CONTROL/$script" ]]
    sh -n "$CONTROL/$script"
done

file "$RPM" | grep -q 'RPM'
echo "Verified Debian and RPM artifacts for screamless $PACKAGE_VERSION"
