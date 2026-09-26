#!/usr/bin/env bash
# Install a published Screamless release. Source builds are explicit.

set -euo pipefail

VERSION="${VERSION:-1.1.0}"
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"
REPO="https://github.com/cyberducttape/ScreemLess"
RELEASE_BASE="$REPO/releases/download/v$VERSION"
INSTALL_SERVICE="${INSTALL_SERVICE:-1}"

as_root() {
    if [[ "${EUID:-$(id -u)}" == 0 ]]; then
        "$@"
    else
        sudo "$@"
    fi
}

usage() { echo "Usage: $0 [--from-source] [--no-service]"; }

FROM_SOURCE=0
while (($#)); do
    case "$1" in
        --from-source) FROM_SOURCE=1 ;;
        --no-service) INSTALL_SERVICE=0 ;;
        -h|--help) usage; exit 0 ;;
        *) echo "Unknown option: $1" >&2; usage >&2; exit 3 ;;
    esac
    shift
done

case "$(uname -m)" in
    x86_64) ARTIFACT_ARCH=amd64 ;;
    aarch64|arm64) ARTIFACT_ARCH=arm64 ;;
    *) echo "Unsupported architecture: $(uname -m)" >&2; exit 1 ;;
esac

BUILD_DIR="$(mktemp -d)"
trap 'rm -rf "$BUILD_DIR"' EXIT

if ((FROM_SOURCE)); then
    command -v cargo >/dev/null 2>&1 || { echo "Rust/cargo is required for --from-source" >&2; exit 1; }
    command -v git >/dev/null 2>&1 || { echo "git is required for --from-source" >&2; exit 1; }
    git clone --branch "v$VERSION" --depth 1 "$REPO" "$BUILD_DIR/source"
    (cd "$BUILD_DIR/source" && cargo build --locked --release)
    BINARY="$BUILD_DIR/source/target/release/screamless"
else
    command -v curl >/dev/null 2>&1 || { echo "curl is required" >&2; exit 1; }
    ARCHIVE="screamless-${VERSION}-linux-${ARTIFACT_ARCH}.tar.gz"
    curl --fail --location --silent --show-error "$RELEASE_BASE/$ARCHIVE" -o "$BUILD_DIR/$ARCHIVE"
    curl --fail --location --silent --show-error "$RELEASE_BASE/SHA256SUMS" -o "$BUILD_DIR/SHA256SUMS"
    (cd "$BUILD_DIR" && grep "  $ARCHIVE$" SHA256SUMS | sha256sum --check -)
    tar -xzf "$BUILD_DIR/$ARCHIVE" -C "$BUILD_DIR"
    BINARY="$BUILD_DIR/screamless-${VERSION}/screamless"
fi

[[ -x "$BINARY" ]] || { echo "Release binary was not found" >&2; exit 1; }

if [[ -w "$INSTALL_DIR" ]]; then
    install -D -m 0755 "$BINARY" "$INSTALL_DIR/screamless"
else
    as_root install -D -m 0755 "$BINARY" "$INSTALL_DIR/screamless"
fi

if [[ "$INSTALL_SERVICE" == 1 ]]; then
    DATA_DIR="/var/lib/screamless"
    if [[ "$FROM_SOURCE" == 1 ]]; then
        SERVICE_FILE="$BUILD_DIR/source/packaging/screamless-agent.service"
    else
        SERVICE_FILE="$BUILD_DIR/screamless-${VERSION}/screamless-agent.service"
    fi
    if [[ -f "$SERVICE_FILE" ]]; then
        as_root install -d -m 0750 "$DATA_DIR"
        as_root install -m 0644 "$SERVICE_FILE" /etc/systemd/system/screamless-agent.service
        if command -v systemctl >/dev/null 2>&1; then
            as_root systemctl daemon-reload
            as_root systemctl enable --now screamless-agent.service
        fi
    fi
fi

echo "Screamless $VERSION installed from a verified release artifact."
