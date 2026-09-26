#!/usr/bin/env bash
# Install a published Screamless release. Source builds are explicit.

set -euo pipefail

VERSION="${VERSION:-1.1.0}"
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"
REPO="https://github.com/cyberducttape/ScreemLess"
RELEASE_BASE="$REPO/releases/download/v$VERSION"
INSTALL_SERVICE="${INSTALL_SERVICE:-1}"

if [[ ! "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$ ]]; then
    echo "VERSION must be a semantic version (for example 1.1.0)" >&2
    exit 3
fi
if [[ ! "$INSTALL_DIR" =~ ^(/[[:alnum:]_.-]+)+/?$ ]]; then
    echo "INSTALL_DIR must be an absolute path using only letters, numbers, '.', '_', and '-'" >&2
    exit 3
fi
INSTALL_DIR="${INSTALL_DIR%/}"

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
    command -v cosign >/dev/null 2>&1 || {
        echo "cosign is required to authenticate release checksums; install cosign and retry" >&2
        exit 1
    }
    ARCHIVE="screamless-${VERSION}-linux-${ARTIFACT_ARCH}.tar.gz"
    curl --fail --location --silent --show-error "$RELEASE_BASE/$ARCHIVE" -o "$BUILD_DIR/$ARCHIVE"
    curl --fail --location --silent --show-error "$RELEASE_BASE/SHA256SUMS" -o "$BUILD_DIR/SHA256SUMS"
    curl --fail --location --silent --show-error "$RELEASE_BASE/SHA256SUMS.sig" -o "$BUILD_DIR/SHA256SUMS.sig"
    curl --fail --location --silent --show-error "$RELEASE_BASE/SHA256SUMS.pem" -o "$BUILD_DIR/SHA256SUMS.pem"
    cosign verify-blob "$BUILD_DIR/SHA256SUMS" \
        --signature "$BUILD_DIR/SHA256SUMS.sig" \
        --certificate "$BUILD_DIR/SHA256SUMS.pem" \
        --certificate-identity "https://github.com/cyberducttape/ScreemLess/.github/workflows/release.yml@refs/tags/v${VERSION}" \
        --certificate-oidc-issuer "https://token.actions.githubusercontent.com"
    (cd "$BUILD_DIR" && awk -v file="$ARCHIVE" '$2 == file { print; count++ } END { exit count != 1 }' SHA256SUMS | sha256sum --check -)
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
        SERVICE_ACTIVATION="$BUILD_DIR/source/packaging/service-activation.sh"
        SERVICE_RENDERER="$BUILD_DIR/source/packaging/render-service-unit.sh"
    else
        SERVICE_FILE="$BUILD_DIR/screamless-${VERSION}/screamless-agent.service"
        SERVICE_ACTIVATION="$BUILD_DIR/screamless-${VERSION}/service-activation.sh"
        SERVICE_RENDERER="$BUILD_DIR/screamless-${VERSION}/render-service-unit.sh"
    fi
    if [[ ! -f "$SERVICE_FILE" || ! -f "$SERVICE_ACTIVATION" || ! -f "$SERVICE_RENDERER" ]]; then
        echo "Agent service files are missing from the installation source" >&2
        exit 1
    fi
    if [[ "$INSTALL_DIR" != "/usr/local/bin" ]]; then
        CUSTOM_SERVICE_FILE="$BUILD_DIR/screamless-agent-custom.service"
        bash "$SERVICE_RENDERER" "$SERVICE_FILE" "$INSTALL_DIR/screamless" > "$CUSTOM_SERVICE_FILE"
        SERVICE_FILE="$CUSTOM_SERVICE_FILE"
    fi

    as_root install -d -m 0750 "$DATA_DIR"
    as_root install -m 0644 "$SERVICE_FILE" /etc/systemd/system/screamless-agent.service
    if command -v systemctl >/dev/null 2>&1 && [[ -d /run/systemd/system ]]; then
        as_root sh "$SERVICE_ACTIVATION" --run
    else
        echo "systemd is not running; enable screamless-agent.service after boot" >&2
    fi
fi

if ((FROM_SOURCE)); then
    echo "Screamless $VERSION installed from a source build."
else
    echo "Screamless $VERSION installed from a verified release artifact."
fi
