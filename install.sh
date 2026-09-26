#!/bin/bash
# Screamless Installation Script
# Downloads pre-built binary or builds from source

set -euo pipefail

VERSION="1.0.0"
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"
REPO="https://github.com/cyberducttape/ScreemLess"
BRANCH="master"

echo "🔍 Screamless $VERSION Installer"
echo "=================================="
echo ""

# Check if already installed
if command -v screamless &> /dev/null; then
    CURRENT=$(screamless --version 2>/dev/null || echo "unknown")
    echo "✓ Screamless already installed: $CURRENT"
    read -p "Reinstall? (y/N) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 0
    fi
fi

# Check for Rust
if ! command -v cargo &> /dev/null; then
    echo "❌ Rust not found. Install from https://rustup.rs/"
    exit 1
fi

echo "Building Screamless..."
BUILD_DIR="$(mktemp -d)"
trap 'rm -rf "$BUILD_DIR"' EXIT
cd "$BUILD_DIR"
git clone --branch "$BRANCH" --depth 1 "$REPO" .
cargo build --locked --release

BINARY="target/release/screamless"

if [ ! -f "$BINARY" ]; then
    echo "❌ Build failed"
    exit 1
fi

# Install
echo ""
echo "Installing to $INSTALL_DIR..."
if [ ! -w "$INSTALL_DIR" ]; then
    echo "Note: sudo required for installation"
    sudo install -D -m 0755 "$BINARY" "$INSTALL_DIR/screamless"
else
    install -D -m 0755 "$BINARY" "$INSTALL_DIR/screamless"
fi

echo ""
echo "✅ Screamless installed successfully!"
echo ""
echo "Quick start:"
echo "  screamless snapshot              # Collect one observation"
echo "  screamless observe --duration 7d # Observe for 7 days"
echo "  screamless report                # Generate report"
echo "  screamless dashboard             # Interactive dashboard"
echo ""
echo "Full docs: $REPO/blob/$BRANCH/README.md"
