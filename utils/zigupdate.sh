#!/bin/bash
# Purpose:
# Script for downloading and updating your Zig installation on Linux to latest available version

# Dependency:
# minisign

# Configuration:
INSTALL_DIR="$HOME/zig"
ARCH="$(uname -m)"

LATEST_VERSION=$(curl -s https://ziglang.org/download/index.json | jq '.master.version' | tr -d '"')
INSTALLED_VERSION=$(zig version)
TARBALL="https://ziglang.org/builds/zig-linux-${ARCH}-${LATEST_VERSION}.tar.xz"
TARBALL_SIG="https://ziglang.org/builds/zig-linux-${ARCH}-${LATEST_VERSION}.tar.xz.minisig"
PUB_KEY="$(curl -sq https://ziglang.org/download/index.html | grep -E -o '<code>.+</code>' | cut -d'>' -f2 | cut -d'<' -f1)"

set -x

if [ "$INSTALLED_VERSION" != "$LATEST_VERSION" ]; then
    cd "$(dirname $INSTALL_DIR)"

    [ -f zig-latest.tar.xz ] && rm zig-latest.tar.xz
    [ -d "$(basename $INSTALL_DIR)" ] && rm -rf "$(basename $INSTALL_DIR)"

    wget "$TARBALL" -O "zig-latest.tar.xz"
    wget "$TARBALL_SIG" -O "zig-latest.tar.xz.minisig"

    # check tarball's signature
    minisign -V -P "${PUB_KEY}" -x "zig-latest.tar.xz.minisig" -m "zig-latest.tar.xz"
    if [ $? -eq 1 ]; then exit 1; fi

    tar xf "zig-latest.tar.xz"
    mv "zig-linux-$ARCH-$LATEST_VERSION" "$(basename $INSTALL_DIR)"

    [ -f zig-latest.tar.xz ] && rm zig-latest.tar.xz
    [ -f zig-latest.tar.xz ] && rm zig-latest.tar.xz.minisig

    echo "Make sure that you Zig install dir: ${INSTALL_DIR} is in your PATH environment variable."
fi
