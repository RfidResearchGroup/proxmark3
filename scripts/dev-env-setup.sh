#!/usr/bin/env bash
# Proxmark3 dev environment — client + ARM firmware toolchain
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

echo "[dev-env] Installing build dependencies..."
export DEBIAN_FRONTEND=noninteractive
sudo apt-get update -qq
sudo apt-get install -y --no-install-recommends \
    build-essential \
    git \
    pkg-config \
    libreadline-dev \
    libbz2-dev \
    liblz4-dev \
    zlib1g-dev \
    libbluetooth-dev \
    libpython3-dev \
    libssl-dev \
    libgd-dev \
    libjansson-dev \
    gcc-arm-none-eabi \
    libnewlib-dev \
    cmake

if [ ! -f Makefile.platform ]; then
    echo "[dev-env] Creating Makefile.platform (PM3GENERIC)..."
    cp Makefile.platform.sample Makefile.platform
    sed -i 's/^PLATFORM=PM3RDV4/#PLATFORM=PM3RDV4/' Makefile.platform
    sed -i 's/^#PLATFORM=PM3GENERIC/PLATFORM=PM3GENERIC/' Makefile.platform
fi

echo "[dev-env] Toolchain:"
arm-none-eabi-gcc --version | head -1 || echo "  (arm-none-eabi-gcc not on PATH)"
gcc --version | head -1

echo "[dev-env] Building client..."
make clean
CC=gcc make -j"$(nproc)" -C client

echo "[dev-env] Building fpga_compress (required for firmware)..."
make -j"$(nproc)" fpga_compress

echo "[dev-env] ARM firmware build smoke..."
make -j"$(nproc)" -C armsrc 2>/dev/null || echo "  (armsrc build may need full 'make' at repo root)"

echo "[dev-env] Ready. Examples:"
echo "  ./pm3 -- emv test"
echo "  ./pm3 -- emv terminal test --golden"
echo "  make -C arms   # firmware (requires Makefile.platform)"
