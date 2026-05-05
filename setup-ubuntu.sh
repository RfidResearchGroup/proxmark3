#!/usr/bin/env bash
# setup-ubuntu.sh — One-shot Proxmark3 setup for Debian/Ubuntu/Kali
#
# Installs all build dependencies, handles ModemManager (udev rule preferred
# over full disable), installs device permission rules, and adds user to the
# required groups.
#
# Usage: bash setup-ubuntu.sh
# Idempotent: safe to re-run on an already-configured machine.

set -euo pipefail

# --- Distro check ---
if ! command -v apt-get &>/dev/null; then
    echo "ERROR: This script requires apt-get (Debian/Ubuntu/Kali). Exiting." >&2
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "==> Updating package lists..."
sudo apt-get update -q

echo "==> Installing build dependencies..."
sudo apt-get install --no-install-recommends -y \
    git ca-certificates build-essential pkg-config \
    libreadline-dev gcc-arm-none-eabi libnewlib-dev \
    libbz2-dev liblz4-dev zlib1g-dev \
    libbluetooth-dev libpython3-dev libssl-dev libgd-dev

# Qt6 for GUI support (optional but included by default)
if apt-cache show qt6-base-dev &>/dev/null 2>&1; then
    sudo apt-get install --no-install-recommends -y qt6-base-dev
elif apt-cache show qtbase5-dev &>/dev/null 2>&1; then
    echo "    Qt6 not available, installing Qt5 fallback..."
    sudo apt-get install --no-install-recommends -y qtbase5-dev
else
    echo "    WARNING: Neither Qt6 nor Qt5 dev packages found. GUI support will be disabled."
fi

# --- ModemManager handling ---
echo "==> Handling ModemManager..."
# ModemManager probes new serial devices with AT commands and can interfere
# with the Proxmark3. A udev rule to ignore the PM3 VID is preferred over
# disabling ModemManager entirely (which would break cellular modems).
UDEV_MM_RULE='/etc/udev/rules.d/77-mm-proxmark3.rules'
if [[ ! -f "$UDEV_MM_RULE" ]]; then
    echo 'ATTRS{idVendor}=="9ac4", ENV{ID_MM_DEVICE_IGNORE}="1"' | sudo tee "$UDEV_MM_RULE" > /dev/null
    echo "    ModemManager ignore rule written to $UDEV_MM_RULE"
else
    echo "    ModemManager ignore rule already exists."
fi

# --- Device permissions ---
echo "==> Setting device permissions..."
if [[ -f "$SCRIPT_DIR/Makefile" ]]; then
    # Use the repo's built-in accessrights target if available
    make -C "$SCRIPT_DIR" accessrights 2>/dev/null || true
fi

# Ensure user is in dialout and plugdev groups
for group in dialout plugdev; do
    if getent group "$group" &>/dev/null; then
        if ! id -nG "$USER" | grep -qw "$group"; then
            sudo usermod -aG "$group" "$USER"
            echo "    Added $USER to $group group."
        else
            echo "    $USER already in $group group."
        fi
    fi
done

# --- Reload udev ---
echo "==> Reloading udev rules..."
sudo udevadm control --reload-rules && sudo udevadm trigger

echo ""
echo "==> Setup complete."
echo ""
echo "    ACTION REQUIRED: Log out and back in for group membership to take effect."
echo ""
echo "    Then build with:"
echo "      make clean && make -j\$(nproc)"
echo ""
echo "    Flash:"
echo "      ./pm3-flash-bootrom"
echo "      ./pm3-flash-fullimage"
echo ""
echo "    Run client:"
echo "      ./pm3"
