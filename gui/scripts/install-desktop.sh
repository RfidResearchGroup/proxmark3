#!/usr/bin/env bash
set -euo pipefail

# Install the desktop file to the user's local applications directory
APP_DIR="$HOME/.local/share/applications"
mkdir -p "$APP_DIR"

SRC_DIR="$(dirname "$0")/.."
DESKTOP_IN="$SRC_DIR/pm3-gui.desktop.in"
DESKTOP_OUT="$APP_DIR/pm3-gui.desktop"

if [ ! -f "$DESKTOP_IN" ]; then
  echo "Desktop template not found: $DESKTOP_IN" >&2
  exit 1
fi

cp "$DESKTOP_IN" "$DESKTOP_OUT"
echo "Installed $DESKTOP_OUT"

echo "You may need to run 'update-desktop-database' to refresh the menu (system dependent)."
