#!/usr/bin/env bash
# Helper wrapper intended to be invoked via pkexec or sudo from the GUI.
set -euo pipefail

SCRIPT_DIR="$(dirname "$0")"
SRC="$SCRIPT_DIR/udev_rules.txt"
DST="/etc/udev/rules.d/99-proxmark3.rules"

if [ ! -f "$SRC" ]; then
  echo "udev rules template missing: $SRC" >&2
  exit 1
fi

cp "$SRC" "$DST"
chmod 644 "$DST"
udevadm control --reload-rules
udevadm trigger
echo "Installed $DST"
