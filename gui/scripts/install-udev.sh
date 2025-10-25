#!/usr/bin/env bash
set -euo pipefail

RULES_SRC="$(dirname "$0")/udev_rules.txt"
RULES_DST="/etc/udev/rules.d/99-proxmark3.rules"

if [ "$EUID" -ne 0 ]; then
  echo "This script must be run as root to install udev rules. See gui/scripts/udev_rules.txt for manual steps." >&2
  exit 2
fi

if [ ! -f "$RULES_SRC" ]; then
  echo "Rules template not found: $RULES_SRC" >&2
  exit 1
fi

cp "$RULES_SRC" "$RULES_DST"
chmod 644 "$RULES_DST"
echo "Installed $RULES_DST"
udevadm control --reload-rules
udevadm trigger
echo "Reloaded udev rules. Unplug and replug your device if needed."
