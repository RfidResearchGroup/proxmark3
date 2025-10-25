#!/usr/bin/env bash
set -euo pipefail

# Minimal helper to build an AppImage locally using appimage-builder.
# Requires: Python environment with appimage-builder installed and the appimage-builder CLI available.

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
RECIPE="$REPO_ROOT/gui/packaging/appimage.yml"

if ! command -v appimage-builder >/dev/null 2>&1; then
  echo "Please install appimage-builder (pip install appimage-builder)" >&2
  exit 2
fi

echo "Running appimage-builder with recipe: $RECIPE"
appimage-builder --recipe "$RECIPE"

echo "AppImage build attempted. Check output for artifacts (dist/)."
