"""Startup checks.  These run in a subprocess: importing the app builds the
Kivy window, so a segfault would take the test session down with it."""

from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
LAUNCHER = ROOT / "ePassport.py"


@pytest.mark.skipif(
    not (os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY")),
    reason="starting the app needs a display",
)
def test_the_launcher_starts() -> None:
    """--help must not die on a signal."""
    proc = subprocess.run(
        [sys.executable, str(LAUNCHER), "--help"],
        capture_output=True,
        text=True,
        timeout=180,
        env={**os.environ, "KIVY_NO_CONSOLELOG": "1"},
    )
    how = (
        f"killed by signal {-proc.returncode}"
        if proc.returncode < 0
        else f"exited {proc.returncode}"
    )
    assert proc.returncode == 0, f"--help {how}\n{proc.stderr[-2000:]}"
    assert "--dump" in proc.stdout


@pytest.mark.skipif(
    not (os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY")),
    reason="importing the app builds a window, which needs a display",
)
def test_a_kivy_warning_does_not_take_the_app_down_with_it() -> None:
    """A Kivy warning must not loop through the stderr Kivy replaced."""
    proc = subprocess.run(
        [
            sys.executable,
            "-c",
            "import sys; sys.path.insert(0, %r)\n" % str(ROOT)
            + "from epassport.app import _install_kivy_logging\n"
            + "from kivy.logger import Logger\n"
            + "_install_kivy_logging(False)\n"
            + "Logger.warning('an ordinary kivy warning')\n",
        ],
        capture_output=True,
        text=True,
        timeout=180,
    )
    assert proc.returncode == 0, f"exited {proc.returncode}\n{proc.stderr[-2000:]}"
    assert "RecursionError" not in proc.stderr


def test_the_window_minimum_is_not_pre_seeded_into_kivy_config() -> None:
    """Read the source: importing the app to check is what crashed."""
    source = (ROOT / "epassport" / "app.py").read_text()
    assert not re.search(
        r"""Config\.set\(\s*['"]graphics['"]\s*,\s*['"]minimum_""", source
    ), "the minimum size must be set on Window, not pre-seeded into Config"
