"""Kivy UI package.  Importing it registers every bundled ``.kv`` rule set."""

from __future__ import annotations

from pathlib import Path

_LOADED = False

#: Load order matters: leaf widgets before the pages that use them.
KV_FILES = (
    "widgets/fields.kv",
    "passport.kv",
    "tabs/tabs.kv",
    "entry.kv",
    "scan.kv",
    "app.kv",
)


def load_kv() -> None:
    """Load every ``.kv`` file exactly once."""
    global _LOADED
    if _LOADED:
        return
    from kivy.lang import Builder

    here = Path(__file__).resolve().parent
    for name in KV_FILES:
        path = here / name
        if path.is_file():
            Builder.load_file(str(path))
    _LOADED = True
