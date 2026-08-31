"""Splitting long text across Labels.

A Label is drawn into a single texture, and OpenGL caps texture size at
commonly 16384px.  A monospace line here is about 13px, so one Label past
roughly 1260 lines silently fails to render and the pane draws nothing at
all - no error with it.  Anything unbounded is split over several Labels.
"""

from __future__ import annotations

#: Lines per Label.  Half the headroom of the smallest maximum we expect.
ROWS_PER_BLOCK = 512


def split_blocks(rows: list[str], *, size: int = ROWS_PER_BLOCK) -> list[str]:
    """``rows`` grouped into chunks of at most ``size``, each joined."""
    return ["\n".join(rows[at : at + size]) for at in range(0, len(rows), size)]
