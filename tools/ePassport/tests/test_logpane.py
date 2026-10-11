"""The pm3 log pane.

Long text has to be split across several Labels: a Label is drawn into one
texture, and OpenGL caps texture size at commonly 16384px.  A log line is
about 13px, so the pane went blank somewhere past 1260 lines - and it holds
4000, so a talkative dump lost its output entirely.
"""

from __future__ import annotations

from epassport.ui.widgets import textblocks


def test_a_long_log_is_split_into_blocks_a_texture_can_hold() -> None:
    rows = [f"[+] line {i}" for i in range(4000)]
    blocks = textblocks.split_blocks(rows)
    assert len(blocks) > 1
    assert all(b.count("\n") + 1 <= textblocks.ROWS_PER_BLOCK for b in blocks)


def test_blocks_join_back_into_the_whole_log() -> None:
    rows = [f"line {i}" for i in range(1500)]
    assert "\n".join(textblocks.split_blocks(rows)) == "\n".join(rows)


def test_a_short_log_stays_a_single_block() -> None:
    assert textblocks.split_blocks(["one", "two"]) == ["one\ntwo"]


def test_no_lines_is_no_blocks() -> None:
    assert textblocks.split_blocks([]) == []


def test_rows_per_block_leaves_headroom_under_the_texture_limit() -> None:
    assert textblocks.ROWS_PER_BLOCK * 13 <= 16384 / 2
