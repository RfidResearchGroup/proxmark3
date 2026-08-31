"""The hex dump renderer."""

from __future__ import annotations

from epassport.ui.widgets.hexview import hexdump


def test_layout_is_offset_hex_ascii() -> None:
    line = hexdump(b"ABC").splitlines()[0]
    assert line.startswith("00000000  41 42 43")
    assert line.endswith("|ABC|")


def test_short_final_row_is_padded_so_the_ascii_gutter_lines_up() -> None:
    rows = hexdump(bytes(range(20))).splitlines()
    assert len(rows) == 2
    assert rows[0].index("|") == rows[1].index("|")


def test_non_printable_bytes_become_dots() -> None:
    assert hexdump(b"\x00\x1f\x7f\x80").endswith("|....|")


def test_empty_input() -> None:
    assert hexdump(b"") == "(empty)"


def test_large_input_is_truncated_with_a_note() -> None:
    out = hexdump(b"\x00" * 100, limit=32)
    assert "68 more bytes not shown" in out


# ------------------------------------------------ fitting a narrow pane
from epassport.ui.widgets import hexview  # noqa: E402


def test_row_width_is_configurable() -> None:
    rows = hexdump(bytes(range(16)), width=8).splitlines()
    assert len(rows) == 2
    assert rows[0].startswith("00000000  00 01 02 03 04 05 06 07")
    assert rows[1].startswith("00000008  08 09 0A 0B 0C 0D 0E 0F")


def test_narrow_rows_still_line_up() -> None:
    rows = hexdump(bytes(range(12)), width=8).splitlines()
    assert rows[0].index("|") == rows[1].index("|")


def test_sample_row_is_worst_case() -> None:
    row = hexview.sample_row(16)
    assert row.count("FF") == 16
    assert row.endswith("|" + "W" * 16 + "|")
    assert len(hexview.sample_row(8)) < len(row)


def test_fit_row_bytes_picks_the_widest_that_fits(monkeypatch) -> None:
    widths = {16: 500.0, 8: 300.0, 4: 180.0}
    monkeypatch.setattr(hexview, "measure_row_width", lambda n: widths[n])
    view = hexview.HexView.__new__(hexview.HexView)  # no Kivy widget tree needed
    assert view.fit_row_bytes(900) == 16
    assert view.fit_row_bytes(500) == 16
    assert view.fit_row_bytes(499) == 8
    assert view.fit_row_bytes(299) == 4
    assert view.fit_row_bytes(10) == 4


def test_fit_row_bytes_before_layout_assumes_the_widest(monkeypatch) -> None:
    monkeypatch.setattr(hexview, "measure_row_width", lambda n: 500.0)
    view = hexview.HexView.__new__(hexview.HexView)
    assert view.fit_row_bytes(0) == 16


# ------------------------------------- splitting a dump the GPU can draw
def test_a_long_dump_is_split_into_blocks_a_texture_can_hold() -> None:
    """One Label per dump made a DG2 vanish.

    A Label is drawn into a single texture, and a dump line is about 13px, so
    past roughly 1260 lines the texture exceeds the 16384px OpenGL maximum,
    fails to be created, and the pane draws nothing at all - no error either.
    """
    blocks = hexview.hexdump_blocks(bytes(40_000), width=16)
    assert len(blocks) > 1
    assert all(b.count("\n") + 1 <= hexview.ROWS_PER_BLOCK for b in blocks)


def test_blocks_join_back_into_exactly_the_one_piece_dump() -> None:
    data = bytes(range(256)) * 20
    assert "\n".join(hexview.hexdump_blocks(data, width=16)) == hexdump(data, width=16)


def test_a_short_dump_stays_a_single_block() -> None:
    assert hexview.hexdump_blocks(b"ABC") == [hexdump(b"ABC")]


def test_empty_input_is_still_one_block() -> None:
    assert hexview.hexdump_blocks(b"") == ["(empty)"]


def test_rows_per_block_leaves_headroom_under_the_texture_limit() -> None:
    """16384px is the common maximum; a smaller one must not be marginal."""
    assert hexview.ROWS_PER_BLOCK * 13 <= 16384 / 2
