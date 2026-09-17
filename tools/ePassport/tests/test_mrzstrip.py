"""Laying the MRZ out inside its band.

The sizing is a plain function so the geometry can be checked without a
window - the bug it guards against was visual but entirely arithmetic.
"""

from __future__ import annotations

import pytest

from epassport.ui.widgets.mrzstrip import CHAR_ADVANCE, LINE_SPACING, fit_rows

TD3 = ["P" * 44, "L" * 44]
TD2 = ["I" * 36, "D" * 36]
TD1 = ["I" * 30, "7" * 30, "E" * 30]

BAND_W = 1000.0
BAND_H = 95.0
MARGIN = 0.055


@pytest.mark.parametrize("rows,label", [(TD3, "TD3"), (TD2, "TD2"), (TD1, "TD1")])
def test_every_format_fits_inside_the_band(rows: list[str], label: str) -> None:
    """A three-line TD1 used to be sized from its width alone, which made the
    glyphs tall enough to overflow the band and cover the fields above."""
    layout = fit_rows(rows, BAND_W, BAND_H, margin=MARGIN)
    assert layout.block_height <= BAND_H, label


@pytest.mark.parametrize("rows,label", [(TD3, "TD3"), (TD2, "TD2"), (TD1, "TD1")])
def test_every_format_fits_the_width(rows: list[str], label: str) -> None:
    layout = fit_rows(rows, BAND_W, BAND_H, margin=MARGIN)
    usable = BAND_W * (1.0 - 2 * MARGIN)
    assert layout.char_width * len(rows[0]) <= usable + 0.001, label


def test_a_three_line_block_is_set_smaller_than_a_two_line_one() -> None:
    assert (
        fit_rows(TD1, BAND_W, BAND_H, margin=MARGIN).font_size
        < fit_rows(TD3, BAND_W, BAND_H, margin=MARGIN).font_size
    )


def test_the_wide_format_is_limited_by_width_not_height() -> None:
    """44 characters across is what constrains a passport's MRZ."""
    layout = fit_rows(TD3, BAND_W, 400.0, margin=MARGIN)
    usable = BAND_W * (1.0 - 2 * MARGIN)
    assert layout.char_width * 44 == pytest.approx(usable, rel=1e-6)
    assert layout.indent == pytest.approx(0.0, abs=0.001)


def test_a_height_limited_block_is_centred_rather_than_left_hugging() -> None:
    layout = fit_rows(TD1, BAND_W, 40.0, margin=MARGIN)
    assert layout.indent > 0


def test_geometry_is_self_consistent() -> None:
    layout = fit_rows(TD3, BAND_W, BAND_H, margin=MARGIN)
    assert layout.char_width == pytest.approx(layout.font_size * CHAR_ADVANCE)
    assert layout.line_height == pytest.approx(layout.font_size * LINE_SPACING)
    assert layout.block_height == pytest.approx(layout.line_height * 2)


def test_a_tiny_band_still_yields_a_usable_font() -> None:
    layout = fit_rows(TD3, 40.0, 6.0, margin=MARGIN)
    assert layout.font_size >= 5.0
    assert layout.char_width > 0


def test_no_rows_does_not_divide_by_zero() -> None:
    layout = fit_rows([], BAND_W, BAND_H, margin=MARGIN)
    assert layout.font_size > 0
    assert layout.block_height > 0


def test_scale_multiplies_the_result() -> None:
    plain = fit_rows(TD3, BAND_W, BAND_H, margin=MARGIN)
    bigger = fit_rows(TD3, BAND_W, BAND_H, margin=MARGIN, scale=2.0)
    assert bigger.font_size == pytest.approx(plain.font_size * 2)


# ------------------------------------------------- geometry per MRZ format
from epassport.ui import theme  # noqa: E402


def test_a_card_is_not_shaped_like_a_passport() -> None:
    """A TD1 is an ID-1 card (85.6 x 54), not a small data page (125 x 88).

    Drawing it at passport aspect with a passport-sized band is what left the
    three-line MRZ unsizable in the first place.
    """
    assert theme.page_aspect("TD1") > theme.page_aspect("TD3")
    assert theme.page_aspect("TD1") == pytest.approx(85.6 / 54.0)
    assert theme.page_aspect("TD3") == pytest.approx(125.0 / 88.0)
    assert theme.page_aspect("TD2") == theme.page_aspect("TD3")


def test_a_three_line_band_takes_a_bigger_share_of_a_smaller_card() -> None:
    assert theme.band_fraction("TD1") > 2 * theme.band_fraction("TD3") * 0.9
    assert 0.20 < theme.band_fraction("TD1") < 0.32
    assert 0.10 < theme.band_fraction("TD3") < 0.16


def test_unknown_or_missing_formats_fall_back_to_the_passport() -> None:
    for kind in (None, "", "TD9", "nonsense"):
        assert theme.page_aspect(kind) == theme.PAGE_ASPECT
        assert theme.band_fraction(kind) == theme.band_fraction("TD3")


@pytest.mark.parametrize("kind,rows", [("TD3", TD3), ("TD2", TD2), ("TD1", TD1)])
def test_each_format_is_legible_in_its_own_band(kind: str, rows: list[str]) -> None:
    """Lay each format out on its real page shape and band, and check the
    characters come out a sensible size relative to the page."""
    page_width = 1000.0
    page_height = page_width / theme.page_aspect(kind)
    band_height = page_height * theme.band_fraction(kind)

    layout = fit_rows(rows, page_width, band_height, margin=MARGIN)
    assert layout.block_height <= band_height

    # Real MRZ print is roughly 2-3% of the document width per character.
    share = layout.char_width / page_width
    assert 0.015 < share < 0.035, f"{kind}: {share:.3f} of the width per character"


def test_line_spacing_lets_three_lines_span_the_document() -> None:
    """Generous spacing shrank a card's MRZ until it no longer reached the
    margins; it should fill most of the printable width, like real print."""
    page_width = 1000.0
    for kind, rows in (("TD3", TD3), ("TD1", TD1)):
        page_height = page_width / theme.page_aspect(kind)
        band = page_height * theme.band_fraction(kind)
        layout = fit_rows(rows, page_width, band, margin=MARGIN)
        usable = page_width * (1.0 - 2 * MARGIN)
        filled = layout.char_width * len(rows[0]) / usable
        assert filled > 0.90, f"{kind} fills only {filled:.0%} of the width"


def test_the_portrait_is_sized_from_the_width_not_the_page_height() -> None:
    """Sizing it as a fraction of page height made it swallow a short card."""
    page_width = 1000.0
    shares = []
    for kind in ("TD3", "TD1"):
        page_height = page_width / theme.page_aspect(kind)
        content = page_height * theme.content_fraction(kind)
        height = min(
            page_width * theme.PHOTO_WIDTH_FRACTION / theme.PHOTO_ASPECT,
            content * theme.PHOTO_MAX_CONTENT_SHARE,
        )
        shares.append(height / content)
    assert all(0.5 < share < 0.8 for share in shares), shares
    assert abs(shares[0] - shares[1]) < 0.1, "both formats give it a similar share"


def test_photo_geometry_matches_a_real_id_photo() -> None:
    assert theme.PHOTO_ASPECT == pytest.approx(35.0 / 45.0)
    assert 0.22 < theme.PHOTO_WIDTH_FRACTION < 0.30


def test_every_format_gets_the_same_mrz_print_size() -> None:
    """OCR-B is a fixed 2.54 mm pitch on a card and on a data page alike.

    Drawing every format to one millimetre scale is what makes that true on
    screen too: a card is smaller than a passport page, so it is drawn
    smaller, and the MRZ ends up the same size in both - as in the hand.
    """
    ref_w, ref_h = theme.REFERENCE_PAGE_MM
    area_w, area_h = 1000.0, 700.0
    scale = min(area_w / ref_w, area_h / ref_h)

    sizes = {}
    for kind, rows in (("TD3", TD3), ("TD1", TD1)):
        doc_w, doc_h = theme.page_size_mm(kind)
        page_w, page_h = doc_w * scale, doc_h * scale
        band = page_h * theme.band_fraction(kind)
        sizes[kind] = fit_rows(rows, page_w, band, margin=MARGIN).font_size

    biggest, smallest = max(sizes.values()), min(sizes.values())
    assert (biggest - smallest) / biggest < 0.05, sizes


def test_a_card_is_drawn_smaller_than_a_data_page() -> None:
    card_w, _card_h = theme.page_size_mm("TD1")
    page_w, _page_h = theme.page_size_mm("TD3")
    assert card_w < page_w
    assert theme.page_size_mm("TD3") == theme.REFERENCE_PAGE_MM
    assert theme.page_size_mm(None) == theme.REFERENCE_PAGE_MM


# ------------------------------------------------------------ resize cost
def test_the_page_is_laid_out_once_and_then_scaled() -> None:
    """Re-flowing the page on every resize event re-rendered every label and
    regenerated the security print, which made dragging a window edge crawl
    and the contents jitter.  It is drawn on a fixed plate and scaled instead.
    """
    import inspect

    from epassport.ui import passport

    assert passport.PX_PER_MM > 0
    plate = inspect.getsource(passport.PagePlate)
    assert "Scatter" in inspect.getsource(passport)
    for locked in ("do_rotation", "do_scale", "do_translation"):
        assert locked in plate, f"{locked} must be pinned - the page is display-only"

    layout = inspect.getsource(passport.AspectBox.do_layout)
    assert ".size =" not in layout, "assigning sizes during layout re-triggers it"
    assert "scale" in layout


def test_the_plate_holds_a_smaller_document_centred() -> None:
    """A card is smaller than the reference page, so it sits centred on it."""
    ref_w, ref_h = theme.REFERENCE_PAGE_MM
    card_w, card_h = theme.page_size_mm("TD1")
    assert card_w < ref_w and card_h < ref_h
    from epassport.ui.passport import PX_PER_MM

    offset_x = (ref_w * PX_PER_MM - card_w * PX_PER_MM) / 2.0
    offset_y = (ref_h * PX_PER_MM - card_h * PX_PER_MM) / 2.0
    assert offset_x > 0 and offset_y > 0
