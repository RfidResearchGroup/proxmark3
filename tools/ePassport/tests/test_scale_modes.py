"""Fitting the page into the window.

A card's MRZ takes about 2.97% of its width per character; a passport's takes
2.03%.  Scale both documents to the same screen width and the card's MRZ comes
out half again as large; make the MRZ match and the card must be drawn smaller.
Both are defensible, so the app offers both - and these tests pin what each
one promises.
"""

from __future__ import annotations

import pytest

from epassport.ui import theme
from epassport.ui.passport import (
    FIT_TO_WINDOW,
    PX_PER_MM,
    SCALE_MODES,
    TRUE_SCALE,
    page_scale,
)

AREA = (1000.0, 700.0)
REF = (theme.REFERENCE_PAGE_MM[0] * PX_PER_MM, theme.REFERENCE_PAGE_MM[1] * PX_PER_MM)


def page_px(kind: str) -> tuple[float, float]:
    w, h = theme.page_size_mm(kind)
    return (w * PX_PER_MM, h * PX_PER_MM)


def test_both_modes_exist() -> None:
    assert set(SCALE_MODES) == {FIT_TO_WINDOW, TRUE_SCALE}


@pytest.mark.parametrize("kind", ["TD3", "TD1"])
def test_fit_fills_one_dimension_exactly(kind: str) -> None:
    """Whatever the format, fitting must use all the space it can."""
    page = page_px(kind)
    scale = page_scale(FIT_TO_WINDOW, AREA, page, REF)
    shown = (page[0] * scale, page[1] * scale)
    fills_width = shown[0] == pytest.approx(AREA[0])
    fills_height = shown[1] == pytest.approx(AREA[1])
    assert fills_width or fills_height, shown
    assert shown[0] <= AREA[0] + 0.001 and shown[1] <= AREA[1] + 0.001


def test_fit_makes_a_card_bigger_on_screen_than_true_scale() -> None:
    card = page_px("TD1")
    assert page_scale(FIT_TO_WINDOW, AREA, card, REF) > page_scale(
        TRUE_SCALE, AREA, card, REF
    )


def test_true_scale_is_the_same_for_every_format() -> None:
    scales = {
        kind: page_scale(TRUE_SCALE, AREA, page_px(kind), REF)
        for kind in ("TD3", "TD1")
    }
    assert scales["TD3"] == pytest.approx(scales["TD1"])


def test_the_reference_page_is_identical_in_both_modes() -> None:
    """A passport fills the window either way; only smaller formats differ."""
    page = page_px("TD3")
    assert page_scale(FIT_TO_WINDOW, AREA, page, REF) == pytest.approx(
        page_scale(TRUE_SCALE, AREA, page, REF)
    )


def test_true_scale_keeps_mrz_print_matched_across_formats() -> None:
    from epassport.ui.widgets.mrzstrip import fit_rows

    on_screen = {}
    for kind, rows in (("TD3", ["P" * 44, "L" * 44]), ("TD1", ["I" * 30] * 3)):
        page_w, page_h = page_px(kind)
        scale = page_scale(TRUE_SCALE, AREA, (page_w, page_h), REF)
        band = page_h * theme.band_fraction(kind)
        on_screen[kind] = fit_rows(rows, page_w, band, margin=0.055).font_size * scale
    biggest, smallest = max(on_screen.values()), min(on_screen.values())
    assert (biggest - smallest) / biggest < 0.05, on_screen


def test_fit_deliberately_does_not_match_mrz_print() -> None:
    """Documented consequence, asserted so nobody 'fixes' it by accident."""
    from epassport.ui.widgets.mrzstrip import fit_rows

    on_screen = {}
    for kind, rows in (("TD3", ["P" * 44, "L" * 44]), ("TD1", ["I" * 30] * 3)):
        page_w, page_h = page_px(kind)
        scale = page_scale(FIT_TO_WINDOW, AREA, (page_w, page_h), REF)
        band = page_h * theme.band_fraction(kind)
        on_screen[kind] = fit_rows(rows, page_w, band, margin=0.055).font_size * scale
    assert on_screen["TD1"] > on_screen["TD3"] * 1.2


def test_a_degenerate_area_does_not_divide_by_zero() -> None:
    for mode in SCALE_MODES:
        assert page_scale(mode, (0, 0), page_px("TD3"), REF) == 1.0
        assert page_scale(mode, AREA, (0, 0), REF) > 0


def test_the_mode_is_remembered(tmp_path) -> None:
    from epassport.config import Settings

    path = tmp_path / "settings.json"
    Settings(page_scale_mode=TRUE_SCALE).save(path)
    assert Settings.load(path).page_scale_mode == TRUE_SCALE
    assert Settings().page_scale_mode == FIT_TO_WINDOW


def test_the_toolbar_toggles_are_labelled_the_same_way() -> None:
    """Both buttons must name the ACTION, not the current state.

    Sitting side by side with opposite conventions, the scale button read
    "True size" while already in true-size mode - which looks exactly like a
    button offering to switch to it.
    """
    from pathlib import Path

    kv = (Path(__file__).parent.parent / "epassport" / "ui" / "app.kv").read_text()

    # chrome: shows "Dark chrome" while NOT dark -> names the action
    assert 'text: "Dark chrome" if not app.dark else "Light chrome"' in kv
    # scale: shows "True size" while fitting -> also names the action
    assert 'text: "True size" if app.scale_mode == "fit" else "Fit window"' in kv


def test_loading_a_new_format_refits_the_page() -> None:
    """The fit depends on the document's size, so a new format must re-fit.

    Without this, opening a card after a passport kept the passport's scale
    and the card sat at 59% of the area until something else forced a layout -
    which looked like the fit button needing a press after every load.
    """
    import inspect

    from epassport.ui import passport

    on_size = inspect.getsource(passport.PassportPage.on_page_size_mm)
    assert "self.refit()" in on_size

    refit = inspect.getsource(passport.PassportPage.refit)
    # It must walk up to the AspectBox: the plate in between is a Scatter and
    # has no layout, so calling _trigger_layout on the immediate parent throws.
    assert "AspectBox" in refit
    assert "self.parent.parent" not in refit, "walk the chain, do not assume depth"


def test_refit_walks_past_a_plate_to_the_layout() -> None:
    from epassport.ui.passport import AspectBox, PassportPage

    class Stub:
        parent = None

    triggered: list[int] = []

    class FakeBox(AspectBox):
        def _trigger_layout(self, *a, **k):
            triggered.append(1)

    box = FakeBox.__new__(FakeBox)
    box.parent = None
    plate = Stub()
    plate.parent = box
    page = PassportPage.__new__(PassportPage)
    page.parent = plate

    PassportPage.refit(page)
    assert triggered == [1]


def test_refit_is_harmless_before_the_page_is_parented() -> None:
    from epassport.ui.passport import PassportPage

    orphan = PassportPage.__new__(PassportPage)
    orphan.parent = None
    PassportPage.refit(orphan)  # must not raise


def test_the_default_window_suits_the_reference_document() -> None:
    """Otherwise a passport is letterboxed the moment you open the app."""
    from epassport.config import Settings

    settings = Settings()
    pad_w, chrome_h = theme.WINDOW_CHROME_PX
    content = (
        settings.window_width - pad_w,
        settings.window_height - chrome_h,
    )
    assert content[0] / content[1] == pytest.approx(theme.PAGE_ASPECT, rel=0.01)


def test_the_suggested_window_matches_the_stored_default() -> None:
    from epassport.config import Settings

    settings = Settings()
    width, height = theme.window_for_reference(settings.window_width)
    assert abs(height - settings.window_height) <= 2, (height, settings.window_height)


def test_the_default_window_clears_the_minimum() -> None:
    from epassport.config import Settings

    settings = Settings()
    assert settings.window_width >= 760
    assert settings.window_height >= 520
