"""The page's security print stays inside the printed frame."""

from __future__ import annotations

import pytest

from epassport.ui.widgets import guilloche


class _Fake:
    """Just enough of a widget for the geometry helpers."""

    def __init__(self, x: float, y: float, bottom_inset: float = 0.0) -> None:
        self.x = x
        self.y = y
        self.bottom_inset = bottom_inset

    _frame_rect = guilloche.Guilloche._frame_rect


def test_frame_is_inset_from_the_paper_edge() -> None:
    fx, fy, fw, fh = _Fake(0, 0)._frame_rect(700, 500)
    inset = min(700, 500) * 0.022
    assert fx == pytest.approx(inset)
    assert fy == pytest.approx(inset)
    assert fw == pytest.approx(700 - 2 * inset)
    assert fh == pytest.approx(500 - 2 * inset)


def test_frame_follows_the_widget_position() -> None:
    fx, fy, _w, _h = _Fake(120, 40)._frame_rect(700, 500)
    inset = min(700, 500) * 0.022
    assert fx == pytest.approx(120 + inset)
    assert fy == pytest.approx(40 + inset)


def test_the_mrz_band_raises_the_frame_floor() -> None:
    """The band is full-bleed, so the frame must stop above it - otherwise
    the rule runs on behind the band and pokes out at the corners."""
    plain = _Fake(0, 0)._frame_rect(700, 500)
    banded = _Fake(0, 0, bottom_inset=64)._frame_rect(700, 500)
    assert banded[1] == pytest.approx(64)
    assert banded[3] == pytest.approx(plain[1] + plain[3] - 64)
    assert banded[3] < plain[3]


def test_a_tiny_widget_never_yields_a_negative_frame() -> None:
    fx, fy, fw, fh = _Fake(0, 0, bottom_inset=500)._frame_rect(700, 500)
    assert fh >= 0


def test_rosettes_are_clipped_in_geometry_not_with_a_stencil() -> None:
    """A stencil here silently stops working when the widget is nested.

    Kivy's StencilView is itself a stencil, and nested stencils do not
    intersect - so an inner stencil around the rosettes clipped nothing at all
    once the page was wrapped in one.
    """
    import inspect

    source = inspect.getsource(guilloche.Guilloche._draw_rosettes)
    assert "clip_polyline" in source
    # No stencil *instructions* - the words may still appear in comments
    # explaining why they are avoided.
    module = inspect.getsource(guilloche)
    for instruction in ("StencilPush(", "StencilUse(", "StencilUnUse(", "StencilPop("):
        assert instruction not in module


def test_the_frame_rule_uses_the_same_rect_as_the_clip() -> None:
    import inspect

    source = inspect.getsource(guilloche.Guilloche._redraw)
    assert "_frame_rect" in source
    assert "_draw_rosettes(w, h, frame)" in source
    assert "_draw_border(w, h, frame)" in source


# ------------------------------------------------------- the clipper itself
RECT = (0.0, 0.0, 100.0, 100.0)


def test_a_segment_wholly_inside_is_untouched() -> None:
    assert guilloche._clip_segment(10, 10, 90, 90, RECT) == (10, 10, 90, 90)


def test_a_segment_wholly_outside_is_dropped() -> None:
    assert guilloche._clip_segment(200, 200, 300, 300, RECT) is None
    assert guilloche._clip_segment(-50, -50, -10, -10, RECT) is None


def test_a_crossing_segment_ends_exactly_on_the_boundary() -> None:
    assert guilloche._clip_segment(-50, 50, 150, 50, RECT) == (0.0, 50.0, 100.0, 50.0)
    assert guilloche._clip_segment(50, -50, 50, 150, RECT) == (50.0, 0.0, 50.0, 100.0)


def test_a_segment_parallel_to_an_edge_and_outside_is_dropped() -> None:
    assert guilloche._clip_segment(-10, 50, -5, 50, RECT) is None
    assert guilloche._clip_segment(50, 200, 90, 200, RECT) is None


def test_a_polyline_is_split_into_runs_that_stay_inside() -> None:
    # Out, in, out again: one run, ending on both boundaries.
    runs = guilloche.clip_polyline([-50, 50, 50, 50, 150, 50], RECT)
    assert runs == [[0.0, 50.0, 50.0, 50.0, 100.0, 50.0]]


def test_a_polyline_that_leaves_and_returns_yields_separate_runs() -> None:
    points = [10, 10, 20, 20, 500, 500, 900, 900, 30, 30, 40, 40]
    runs = guilloche.clip_polyline(points, RECT)
    assert len(runs) == 2
    for run in runs:
        for x, y in zip(run[0::2], run[1::2]):
            assert -0.001 <= x <= 100.001
            assert -0.001 <= y <= 100.001


def test_every_clipped_point_lies_within_the_rect() -> None:
    import math

    points: list[float] = []
    for i in range(400):
        t = i * math.tau / 60
        points += [50 + 400 * math.cos(t), 50 + 400 * math.sin(t)]
    for run in guilloche.clip_polyline(points, RECT):
        for x, y in zip(run[0::2], run[1::2]):
            assert -0.001 <= x <= 100.001, x
            assert -0.001 <= y <= 100.001, y


def test_a_curve_entirely_outside_produces_nothing() -> None:
    points = [500, 500, 600, 600, 700, 700]
    assert guilloche.clip_polyline(points, RECT) == []


def test_runs_are_long_enough_to_draw() -> None:
    """Kivy needs at least two points; a one-point run would raise."""
    for run in guilloche.clip_polyline([-10, 50, 5, 50, -10, 50], RECT):
        assert len(run) >= 4
        assert len(run) % 2 == 0


def test_an_empty_ghost_portrait_draws_nothing() -> None:
    """A ghost is a faint repeat of the portrait; with no image to repeat, a
    placeholder silhouette just reads as a smudge on the page."""
    import inspect

    from epassport.ui.widgets import portrait

    source = inspect.getsource(portrait.Portrait._redraw)
    guard = source.index("if self.ghost:")
    placeholder = source.index("_draw_placeholder")
    assert guard < placeholder, "the ghost must bail out before the placeholder"
