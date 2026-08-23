"""Procedural guilloche background.

Superimposed Lissajous/spirograph line families drawn straight onto the Kivy
canvas.  Nothing here is traced from a real document's security print, and the
alpha is kept low enough that text over it stays well above 4.5:1 contrast.
"""

from __future__ import annotations

import math

from kivy.clock import Clock
from kivy.graphics import Color, Line, Rectangle
from kivy.properties import BooleanProperty, NumericProperty
from kivy.uix.widget import Widget

from .. import theme


def clip_polyline(points: list[float], rect) -> list[list[float]]:
    """Split a flat ``[x0, y0, x1, y1, ...]`` polyline against ``rect``.

    Returns the runs that lie inside, with the crossing points interpolated so
    each run ends exactly on the boundary.  Doing this in geometry rather than
    with a stencil keeps the result identical wherever the widget is nested.

    Most of a rosette sits inside the frame, so segments with both ends inside
    take a four-comparison fast path; only the ones actually crossing an edge
    pay for the full clip.
    """
    rx, ry, rw, rh = rect
    xmax, ymax = rx + rw, ry + rh
    runs: list[list[float]] = []
    current: list[float] = []
    inside_prev = None

    for index in range(0, len(points) - 2, 2):
        x0, y0, x1, y1 = points[index : index + 4]
        if inside_prev is None:
            inside_prev = rx <= x0 <= xmax and ry <= y0 <= ymax
        inside_next = rx <= x1 <= xmax and ry <= y1 <= ymax

        if inside_prev and inside_next:
            if current:
                current += [x1, y1]
            else:
                current = [x0, y0, x1, y1]
            inside_prev = inside_next
            continue

        segment = _clip_segment(x0, y0, x1, y1, rect)
        inside_prev = inside_next
        if segment is None:
            if len(current) >= 4:
                runs.append(current)
            current = []
            continue
        cx0, cy0, cx1, cy1 = segment
        if not current:
            current = [cx0, cy0, cx1, cy1]
        elif current[-2] == cx0 and current[-1] == cy0:
            current += [cx1, cy1]
        else:
            # The line re-entered the rectangle somewhere else.
            if len(current) >= 4:
                runs.append(current)
            current = [cx0, cy0, cx1, cy1]

    if len(current) >= 4:
        runs.append(current)
    return runs


def _clip_segment(x0: float, y0: float, x1: float, y1: float, rect):
    """Liang-Barsky clip of one segment to ``(x, y, w, h)``.  None if outside."""
    rx, ry, rw, rh = rect
    xmin, xmax = rx, rx + rw
    ymin, ymax = ry, ry + rh
    dx, dy = x1 - x0, y1 - y0
    t0, t1 = 0.0, 1.0
    for p, q in ((-dx, x0 - xmin), (dx, xmax - x0), (-dy, y0 - ymin), (dy, ymax - y0)):
        if p == 0:
            if q < 0:
                return None  # parallel to this edge and outside it
            continue
        t = q / p
        if p < 0:
            if t > t1:
                return None
            t0 = max(t0, t)
        else:
            if t < t0:
                return None
            t1 = min(t1, t)
    if t0 > t1:
        return None
    return (x0 + t0 * dx, y0 + t0 * dy, x0 + t1 * dx, y0 + t1 * dy)


class Guilloche(Widget):
    """Paper, rosette line families and a subtle grain, in that order."""

    #: How many line families to superimpose.  Two reads as security print;
    #: more turns into mush at small sizes.
    families = NumericProperty(3)
    detail = NumericProperty(560)
    show_grain = BooleanProperty(True)
    #: Height of the MRZ band at the foot of the page.  The inner rule stops
    #: there, because on a real document the band's own hairline closes the
    #: frame - a rule running behind the band leaves a stub poking out.
    bottom_inset = NumericProperty(0)

    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        # Coalesce redraws: a resize changes pos and size separately, and
        # rebuilding the security print three times per frame is what made
        # dragging a window edge crawl.
        self._trigger = Clock.create_trigger(self._redraw, -1)
        self.bind(
            pos=self._trigger,
            size=self._trigger,
            families=self._trigger,
            bottom_inset=self._trigger,
        )
        self._trigger()

    def _redraw(self, *_args) -> None:
        self.canvas.before.clear()
        w, h = self.size
        if w < 8 or h < 8:
            return
        frame = self._frame_rect(w, h)
        with self.canvas.before:
            Color(*theme.PAPER)
            Rectangle(pos=self.pos, size=self.size)
            # Security print belongs inside the printed frame.  The curves are
            # clipped geometrically rather than with a stencil: this widget can
            # sit inside another StencilView, and Kivy's nested stencils do not
            # intersect, so an inner stencil silently stops clipping.
            self._draw_rosettes(w, h, frame)
            self._draw_border(w, h, frame)
            if self.show_grain:
                self._draw_grain(w, h)

    # -- line families ----------------------------------------------------
    def _draw_rosettes(self, w: float, h: float, frame) -> None:
        """Rosettes: one large pale family, one tighter warm one, one corner."""
        m = min(w, h)
        specs = (
            # (cx, cy, R, r, d, colour, width, turns)
            (
                0.68 * w,
                0.52 * h,
                m * 0.40,
                m * 0.0625,
                m * 0.20,
                theme.GUILLOCHE,
                1.0,
                8,
            ),
            (
                0.26 * w,
                0.40 * h,
                m * 0.27,
                m * 0.0450,
                m * 0.13,
                theme.GUILLOCHE_WARM,
                0.9,
                6,
            ),
            (
                0.88 * w,
                0.86 * h,
                m * 0.15,
                m * 0.0250,
                m * 0.08,
                theme.GUILLOCHE,
                0.8,
                6,
            ),
        )
        for cx, cy, big, small, offset, colour, width, turns in specs[
            : int(self.families)
        ]:
            Color(*colour)
            curve = self._hypotrochoid(cx, cy, big, small, offset, turns)
            # Clip in geometry, not with a stencil: this widget may sit inside
            # another StencilView and Kivy's nested stencils do not intersect.
            for run in clip_polyline(curve, frame):
                Line(points=run, width=width)

    def _hypotrochoid(
        self, cx: float, cy: float, big: float, small: float, offset: float, turns: int
    ) -> list[float]:
        """Classic spirograph curve, sampled densely enough to look drawn."""
        points: list[float] = []
        steps = int(self.detail)
        span = turns * 2 * math.pi
        ratio = (big - small) / small if small else 1.0
        for i in range(steps + 1):
            t = span * i / steps
            x = cx + (big - small) * math.cos(t) + offset * math.cos(ratio * t)
            y = cy + (big - small) * math.sin(t) - offset * math.sin(ratio * t)
            points += [self.x + x, self.y + y]
        return points

    # -- paper --------------------------------------------------------------
    def _frame_rect(self, w: float, h: float) -> tuple[float, float, float, float]:
        """The printed frame as ``(x, y, width, height)``.

        The rosettes are clipped to this and the inner rule is drawn on it, so
        the security print and the frame can never disagree.
        """
        inset = min(w, h) * 0.022
        floor = self.y + max(inset, self.bottom_inset)
        top = self.y + h - inset
        return (self.x + inset, floor, w - 2 * inset, max(0.0, top - floor))

    def _draw_border(self, w: float, h: float, frame) -> None:
        Color(*theme.PAPER_EDGE)
        Line(rectangle=(self.x + 1, self.y + 1, w - 2, h - 2), width=1.2)
        Color(*theme.RULE)
        fx, fy, fw, fh = frame
        # Three sides only: the MRZ band's own hairline closes the fourth, and
        # a rule running on behind the band leaves a stub poking out.
        Line(points=[fx, fy, fx, fy + fh, fx + fw, fy + fh, fx + fw, fy], width=0.9)

    def _draw_grain(self, w: float, h: float) -> None:
        """Faint horizontal fibres - deterministic, so redraws do not shimmer."""
        Color(*theme.GRAIN)
        step = max(3.0, h / 90.0)
        y = 0.0
        n = 0
        while y < h:
            phase = (n * 37) % 100 / 100.0
            x0 = self.x + w * 0.02 + phase * w * 0.10
            x1 = self.x + w * 0.98 - ((n * 53) % 100) / 100.0 * w * 0.10
            Line(points=[x0, self.y + y, x1, self.y + y], width=0.6)
            y += step
            n += 1
