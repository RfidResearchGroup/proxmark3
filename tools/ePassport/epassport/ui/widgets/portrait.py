"""Portrait frame, ghost portrait and the placeholder silhouette."""

from __future__ import annotations

import io

from kivy.clock import Clock
from kivy.core.image import Image as CoreImage
from kivy.graphics import Color, Ellipse, Line, Rectangle
from kivy.properties import BooleanProperty, NumericProperty, ObjectProperty
from kivy.uix.widget import Widget

from .. import theme


def texture_from_png(png: bytes):
    """Kivy texture from in-memory PNG bytes, or None."""
    if not png:
        return None
    try:
        return CoreImage(io.BytesIO(png), ext="png").texture
    except Exception:
        return None


class Portrait(Widget):
    """A letterboxed portrait in a thin frame.

    ``ghost`` renders the same image at low opacity with no frame, which is
    what the small repeat image on a real data page looks like.
    """

    png = ObjectProperty(b"", allownone=True)
    ghost = BooleanProperty(False)
    opacity_level = NumericProperty(1.0)

    def __init__(self, **kwargs) -> None:
        self._texture = None
        super().__init__(**kwargs)
        self._trigger = Clock.create_trigger(self._redraw, -1)
        self.bind(
            pos=self._trigger, size=self._trigger, png=self._on_png, ghost=self._trigger
        )
        self._on_png()

    def _on_png(self, *_args) -> None:
        self._texture = texture_from_png(self.png or b"")
        self._trigger()

    def _redraw(self, *_args) -> None:
        self.canvas.clear()
        w, h = self.size
        if w < 4 or h < 4:
            return
        alpha = 0.25 if self.ghost else self.opacity_level
        with self.canvas:
            if self._texture is None:
                # A ghost is a faint repeat of the portrait.  With no image
                # there is nothing to repeat, and a placeholder silhouette
                # just reads as a smudge on the page.
                if self.ghost:
                    return
                self._draw_placeholder(w, h, alpha)
            else:
                self._draw_image(w, h, alpha)
            if not self.ghost:
                Color(*theme.PORTRAIT_FRAME)
                Line(rectangle=(self.x, self.y, w, h), width=1.2)

    def _draw_image(self, w: float, h: float, alpha: float) -> None:
        tex = self._texture
        scale = min(w / tex.width, h / tex.height)
        tw, th = tex.width * scale, tex.height * scale
        if not self.ghost:
            Color(1, 1, 1, 1)
            Rectangle(pos=self.pos, size=self.size)
        Color(1, 1, 1, alpha)
        Rectangle(
            texture=tex,
            pos=(self.x + (w - tw) / 2, self.y + (h - th) / 2),
            size=(tw, th),
        )

    def _draw_placeholder(self, w: float, h: float, alpha: float) -> None:
        """The 'no DG2' silhouette: head and shoulders, nothing face-like."""
        Color(0.90, 0.89, 0.86, alpha)
        Rectangle(pos=self.pos, size=self.size)
        Color(0.68, 0.67, 0.64, alpha)
        head = min(w, h) * 0.34
        Ellipse(pos=(self.x + w / 2 - head / 2, self.y + h * 0.52), size=(head, head))
        body = w * 0.78
        Ellipse(
            pos=(self.x + w / 2 - body / 2, self.y + h * 0.05),
            size=(body, h * 0.52),
            angle_start=-90,
            angle_end=90,
        )
