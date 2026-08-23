"""A small drawn wastebasket button.

The bundled DejaVu fonts have no U+1F5D1 WASTEBASKET, and relying on a system
emoji font would mean shipping a button that renders as tofu on some machines.
Drawing it with canvas primitives costs a few lines and always looks the same.
"""

from __future__ import annotations

from kivy.graphics import Color, Line, Rectangle
from kivy.properties import BooleanProperty, ListProperty, NumericProperty
from kivy.uix.behaviors import ButtonBehavior
from kivy.uix.widget import Widget

from .. import theme


class BinButton(ButtonBehavior, Widget):
    """A wastebasket icon that behaves like a button.

    Turns red while pressed, so an accidental brush of the mouse is visibly
    different from a committed click on something destructive.
    """

    #: Icon colour when idle.
    tint = ListProperty(list(theme.LIGHT["text_dim"]))
    #: Colour while the button is held down.
    active_tint = ListProperty(list(theme.BAD))
    disabled_tint = ListProperty([0.45, 0.45, 0.48, 0.45])
    line_width = NumericProperty(1.4)
    hovered = BooleanProperty(False)

    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        self.bind(
            pos=self._redraw,
            size=self._redraw,
            state=self._redraw,
            disabled=self._redraw,
            tint=self._redraw,
        )
        self._redraw()

    def _colour(self) -> list[float]:
        if self.disabled:
            return list(self.disabled_tint)
        if self.state == "down":
            return list(self.active_tint)
        return list(self.tint)

    def _redraw(self, *_args) -> None:
        self.canvas.clear()
        w, h = self.size
        if w < 8 or h < 8:
            return
        # Work inside a square, centred, so the icon never distorts.
        side = min(w, h) * 0.72
        x = self.x + (w - side) / 2.0
        y = self.y + (h - side) / 2.0
        colour = self._colour()

        body_w = side * 0.62
        body_h = side * 0.62
        body_x = x + (side - body_w) / 2.0
        body_y = y + side * 0.06
        lid_y = body_y + body_h + side * 0.06

        with self.canvas:
            Color(*colour)
            # Lid, with a handle above it.
            Rectangle(pos=(x + side * 0.10, lid_y), size=(side * 0.80, side * 0.09))
            Line(
                rectangle=(
                    x + side * 0.36,
                    lid_y + side * 0.11,
                    side * 0.28,
                    side * 0.10,
                ),
                width=self.line_width,
            )
            # Body: a slight taper, drawn as four lines.
            taper = side * 0.06
            Line(
                points=[
                    body_x,
                    body_y + body_h,
                    body_x + taper,
                    body_y,
                    body_x + body_w - taper,
                    body_y,
                    body_x + body_w,
                    body_y + body_h,
                ],
                width=self.line_width,
                joint="miter",
            )
            # Three ribs.
            for fraction in (0.30, 0.50, 0.70):
                rib_x = body_x + body_w * fraction
                Line(
                    points=[
                        rib_x,
                        body_y + body_h * 0.16,
                        rib_x,
                        body_y + body_h * 0.84,
                    ],
                    width=1.0,
                )
