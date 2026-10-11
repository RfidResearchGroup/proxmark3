"""Book tabs plus the page-turn transition between them.

The animation is deliberately cheap: an x-scale squeeze with a short fade,
which reads as a page flipping without any 3D machinery.
"""

from __future__ import annotations

from kivy.animation import Animation
from kivy.properties import (
    BooleanProperty,
    ListProperty,
    NumericProperty,
    ObjectProperty,
    StringProperty,
)
from kivy.uix.behaviors import ButtonBehavior
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.floatlayout import FloatLayout
from kivy.uix.label import Label
from kivy.uix.scatter import Scatter

from .. import theme


class BookTab(ButtonBehavior, Label):
    """One tab in the strip above the page, shaped like a book tab."""

    active = BooleanProperty(False)
    index = NumericProperty(0)
    palette = ObjectProperty(theme.LIGHT)


class TabStrip(BoxLayout):
    """The row of tabs above the page.  Fires ``on_select`` with the index."""

    titles = ListProperty(list(theme.TAB_TITLES))
    active_index = NumericProperty(0)
    palette = ObjectProperty(theme.LIGHT)

    __events__ = ("on_select",)

    def on_select(self, index: int) -> None:
        """Default handler - kv binds over this."""

    def select(self, index: int) -> None:
        if index == self.active_index:
            return
        self.active_index = index
        self.dispatch("on_select", index)


class PageTurn(FloatLayout):
    """Swaps its single child with a short page-turn squeeze."""

    duration = NumericProperty(0.16)

    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        self._current = None

    def show(self, widget, *, animate: bool = True) -> None:
        """Put ``widget`` on screen, turning the page if one is already there."""
        if widget is self._current:
            return
        old = self._current
        self._current = widget
        widget.size_hint = (1, 1)
        widget.pos_hint = {"x": 0, "y": 0}

        if old is None or not animate:
            self.clear_widgets()
            self.add_widget(widget)
            return

        def _swap(*_args) -> None:
            self.clear_widgets()
            self.add_widget(widget)
            widget.opacity = 0
            Animation(opacity=1, duration=self.duration, t="out_quad").start(widget)

        old.opacity = 1
        anim = Animation(opacity=0, duration=self.duration, t="in_quad")
        anim.bind(on_complete=_swap)
        anim.start(old)


class TabPage(BoxLayout):
    """Base class for the non-passport tabs: a titled panel."""

    title = StringProperty("")
    palette = ObjectProperty(theme.LIGHT)
    record = ObjectProperty(None, allownone=True, rebind=True)

    def refresh(self) -> None:
        """Called when a new record arrives.  Subclasses override."""
