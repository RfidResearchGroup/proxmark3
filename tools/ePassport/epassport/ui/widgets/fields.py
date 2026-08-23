"""Data-page field: a small-caps label above a heavier value, plus a check badge."""

from __future__ import annotations

from kivy.properties import (
    BooleanProperty,
    NumericProperty,
    OptionProperty,
    StringProperty,
)
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.label import Label

from .. import theme


class FieldLabel(Label):
    """The muted blue-grey caption above a value."""


class FieldValue(Label):
    """The dark, heavier value itself."""


class CheckBadge(Label):
    """A small tick/cross for one MRZ check digit.  Never blocks display."""

    state = OptionProperty("none", options=("none", "ok", "bad"))

    def on_state(self, *_args) -> None:
        self.text = {"none": "", "ok": "✓", "bad": "✗"}[self.state]
        self.color = {"none": (0, 0, 0, 0), "ok": theme.OK, "bad": theme.BAD}[
            self.state
        ]


class DataField(BoxLayout):
    """One label/value pair as it appears on the data page."""

    label_text = StringProperty("")
    value_text = StringProperty("")
    check = OptionProperty("none", options=("none", "ok", "bad"))
    value_font_size = NumericProperty(17)
    label_font_size = NumericProperty(10)
    dim = BooleanProperty(False)
    source_note = StringProperty("")
