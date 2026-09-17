"""Monospace, autoscrolling log pane fed line by line from the pm3 worker."""

from __future__ import annotations

from collections import deque

from kivy.clock import Clock
from kivy.properties import BooleanProperty, ListProperty, NumericProperty
from kivy.uix.boxlayout import BoxLayout

from .textblocks import split_blocks

#: Log lines wrap, so a block covers more rows than it holds lines.
#: Half of the hex dump's block leaves room for that.
LOG_ROWS_PER_BLOCK = 256

#: pm3 prefixes every line; colour them the way the client does.
_PREFIX_COLOURS = {
    "[+]": "33cc66",
    "[=]": "9aa4b2",
    "[!]": "e0b341",
    "[!!]": "ff6b6b",
    "[-]": "ff6b6b",
    "[?]": "6bb8ff",
    "[#]": "9aa4b2",
    "[usb]": "6bb8ff",
}


class LogPane(BoxLayout):
    """Holds at most :attr:`max_lines` lines and autoscrolls to the newest."""

    max_lines = NumericProperty(4000)
    autoscroll = BooleanProperty(True)
    #: The log, one entry per Label.  See :mod:`.textblocks`.
    blocks = ListProperty([])
    text_color = ListProperty([1, 1, 1, 1])

    def __init__(self, **kwargs) -> None:
        self._lines: deque[str] = deque(maxlen=int(self.max_lines))
        self._pending: list[str] = []
        self._scheduled = False
        super().__init__(**kwargs)

    # -- worker-thread safe -----------------------------------------------
    def append(self, line: str) -> None:
        """Queue a line.  Safe to call from any thread."""
        self._pending.append(line)
        if not self._scheduled:
            self._scheduled = True
            Clock.schedule_once(self._flush, 0)

    def _flush(self, *_args) -> None:
        self._scheduled = False
        if not self._pending:
            return
        pending, self._pending = self._pending, []
        for line in pending:
            self._lines.append(_markup(line))
        self.blocks = split_blocks(list(self._lines), size=LOG_ROWS_PER_BLOCK)
        if self.autoscroll and "scroller" in self.ids:
            Clock.schedule_once(lambda *_: setattr(self.ids.scroller, "scroll_y", 0), 0)

    def clear(self) -> None:
        self._lines.clear()
        self._pending.clear()
        self.blocks = []

    def on_blocks(self, *_args) -> None:
        self._render()

    def on_text_color(self, *_args) -> None:
        self._render()

    def _render(self) -> None:
        """One Label per block, reusing them so only what changed re-renders."""
        box = self.ids.get("log_box")
        if box is None:
            return
        from kivy.metrics import sp
        from kivy.uix.label import Label

        from .. import theme

        labels = list(reversed(box.children))  # children run newest-first
        while len(labels) > len(self.blocks):
            box.remove_widget(labels.pop())
        while len(labels) < len(self.blocks):
            label = Label(
                markup=True,
                font_name=theme.FONT_MONO,
                font_size=sp(11),
                color=self.text_color,
                halign="left",
                valign="top",
                size_hint_y=None,
                size_hint_x=1,
            )
            label.bind(
                width=lambda inst, value: setattr(inst, "text_size", (value, None)),
                texture_size=lambda inst, value: setattr(inst, "height", value[1]),
            )
            box.add_widget(label)
            labels.append(label)
        for label, block in zip(labels, self.blocks):
            if label.text != block:
                label.text = block

    @property
    def raw_text(self) -> str:
        """The log without markup, for copy/export."""
        return "\n".join(_strip_markup(line) for line in self._lines)


def _markup(line: str) -> str:
    escaped = line.replace("&", "&amp;").replace("[", "&bl;").replace("]", "&br;")
    for prefix, colour in _PREFIX_COLOURS.items():
        token = prefix.replace("[", "&bl;").replace("]", "&br;")
        if escaped.startswith(token):
            return f"[color=#{colour}]{token}[/color]{escaped[len(token):]}"
    return escaped


def _strip_markup(line: str) -> str:
    import re

    out = re.sub(r"\[/?color[^\]]*\]", "", line)
    return out.replace("&bl;", "[").replace("&br;", "]").replace("&amp;", "&")
