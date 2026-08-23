"""Monospace, autoscrolling log pane fed line by line from the pm3 worker."""

from __future__ import annotations

from collections import deque

from kivy.clock import Clock
from kivy.properties import BooleanProperty, NumericProperty, StringProperty
from kivy.uix.boxlayout import BoxLayout

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
    text = StringProperty("")

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
        self.text = "\n".join(self._lines)
        if self.autoscroll and "scroller" in self.ids:
            Clock.schedule_once(lambda *_: setattr(self.ids.scroller, "scroll_y", 0), 0)

    def clear(self) -> None:
        self._lines.clear()
        self._pending.clear()
        self.text = ""

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
