"""Classic hex dump: offset, 16 bytes of hex, ASCII gutter."""

from __future__ import annotations

from kivy.clock import Clock
from kivy.properties import (
    ListProperty,
    NumericProperty,
    ObjectProperty,
    StringProperty,
)
from kivy.uix.boxlayout import BoxLayout

from .textblocks import ROWS_PER_BLOCK, split_blocks  # noqa: F401

#: Beyond this the pane renders a prefix and says so - a 25 kB DG2 as one
#: Label would stall the UI thread for seconds.
MAX_BYTES = 64 * 1024


def hexdump(data: bytes, *, width: int = 16, limit: int = MAX_BYTES) -> str:
    """Render ``data`` as an offset/hex/ASCII dump."""
    if not data:
        return "(empty)"
    body = data[:limit]
    rows: list[str] = []
    for offset in range(0, len(body), width):
        chunk = body[offset : offset + width]
        hex_part = " ".join(f"{b:02X}" for b in chunk)
        gap = "   " * (width - len(chunk))
        ascii_part = "".join(chr(b) if 0x20 <= b < 0x7F else "." for b in chunk)
        rows.append(f"{offset:08X}  {hex_part}{gap}  |{ascii_part}|")
    if len(data) > limit:
        rows.append(f"... {len(data) - limit} more bytes not shown")
    return "\n".join(rows)


def hexdump_blocks(
    data: bytes, *, width: int = 16, limit: int = MAX_BYTES
) -> list[str]:
    """:func:`hexdump`, split into chunks that each fit one texture."""
    return split_blocks(hexdump(data, width=width, limit=limit).splitlines())


#: Row widths to try, widest first.  A hex dump must not wrap, so instead of
#: letting it overflow we fit fewer bytes per row into a narrow pane.
ROW_WIDTHS = (16, 8, 4)


class HexView(BoxLayout):
    """Shows :attr:`data` as a hex dump that fits the pane it is given."""

    data = ObjectProperty(b"")
    title = StringProperty("")
    byte_count = NumericProperty(0)
    #: The dump, one entry per Label.  See :data:`ROWS_PER_BLOCK`.
    blocks = ListProperty([])
    text_color = ListProperty([1, 1, 1, 1])
    #: Width available for the dump, in pixels.  Set from the ``.kv`` rule.
    available_width = NumericProperty(0)
    row_bytes = NumericProperty(16)

    def on_data(self, _instance, value: bytes) -> None:
        self.byte_count = len(value or b"")
        self._rebuild()

    def on_available_width(self, *_args) -> None:
        self._rebuild()

    def _rebuild(self) -> None:
        width = self.fit_row_bytes(self.available_width)
        if width != self.row_bytes:
            self.row_bytes = width
        self.blocks = hexdump_blocks(self.data or b"", width=width)

    def on_blocks(self, *_args) -> None:
        Clock.schedule_once(self._render, -1)

    def on_text_color(self, *_args) -> None:
        Clock.schedule_once(self._render, -1)

    def _render(self, *_args) -> None:
        box = self.ids.get("dump_box")
        if box is None:
            return
        from kivy.metrics import sp
        from kivy.uix.label import Label

        from .. import theme

        box.clear_widgets()
        for block in self.blocks:
            label = Label(
                text=block,
                font_name=theme.FONT_MONO,
                font_size=sp(11),
                color=self.text_color,
                halign="left",
                valign="top",
                size_hint=(None, None),
            )
            label.bind(texture_size=label.setter("size"))
            box.add_widget(label)

    def fit_row_bytes(self, available: float) -> int:
        """Largest row width whose rendered line fits in ``available`` pixels."""
        if available <= 0:
            return ROW_WIDTHS[0]
        for count in ROW_WIDTHS:
            if measure_row_width(count) <= available:
                return count
        return ROW_WIDTHS[-1]


def sample_row(count: int) -> str:
    """A worst-case row of ``count`` bytes, for measuring."""
    return (
        f"{0:08X}  " + " ".join("FF" for _ in range(count)) + "  |" + "W" * count + "|"
    )


_row_width_cache: dict[int, float] = {}


def measure_row_width(count: int) -> float:
    """Rendered width of a ``count``-byte row, in pixels.  Cached."""
    if count in _row_width_cache:
        return _row_width_cache[count]
    from kivy.core.text import Label as CoreLabel
    from kivy.metrics import sp

    from .. import theme

    label = CoreLabel(
        text=sample_row(count), font_size=sp(11), font_name=theme.FONT_MONO
    )
    label.refresh()
    width = float(label.texture.size[0]) + sp(20)  # padding and the scrollbar
    _row_width_cache[count] = width
    return width
