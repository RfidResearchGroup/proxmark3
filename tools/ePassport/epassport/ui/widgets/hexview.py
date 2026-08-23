"""Classic hex dump: offset, 16 bytes of hex, ASCII gutter."""

from __future__ import annotations

from kivy.properties import NumericProperty, ObjectProperty, StringProperty
from kivy.uix.boxlayout import BoxLayout

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


#: Row widths to try, widest first.  A hex dump must not wrap, so instead of
#: letting it overflow we fit fewer bytes per row into a narrow pane.
ROW_WIDTHS = (16, 8, 4)


class HexView(BoxLayout):
    """Shows :attr:`data` as a hex dump that fits the pane it is given."""

    data = ObjectProperty(b"")
    title = StringProperty("")
    byte_count = NumericProperty(0)
    text = StringProperty("(no file selected)")
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
        self.text = hexdump(self.data or b"", width=width)

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
