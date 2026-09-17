"""The MRZ strip along the bottom of the data page.

Rendered verbatim from EF_DG1 - this is the one place the raw ``<`` fillers
stay, because that is what is actually printed on the document.
"""

from __future__ import annotations

from dataclasses import dataclass

from kivy.graphics import Color, Line, Rectangle
from kivy.properties import ListProperty, NumericProperty
from kivy.uix.widget import Widget
from kivy.clock import Clock
from kivy.core.text import Label as CoreLabel

from .. import theme

#: Ratio of glyph advance to font size for the bundled monospace face, and
#: the baseline-to-baseline spacing as a multiple of the font size.
CHAR_ADVANCE = 1.0 / 1.55
#: Baseline-to-baseline as a multiple of the font size.  Printed MRZ lines sit
#: close together; leaving a full line of air between them makes three lines
#: shrink until they no longer span the document.
LINE_SPACING = 1.15

#: Air above and below the block, as a fraction of one line.
BLOCK_PADDING = 0.25


@dataclass
class RowLayout:
    """How one MRZ block is placed inside its band."""

    font_size: float
    char_width: float
    line_height: float
    block_height: float
    indent: float = 0.0


def fit_rows(
    rows: list[str], width: float, height: float, *, margin: float, scale: float = 1.0
) -> RowLayout:
    """Size an MRZ block so it fits the band in *both* directions.

    Fitting only the width blows a three-line TD1 clean out of the band and
    over the fields above it: 30 characters stretched across the page make a
    font tall enough that three lines of it no longer fit.  So take the
    smaller of the width-derived and height-derived sizes.
    """
    row_count = max(1, len(rows))
    widest = max((len(row) for row in rows), default=1) or 1
    usable_width = max(1.0, width * (1.0 - 2 * margin))
    # Leave half a line of breathing room above and below the block.
    usable_height = max(1.0, height / (row_count + BLOCK_PADDING))

    from_width = usable_width / widest / CHAR_ADVANCE
    from_height = usable_height / LINE_SPACING
    font_size = max(5.0, min(from_width, from_height) * scale)

    char_width = font_size * CHAR_ADVANCE
    line_height = font_size * LINE_SPACING
    # Centre a block that no longer fills the width - a height-limited TD1
    # would otherwise sit hard against the left margin.
    indent = max(0.0, (usable_width - char_width * widest) / 2.0)
    return RowLayout(
        font_size=font_size,
        char_width=char_width,
        line_height=line_height,
        block_height=line_height * row_count,
        indent=indent,
    )


#: Rendered glyphs, keyed by (character, font size).  An MRZ is ~90
#: characters drawn from an alphabet of 37, so without this a redraw builds
#: ninety textures to show at most thirty-seven distinct ones.
_GLYPHS: dict[tuple[str, int], object] = {}
_GLYPH_CACHE_LIMIT = 600


def glyph_texture(char: str, font_size: float):
    """A cached texture for one MRZ character at one size."""
    key = (char, int(round(font_size)))
    texture = _GLYPHS.get(key)
    if texture is None:
        label = CoreLabel(
            text=char, font_size=key[1], font_name=theme.FONT_MRZ, color=theme.MRZ_TEXT
        )
        label.refresh()
        texture = label.texture
        if len(_GLYPHS) >= _GLYPH_CACHE_LIMIT:
            # A resize sweeps through many sizes; do not grow without bound.
            _GLYPHS.clear()
        _GLYPHS[key] = texture
    return texture


class MrzStrip(Widget):
    """Monospace, letter-spaced, on a band that runs the full page width.

    On a real document the machine-readable zone is a full-bleed band at the
    foot of the page, very slightly lighter than the surrounding paper, with a
    hairline rule above it.  It is not a boxed-in panel, so this widget draws
    edge to edge and takes no horizontal inset from the page layout.
    """

    lines = ListProperty([])
    font_scale = NumericProperty(1.0)
    #: Left margin as a fraction of the width, matching ICAO's print area.
    margin = NumericProperty(0.055)

    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        self._trigger = Clock.create_trigger(self._redraw, -1)
        self.bind(
            pos=self._trigger,
            size=self._trigger,
            lines=self._trigger,
            font_scale=self._trigger,
            margin=self._trigger,
        )

    def _redraw(self, *_args) -> None:
        self.canvas.clear()
        w, h = self.size
        if w < 20 or h < 10:
            return
        rows = [line for line in self.lines if line]
        with self.canvas:
            Color(*theme.MRZ_BAND)
            Rectangle(pos=self.pos, size=self.size)
            # A hairline rule, not a border: the band has no sides or bottom.
            Color(*theme.MRZ_RULE)
            Line(points=[self.x, self.top, self.right, self.top], width=1.0)
            if rows:
                self._draw_rows(rows, w, h)

    def _draw_rows(self, rows: list[str], w: float, h: float) -> None:
        """Lay the characters out on a fixed pitch, left-aligned in the band."""
        layout = fit_rows(rows, w, h, margin=self.margin, scale=self.font_scale)
        left = self.x + w * self.margin + layout.indent
        top = self.y + (h + layout.block_height) / 2.0 + h * 0.06

        for index, row in enumerate(rows):
            baseline = top - layout.line_height * (index + 1)
            for offset, ch in enumerate(row):
                if ch == " ":
                    continue
                tex = glyph_texture(ch, layout.font_size)
                Color(*theme.MRZ_TEXT)
                Rectangle(
                    texture=tex,
                    pos=(
                        left
                        + offset * layout.char_width
                        + (layout.char_width - tex.width) / 2.0,
                        baseline,
                    ),
                    size=tex.size,
                )
