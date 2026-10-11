"""Colours, fonts and metrics.

The passport page is always paper-light; only the surrounding chrome follows
the dark-mode setting, exactly as a real book stays paper under any desk lamp.
"""

from __future__ import annotations

from ..config import font

# -- the page --------------------------------------------------------------
PAPER = (0.960, 0.945, 0.905, 1)  # warm off-white
PAPER_EDGE = (0.870, 0.845, 0.790, 1)
GRAIN = (0.55, 0.50, 0.42, 0.030)
GUILLOCHE = (0.42, 0.50, 0.62, 0.15)
GUILLOCHE_WARM = (0.62, 0.48, 0.40, 0.11)

LABEL = (0.38, 0.45, 0.55, 1)  # muted blue-grey, small caps
VALUE = (0.09, 0.10, 0.14, 1)  # near-black
VALUE_DIM = (0.35, 0.36, 0.42, 1)
#: The MRZ band is barely lighter than the paper, and slightly translucent so
#: the security print still shows through.  A solid white panel reads as a UI
#: element pasted onto the page rather than as part of the document.
MRZ_BAND = (0.966, 0.952, 0.913, 0.88)
MRZ_RULE = (0.74, 0.71, 0.65, 1)
MRZ_TEXT = (0.07, 0.08, 0.11, 1)
RULE = (0.72, 0.70, 0.64, 1)
PORTRAIT_FRAME = (0.55, 0.53, 0.48, 1)

OK = (0.13, 0.52, 0.28, 1)
BAD = (0.72, 0.17, 0.14, 1)
WARN = (0.78, 0.52, 0.10, 1)

# -- the chrome ------------------------------------------------------------
LIGHT = {
    "bg": (0.878, 0.878, 0.886, 1),
    "panel": (0.945, 0.945, 0.953, 1),
    "text": (0.11, 0.12, 0.15, 1),
    "text_dim": (0.42, 0.44, 0.48, 1),
    "accent": (0.13, 0.29, 0.52, 1),
    "tab": (0.815, 0.800, 0.770, 1),
    "tab_active": (0.960, 0.945, 0.905, 1),
    "border": (0.72, 0.72, 0.74, 1),
    "log_bg": (0.14, 0.15, 0.18, 1),
    "log_text": (0.80, 0.83, 0.86, 1),
    "field_bg": (1, 1, 1, 1),
}

DARK = {
    "bg": (0.106, 0.114, 0.133, 1),
    "panel": (0.149, 0.161, 0.188, 1),
    "text": (0.88, 0.89, 0.91, 1),
    "text_dim": (0.58, 0.60, 0.65, 1),
    "accent": (0.42, 0.62, 0.92, 1),
    "tab": (0.196, 0.212, 0.247, 1),
    "tab_active": (0.960, 0.945, 0.905, 1),
    "border": (0.27, 0.29, 0.34, 1),
    "log_bg": (0.078, 0.086, 0.102, 1),
    "log_text": (0.78, 0.81, 0.85, 1),
    "field_bg": (0.196, 0.212, 0.247, 1),
}

# -- fonts -----------------------------------------------------------------
FONT_MRZ = font("DejaVuSansMono.ttf")
FONT_MRZ_BOLD = font("DejaVuSansMono-Bold.ttf")
FONT_VALUE = font("DejaVuSerif-Bold.ttf")
FONT_VALUE_LIGHT = font("DejaVuSerif.ttf")
FONT_LABEL = font("DejaVuSans.ttf")
FONT_LABEL_BOLD = font("DejaVuSans-Bold.ttf")
FONT_MONO = FONT_MRZ

#: Real document geometry, in millimetres, per MRZ format.  A TD1 identity
#: card is not a small passport: it is a different shape, and its three-line
#: MRZ takes a quarter of its height rather than an eighth.
#:
#:   kind: (width, height, mrz band height)
PAGE_GEOMETRY: dict[str, tuple[float, float, float]] = {
    "TD3": (125.0, 88.0, 11.5),  # passport data page
    "TD2": (125.0, 88.0, 11.5),  # same booklet, two shorter lines
    "TD1": (85.6, 54.0, 15.0),  # ID-1 card, three lines
}

#: Everything is drawn to one millimetre scale, chosen so this reference
#: document exactly fills the available area.  A smaller document is therefore
#: drawn smaller - which is the point: an ID-1 card really is two thirds the
#: width of a passport data page, and only at true relative size do the two
#: come out with the same MRZ print size, as they do in the hand.
REFERENCE_PAGE_MM = (PAGE_GEOMETRY["TD3"][0], PAGE_GEOMETRY["TD3"][1])

#: Used when no document is loaded.
PAGE_ASPECT = PAGE_GEOMETRY["TD3"][0] / PAGE_GEOMETRY["TD3"][1]


def page_size_mm(kind: str | None) -> tuple[float, float]:
    """Physical size of the document, in millimetres."""
    width, height, _band = PAGE_GEOMETRY.get(kind or "", PAGE_GEOMETRY["TD3"])
    return (width, height)


def content_fraction(kind: str | None) -> float:
    """Share of the page height left for the portrait and the fields."""
    return (
        1.0
        - PAGE_TOP_PAD
        - PAGE_HEADER
        - PAGE_GAP
        - PAGE_BOTTOM_PAD
        - band_fraction(kind)
    )


def page_aspect(kind: str | None) -> float:
    """Width/height of the document, so a card is not drawn as a passport."""
    width, height, _band = PAGE_GEOMETRY.get(kind or "", PAGE_GEOMETRY["TD3"])
    return width / height


#: Space the window chrome takes from the page area, in pixels: horizontal
#: padding either side, and toolbar + tab strip + status bar vertically.
#: Measured from a running window; the test suite checks it still holds.
WINDOW_CHROME_PX = (12, 85)


def window_for_reference(width: int = 1100) -> tuple[int, int]:
    """A window size whose content area matches the reference document.

    Open at any other shape and a passport is letterboxed on first run, which
    reads as the app failing to use the window rather than as the document
    and the window being different shapes.
    """
    pad_w, chrome_h = WINDOW_CHROME_PX
    return (width, round((width - pad_w) / PAGE_ASPECT + chrome_h))


#: Page furniture, as fractions of the page height.  Named here so the ``.kv``
#: rule and the layout maths cannot drift apart.
PAGE_TOP_PAD = 0.050
PAGE_HEADER = 0.080
PAGE_GAP = 0.006
PAGE_BOTTOM_PAD = 0.030

#: A passport photo is 35 x 45 mm, about 28% of the document width on both a
#: data page and a card - so the portrait is sized from the width, not from a
#: page height that now differs per format.  Held a little under 28% so the
#: field labels beside it are not squeezed into truncation.
PHOTO_WIDTH_FRACTION = 0.25
PHOTO_ASPECT = 35.0 / 45.0
#: ...but never more than this share of the space above the MRZ band.
PHOTO_MAX_CONTENT_SHARE = 0.66


def band_fraction(kind: str | None) -> float:
    """The MRZ band's share of the page height, for this format."""
    _width, height, band = PAGE_GEOMETRY.get(kind or "", PAGE_GEOMETRY["TD3"])
    return band / height


TAB_TITLES = ("DATA PAGE", "PERSONAL", "ISSUER", "SECURITY", "FILES", "LOG")

#: Kivy draws a popup's title bar from its own dark atlas image whatever our
#: palette says, so the title needs a colour that works against dark - in both
#: chrome themes.
POPUP_TITLE = (0.93, 0.94, 0.96, 1)


def palette(dark: bool) -> dict[str, tuple[float, float, float, float]]:
    return DARK if dark else LIGHT


def small_caps(text: str) -> str:
    """Data-page labels are set in caps; the font does the rest."""
    return text.upper()
