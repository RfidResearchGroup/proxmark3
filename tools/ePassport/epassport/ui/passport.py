"""The passport data page: the widget the whole app exists to draw.

It binds only to a :class:`PassportRecord`, so "read from card" and "open a
saved dump" render through exactly the same code.
"""

from __future__ import annotations

from kivy.properties import (
    ListProperty,
    NumericProperty,
    ObjectProperty,
    OptionProperty,
)
from kivy.uix.floatlayout import FloatLayout
from kivy.uix.scatter import Scatter
from kivy.uix.widget import Widget

from ..emrtd.model import PassportRecord
from . import theme

#: The page is laid out once at this resolution and then scaled.  Nothing on
#: it is interactive, so scaling a finished plate is both faster and steadier
#: than re-flowing every label each time the window moves a pixel.
PX_PER_MM = 8.0


class PagePlate(Scatter):
    """Holds the page at a fixed size and draws it scaled.

    A Scatter applies a matrix, so its children keep their own geometry: the
    text does not re-render, the security print does not regenerate, and a
    resize costs a matrix multiply instead of a full re-layout.
    """

    def __init__(self, **kwargs) -> None:
        kwargs.setdefault("do_rotation", False)
        kwargs.setdefault("do_scale", False)
        kwargs.setdefault("do_translation", False)
        kwargs.setdefault("auto_bring_to_front", False)
        # The plate keeps a fixed size; without this the enclosing FloatLayout
        # stretches it to fill, and fights every size we set.
        kwargs.setdefault("size_hint", (None, None))
        super().__init__(**kwargs)

    def on_touch_down(self, touch):  # the page is display-only
        return False


#: How the page is scaled into the available area.
#:
#: A card's MRZ takes 2.97% of its width per character; a passport's takes
#: 2.03%.  So scaling both documents to the same screen width necessarily
#: makes the card's MRZ half again as large, and making the MRZ match
#: necessarily means drawing the card smaller.  You can have one or the other,
#: which is why this is a setting rather than a decision.
FIT_TO_WINDOW = "fit"  # fill the area; MRZ print differs between formats
TRUE_SCALE = "true"  # one mm scale; MRZ print identical, small doc stays small

SCALE_MODES = (FIT_TO_WINDOW, TRUE_SCALE)


def page_scale(
    mode: str,
    area: tuple[float, float],
    page_px: tuple[float, float],
    reference_px: tuple[float, float],
) -> float:
    """Scale factor for a page of ``page_px`` inside ``area``.

    ``FIT_TO_WINDOW`` fills the area with whatever document is loaded.
    ``TRUE_SCALE`` scales every format identically, so a card comes out as
    much smaller than a data page as it really is.
    """
    area_w, area_h = area
    if area_w <= 0 or area_h <= 0:
        return 1.0
    if mode == TRUE_SCALE:
        ref_w, ref_h = reference_px
        return min(area_w / ref_w, area_h / ref_h)
    page_w, page_h = page_px
    if page_w <= 0 or page_h <= 0:
        return 1.0
    return min(area_w / page_w, area_h / page_h)


class AspectBox(FloatLayout):
    """Scales the page plate into the available area."""

    #: One of :data:`SCALE_MODES`.
    scale_mode = OptionProperty(FIT_TO_WINDOW, options=list(SCALE_MODES))

    def on_scale_mode(self, *_args) -> None:
        self._trigger_layout()

    def do_layout(self, *args, **kwargs) -> None:
        # Only scale and position here.  Assigning sizes during a layout pass
        # re-triggers the pass, which recurses.
        ref_w, ref_h = theme.REFERENCE_PAGE_MM
        for child in self.children:
            w, h = self.width, self.height
            if w <= 0 or h <= 0 or not child.width or not child.height:
                continue
            page = self._page_of(child)
            page_w = page.width if page is not None else child.width
            page_h = page.height if page is not None else child.height

            scale = page_scale(
                self.scale_mode,
                (w, h),
                (page_w, page_h),
                (ref_w * PX_PER_MM, ref_h * PX_PER_MM),
            )

            if abs(child.scale - scale) > 1e-6:
                child.scale = scale

            # Centre the *document*, which may sit inset on a larger plate.
            offset_x = page.x * scale if page is not None else 0.0
            offset_y = page.y * scale if page is not None else 0.0
            child.pos = (
                self.x + (w - page_w * scale) / 2.0 - offset_x,
                self.y + (h - page_h * scale) / 2.0 - offset_y,
            )
        super().do_layout(*args, **kwargs)

    @staticmethod
    def _page_of(child):
        if hasattr(child, "page_size_mm"):
            return child
        for grandchild in getattr(child, "children", ()):
            if hasattr(grandchild, "page_size_mm"):
                return grandchild
        return None


class PassportPage(Widget):
    """The rendered data page.  Set :attr:`record` and it redraws itself."""

    record = ObjectProperty(None, allownone=True, rebind=True)
    #: Width/height of the document being shown, and the MRZ band's share of
    #: its height.  Both depend on the format: see ``theme.PAGE_GEOMETRY``.
    page_aspect = NumericProperty(theme.PAGE_ASPECT)
    #: Physical size in millimetres; the parent scales every format from this.
    page_size_mm = ListProperty(list(theme.REFERENCE_PAGE_MM))
    band_fraction = NumericProperty(theme.band_fraction("TD3"))
    content_fraction = NumericProperty(theme.content_fraction("TD3"))
    #: Mirrors ``record.mrz``.  A Kivy property so ``.kv`` can actually bind
    #: to it - a plain Python @property is invisible to the binding machinery.
    mrz = ObjectProperty(None, allownone=True, rebind=True)

    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        ref_w, ref_h = theme.REFERENCE_PAGE_MM
        self.size = (ref_w * PX_PER_MM, ref_h * PX_PER_MM)
        self.size_hint = (None, None)
        if self.record is None:
            self.record = PassportRecord()

    def on_record(self, _instance, value: PassportRecord | None) -> None:
        self.mrz = value.mrz if value else None
        kind = self.mrz.kind if self.mrz else None
        self.page_aspect = theme.page_aspect(kind)
        self.page_size_mm = list(theme.page_size_mm(kind))
        self.band_fraction = theme.band_fraction(kind)
        self.content_fraction = theme.content_fraction(kind)

    def on_page_size_mm(self, *_args) -> None:
        """Take the new format's size and centre it on the fixed plate.

        The plate itself never changes size - resizing a Scatter from inside a
        layout pass sends the whole thing into a loop - so a smaller document
        simply occupies less of it.
        """
        doc_w, doc_h = self.page_size_mm
        ref_w, ref_h = theme.REFERENCE_PAGE_MM
        size = (doc_w * PX_PER_MM, doc_h * PX_PER_MM)
        if tuple(self.size) != size:
            self.size = size
        self.pos = (
            (ref_w * PX_PER_MM - size[0]) / 2.0,
            (ref_h * PX_PER_MM - size[1]) / 2.0,
        )
        # The fit depends on the document's size, so a new format has to be
        # re-fitted.  Without this, opening a card after a passport kept the
        # passport's scale and the card sat small until something else forced
        # a layout.
        self.refit()

    def refit(self) -> None:
        """Ask the enclosing :class:`AspectBox` to scale the page again."""
        parent = self.parent
        while parent is not None:
            # Only the AspectBox lays out; the plate between us is a Scatter
            # and has no layout of its own.
            if isinstance(parent, AspectBox):
                parent._trigger_layout()
                return
            parent = parent.parent

    # -- helpers used by passport.kv --------------------------------------
    def check_state(self, name: str) -> str:
        """'ok' / 'bad' / 'none' for one MRZ field, for the little badge."""
        m = self.mrz
        if m is None:
            return "none"
        field = getattr(m, name, None)
        if field is None or getattr(field, "ok", None) is None:
            return "none"
        return "ok" if field.ok else "bad"

    def value(self, name: str, default: str = "") -> str:
        m = self.mrz
        if m is None:
            return default
        got = getattr(m, name, None)
        if got is None:
            return default
        return getattr(got, "value", got) or default
