"""MRZ OCR: preprocess a cropped strip, run tesseract, accept only clean reads.

A candidate is accepted only when its check digits validate *and* two
consecutive frames agree.  That is what stops a single hallucinated digit from
being fed to BAC.
"""

from __future__ import annotations

import logging
import re
import threading
from functools import lru_cache
from dataclasses import dataclass, field

from ..emrtd import mrz as mrzlib

log = logging.getLogger(__name__)

#: The only characters tesseract is allowed to emit.
WHITELIST = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ<"
TESSERACT_CONFIG = f"--psm 6 -c tessedit_char_whitelist={WHITELIST}"

#: Valid MRZ line widths, longest first so TD3 wins ties.
LINE_WIDTHS = (44, 36, 30)


def use_private_tempdir() -> None:
    """Point tesseract's scratch files at the app's own 0700 directory.

    The subprocess backend hands images to the tesseract binary through a temp
    file.  By default that lands in /tmp, which would put a picture of
    somebody's MRZ outside the app data dir - so redirect it before any OCR
    happens.  The in-process backend writes nothing at all.
    """
    import tempfile

    from ..config import data_dir

    scratch = data_dir() / "ocr-tmp"
    scratch.mkdir(parents=True, exist_ok=True)
    try:
        scratch.chmod(0o700)
    except OSError:
        pass
    tempfile.tempdir = str(scratch)


def clear_private_tempdir() -> None:
    """Delete any OCR scratch files left behind."""
    from ..config import data_dir

    scratch = data_dir() / "ocr-tmp"
    if not scratch.is_dir():
        return
    for leftover in scratch.iterdir():
        try:
            leftover.unlink()
        except OSError:
            pass


# ------------------------------------------------------------------ engine
# An in-process binding (tesserocr) would avoid re-launching tesseract for
# every frame and is roughly three times faster per call.  It was tried and
# rejected: the PyPI wheel bundles its own leptonica, and pairing that with a
# system tessdata directory hung indefinitely mid-recognition.  A backend that
# can wedge the OCR thread is worse than a slower one, so this stays on the
# subprocess path.  The cost is mitigated instead by not calling it as often -
# see :func:`looks_like_text` and the frame-change check in the scan loop.


def tesseract_available() -> tuple[bool, str]:
    """``(available, reason)`` - the reason is shown in the disabled tooltip."""
    try:
        import pytesseract
    except ImportError:
        return False, "pytesseract is not installed - run: pip install pytesseract"
    try:
        pytesseract.get_tesseract_version()
    except Exception:
        return (
            False,
            "the tesseract binary is not installed - run: sudo apt install tesseract-ocr",
        )
    return True, ""


@lru_cache(maxsize=1)
def best_language() -> str:
    """Prefer OCR-B / mrz traineddata when installed, else plain eng.

    Cached: the lookup shells out to tesseract, and paying that on every frame
    cost more than several of the image-processing steps combined.
    """
    try:
        import pytesseract

        langs = set(pytesseract.get_languages(config=""))
    except Exception:
        return "eng"
    for candidate in ("mrz", "ocrb", "OCRB"):
        if candidate in langs:
            return candidate
    return "eng"


# ------------------------------------------------------------- preprocessing
#: Tesseract wants a decent x-height.  An MRZ strip below this many pixels
#: tall gets upscaled before it is handed over.
MIN_STRIP_HEIGHT = 120

#: Above this the strip is downscaled.  Past roughly this height extra pixels
#: buy no accuracy on the test set and only cost time.
MAX_STRIP_HEIGHT = 190


def normalize_scale(image):
    """Scale a cropped strip into the band tesseract reads best."""
    import cv2

    h = image.shape[0]
    if h == 0:
        return image
    if h < MIN_STRIP_HEIGHT:
        factor, interp = MIN_STRIP_HEIGHT / h, cv2.INTER_CUBIC
    elif h > MAX_STRIP_HEIGHT:
        factor, interp = MAX_STRIP_HEIGHT / h, cv2.INTER_AREA
    else:
        return image
    return cv2.resize(image, None, fx=factor, fy=factor, interpolation=interp)


def to_gray(image):
    import cv2

    return cv2.cvtColor(image, cv2.COLOR_BGR2GRAY) if image.ndim == 3 else image


def deskew(image):
    """Rotate a strip upright using the orientation of all its text pixels.

    ``minAreaRect`` over every dark pixel is far more stable than over the
    single largest contour, which on a thresholded MRZ is usually the page
    border rather than any text.
    """
    import cv2

    gray = to_gray(image)
    _, mask = cv2.threshold(gray, 0, 255, cv2.THRESH_BINARY_INV + cv2.THRESH_OTSU)
    points = cv2.findNonZero(mask)
    if points is None or len(points) < 50:
        return image
    angle = cv2.minAreaRect(points)[-1]
    if angle < -45:
        angle += 90
    elif angle > 45:
        angle -= 90
    if abs(angle) < 0.4 or abs(angle) > 15:
        return image
    h, w = image.shape[:2]
    matrix = cv2.getRotationMatrix2D((w / 2, h / 2), angle, 1.0)
    return cv2.warpAffine(
        image, matrix, (w, h), flags=cv2.INTER_CUBIC, borderMode=cv2.BORDER_REPLICATE
    )


def variant_plain(image):
    """Grayscale only.

    Usually the best input: thresholding an already-clean print tends to eat
    the long runs of '<' fillers, which is what makes a line the wrong length.
    """
    import cv2

    return cv2.bilateralFilter(to_gray(image), 5, 40, 40)


def variant_clahe_otsu(image):
    """Contrast-equalise, then a global Otsu threshold.  Good for dim frames."""
    import cv2

    gray = to_gray(image)
    equalized = cv2.createCLAHE(clipLimit=2.0, tileGridSize=(8, 8)).apply(gray)
    blurred = cv2.GaussianBlur(equalized, (3, 3), 0)
    _, binary = cv2.threshold(blurred, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
    return binary


def variant_adaptive(image):
    """Adaptive threshold, with a block wide enough not to eat filler runs."""
    import cv2

    gray = to_gray(image)
    equalized = cv2.createCLAHE(clipLimit=2.0, tileGridSize=(8, 8)).apply(gray)
    return cv2.adaptiveThreshold(
        equalized, 255, cv2.ADAPTIVE_THRESH_MEAN_C, cv2.THRESH_BINARY, 61, 15
    )


#: Tried in order; the first variant yielding a check-digit-valid MRZ wins, so
#: the common case costs exactly one tesseract call.
VARIANTS = (
    ("plain", variant_plain),
    ("clahe-otsu", variant_clahe_otsu),
    ("adaptive", variant_adaptive),
)

#: The variant that last produced a valid read is tried first next time.
#: Lighting does not change between frames, so the winner rarely does either -
#: and on a dim page this turns three tesseract calls back into one.
_last_winner: str = ""


def ordered_variants() -> tuple[tuple[str, object], ...]:
    if not _last_winner:
        return VARIANTS
    return tuple(sorted(VARIANTS, key=lambda item: item[0] != _last_winner))


def preprocess(image, *, deskew_first: bool = True):
    """Single-variant preprocessing: deskew, rescale, CLAHE + Otsu."""
    prepared = deskew(image) if deskew_first else image
    return variant_clahe_otsu(normalize_scale(prepared))


#: The crop is taken slightly wider than the drawn guide, so a page held at a
#: slight angle does not lose its first or last character to the box edge.
GUIDE_MARGIN = 0.03


def crop_to_guide(
    image, guide: tuple[float, float, float, float], *, margin: float = GUIDE_MARGIN
):
    """Crop a BGR frame to the guide rectangle, as fractions (x, y, w, h).

    ``y`` is measured from the TOP of the frame, matching how the guide reads
    in the UI.
    """
    h, w = image.shape[:2]
    fx, fy, fw, fh = guide
    pad_x, pad_y = fw * margin, fh * margin
    fx, fw = fx - pad_x, fw + 2 * pad_x
    fy, fh = fy - pad_y, fh + 2 * pad_y
    x0 = max(0, int(fx * w))
    y0 = max(0, int(fy * h))
    x1 = min(w, int((fx + fw) * w))
    y1 = min(h, int((fy + fh) * h))
    if x1 - x0 < 20 or y1 - y0 < 10:
        return image
    return image[y0:y1, x0:x1]


# -------------------------------------------------------------- recognition
def ocr_text(image, *, lang: str | None = None) -> str:
    """Run tesseract over a preprocessed image."""
    import pytesseract

    return pytesseract.image_to_string(
        image, lang=lang or best_language(), config=TESSERACT_CONFIG
    )


#: The filler character; long runs of it are what OCR miscounts.
FILLER_CHAR = "<"

#: How many characters a line may be off its format width and still be
#: repaired - but only ever by adding or removing filler.
WIDTH_SLACK = 12


def looks_like_line2(line: str) -> bool:
    """True when a line has line 2's date fields where they belong.

    Line 2 ends in the composite check digit, so unlike a name line it must
    never be padded out with fillers - the padding would silently displace a
    check digit.  The two six-digit date runs are a cheap, reliable tell.
    """
    return len(line) >= 28 and line[13:19].isdigit() and line[21:27].isdigit()


def _fit_to_width(line: str, width: int) -> str | None:
    """Pad or trim a line to ``width`` using only its trailing fillers.

    Trailing fillers on a name line carry no information, so restoring them is
    safe.  Anything else - in particular a line 2, whose last character is a
    check digit - is rejected rather than mangled into shape.
    """
    if len(line) == width:
        return line
    if abs(len(line) - width) > WIDTH_SLACK:
        return None
    if len(line) < width:
        if not line.endswith(FILLER_CHAR) or looks_like_line2(line):
            return None
        return line + FILLER_CHAR * (width - len(line))
    excess = len(line) - width
    if line[-excess:] != FILLER_CHAR * excess:
        return None
    return line[:-excess]


def candidate_lines(raw: str) -> list[str]:
    """Every line that is an MRZ width, flattened.  Kept for callers/tests."""
    seen: list[str] = []
    for lines in candidates_by_width(raw).values():
        for line in lines:
            if line not in seen:
                seen.append(line)
    return seen


def candidates_by_width(raw: str) -> dict[int, list[str]]:
    """Fit each OCR'd line to *every* width it could plausibly be.

    A line of 38 characters could be a 44-wide line that lost six fillers or a
    36-wide one that gained two; guessing costs a real read, so both are
    offered and the check digits decide.
    """
    buckets: dict[int, list[str]] = {width: [] for width in LINE_WIDTHS}
    for line in raw.splitlines():
        cleaned = mrzlib.clean_line(line)
        if not cleaned:
            continue
        for width in LINE_WIDTHS:
            fitted = _fit_to_width(cleaned, width)
            if fitted is not None and fitted not in buckets[width]:
                buckets[width].append(fitted)
    return buckets


def group_candidates(lines: list[str]) -> list[list[str]]:
    """Group same-width lines into 2- or 3-line MRZ candidates."""
    groups: list[list[str]] = []
    for width, count in ((44, 2), (36, 2), (30, 3)):
        run = [line for line in lines if len(line) == width]
        for start in range(0, max(0, len(run) - count + 1)):
            groups.append(run[start : start + count])
    return [g for g in groups if len(g) in (2, 3)]


#: A synthetic line 1 used to validate a lone line 2.  TD3 and TD2 put every
#: one of their check digits - including the composite - inside line 2, so a
#: line 2 on its own is fully self-validating, and it carries everything BAC
#: needs.  TD1 spreads its composite across two lines and is excluded.
_LINE2_ONLY_HEAD = {
    44: "P<UTO" + FILLER_CHAR * 39,
    36: "I<UTO" + FILLER_CHAR * 31,
}


def try_line2_only(line: str) -> "OcrResult | None":
    """Validate a lone MRZ line 2.  Returns None unless every check passes."""
    head = _LINE2_ONLY_HEAD.get(len(line))
    if head is None:
        return None
    for attempt in (mrzlib.coerce_lines([head, line]), [head, line]):
        try:
            parsed = mrzlib.parse(attempt)
        except mrzlib.MrzError:
            continue
        if parsed.all_checks_ok:
            return OcrResult(
                mrz=parsed,
                lines=[attempt[1]],
                line2_only=True,
                reason="line 2 only - check digits valid, enough for BAC",
            )
    return None


def groups_from_raw(raw: str) -> list[list[str]]:
    """All plausible line groupings for one OCR pass, widest format first."""
    buckets = candidates_by_width(raw)
    groups: list[list[str]] = []
    for width, count in ((44, 2), (36, 2), (30, 3)):
        run = buckets.get(width, [])
        for start in range(0, max(0, len(run) - count + 1)):
            groups.append(run[start : start + count])
    return groups


@dataclass
class OcrResult:
    """One OCR attempt."""

    mrz: mrzlib.Mrz | None = None
    lines: list[str] = field(default_factory=list)
    raw: str = ""
    accepted: bool = False
    reason: str = ""
    #: Which preprocessing variant produced this read, for diagnostics.
    variant: str = ""
    #: True when only line 2 was recovered.  It self-validates and carries
    #: everything BAC needs, but the holder's name is not available.
    line2_only: bool = False

    @property
    def unverifiable_characters(self) -> str:
        """Document-number characters the check digits cannot vouch for.

        Valid check digits do NOT mean the document number is right: swaps
        like L/1 or S/8 are invisible to the 7-3-1 scheme.  The user gets the
        value in an editable box precisely so they can eyeball these.
        """
        if self.mrz is None:
            return ""
        number = self.mrz.document_number.value
        positions = mrzlib.ambiguous_positions(number)
        return "".join(sorted({number[i] for i in positions}))

    @property
    def checks_ok(self) -> bool:
        return self.mrz is not None and self.mrz.all_checks_ok


#: A strip must have at least this fraction of dark pixels to be worth an OCR
#: call.  An empty desk or a hand over the lens has almost none.
MIN_INK = 0.010
MAX_INK = 0.60


def ink_bands(mask, *, floor: float) -> int:
    """Count horizontal bands of ink - i.e. how many lines of text there are."""
    rows = mask.mean(axis=1) / 255.0
    bands = 0
    run = 0
    for value in rows:
        if value > floor:
            run += 1
        else:
            if run >= 3:  # a stray speckled row is not a line of text
                bands += 1
            run = 0
    if run >= 3:
        bands += 1
    return bands


def looks_like_text(image) -> tuple[bool, str]:
    """Cheap gate: does this strip plausibly hold MRZ lines?

    One OCR pass costs a few hundred milliseconds; this costs microseconds.
    Rejecting frames of desk, hand or half a passport photo here is what keeps
    the scan responsive while the user is still lining the document up.

    Returns ``(worth_trying, reason)`` so the UI can say something useful.
    """
    import cv2

    gray = to_gray(image)
    if gray.size == 0:
        return False, "no image"
    _, mask = cv2.threshold(gray, 0, 255, cv2.THRESH_BINARY_INV + cv2.THRESH_OTSU)
    ink = float(mask.mean()) / 255.0
    if ink < MIN_INK:
        return False, "hold the MRZ inside the box"
    if ink > MAX_INK:
        return False, "too dark - move into better light"
    # The MRZ is two or three dense, well-separated bands.  A photo, a hand or
    # the top half of the page gives one big blob or none at all.
    bands = ink_bands(mask, floor=max(ink * 1.5, 0.02))
    if bands < 2:
        return False, "line up both MRZ lines inside the box"
    return True, ""


def read_frame(
    image,
    *,
    guide: tuple[float, float, float, float] | None = None,
    lang: str | None = None,
) -> OcrResult:
    """Full pipeline for one frame.

    Each preprocessing variant is tried in turn and the first that produces a
    check-digit-valid MRZ wins; if none does, the most promising partial read
    is returned so the UI can show progress instead of silence.
    """
    try:
        cropped = crop_to_guide(image, guide) if guide else image
        # Deskew first: the gate measures horizontal bands of ink, and tilted
        # text smears those bands into one.  Straightening costs ~2 ms, far
        # less than the OCR pass the gate is there to avoid.
        straightened = deskew(cropped)
        worth_trying, why = looks_like_text(straightened)
        if not worth_trying:
            return OcrResult(reason=why)
        straightened = normalize_scale(straightened)
    except Exception as exc:
        return OcrResult(reason=f"preprocessing failed: {exc}")

    global _last_winner
    language = lang or best_language()
    best = OcrResult(reason="nothing recognised")
    for attempt, (name, variant) in enumerate(ordered_variants()):
        try:
            raw = ocr_text(variant(straightened), lang=language)
        except Exception as exc:
            return OcrResult(reason=f"OCR failed: {exc}")
        result = parse_raw(raw)
        result.variant = name
        if result.checks_ok:
            _last_winner = name
            return result
        if _score(result) > _score(best):
            best = result
        # Escalate to another variant only while there is something to work
        # with.  If two passes have found no line of MRZ length at all, the
        # frame is not framed right and a third pass will not change that -
        # the next frame is only milliseconds away.
        if attempt >= 1 and not best.lines and best.mrz is None:
            break
    return best


def _score(result: OcrResult) -> int:
    """Rank partial reads so the UI shows the closest attempt, not the last."""
    if result.mrz is not None:
        return 100 - len(result.mrz.failed_checks())
    return len(result.lines)


def parse_raw(raw: str) -> OcrResult:
    """Turn raw tesseract text into a validated MRZ, or explain why not.

    Candidate lines are repaired by field position before validation: a
    digits-only field never legitimately holds an 'O'.  If no complete MRZ
    survives, a self-validating line 2 is accepted on its own - it carries
    every value BAC needs.
    """
    fallback: OcrResult | None = None
    for group in groups_from_raw(raw):
        for attempt in (mrzlib.coerce_lines(group), group):
            try:
                parsed = mrzlib.parse(attempt)
            except mrzlib.MrzError:
                continue
            if parsed.all_checks_ok:
                return OcrResult(
                    mrz=parsed, lines=attempt, raw=raw, reason="check digits valid"
                )
            if fallback is None:
                fallback = OcrResult(
                    mrz=parsed,
                    lines=attempt,
                    raw=raw,
                    reason="check digits failed: " + ", ".join(parsed.failed_checks()),
                )

    buckets = candidates_by_width(raw)
    for width in (44, 36):
        for line in buckets.get(width, []):
            lone = try_line2_only(line)
            if lone is not None:
                lone.raw = raw
                return lone

    if fallback is not None:
        return fallback
    seen = candidate_lines(raw)
    if not seen:
        return OcrResult(raw=raw, reason="no line of MRZ length found")
    return OcrResult(
        raw=raw, lines=seen, reason="lines found but none parsed as an MRZ"
    )


class Acceptor:
    """Accept only when check digits pass and two consecutive frames agree."""

    def __init__(self, *, required_agreements: int = 2) -> None:
        self.required = required_agreements
        self._last: tuple[str, ...] | None = None
        self._streak = 0

    def offer(self, result: OcrResult) -> OcrResult:
        """Feed one OCR result; the returned result carries ``accepted``."""
        if result.mrz is None or not result.checks_ok:
            self._last = None
            self._streak = 0
            return result
        key = tuple(result.lines)
        if key == self._last:
            self._streak += 1
        else:
            self._last = key
            self._streak = 1
        if self._streak >= self.required:
            result.accepted = True
            result.reason = f"accepted after {self._streak} matching frames"
        else:
            result.reason = f"check digits valid, waiting for confirmation ({self._streak}/{self.required})"
        return result

    def reset(self) -> None:
        self._last = None
        self._streak = 0
