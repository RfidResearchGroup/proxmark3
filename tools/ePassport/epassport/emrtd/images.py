"""Locate and decode biometric images inside CBEFF-wrapped data groups.

DG2/DG5/DG7 wrap the actual image in an ISO/IEC 19794-5 (or 19794-4) header
whose length fields are not always trustworthy in the wild.  Rather than trust
them we scan for the image magic, which is what the pm3 client does too.
"""

from __future__ import annotations

import io
import logging
from dataclasses import dataclass

log = logging.getLogger(__name__)

JPEG_MAGIC = b"\xff\xd8\xff"
JP2_MAGIC = b"\x00\x00\x00\x0c\x6a\x50\x20\x20"  # JP2 signature box
J2K_MAGIC = b"\xff\x4f\xff\x51"  # raw JPEG2000 codestream
PNG_MAGIC = b"\x89PNG\r\n\x1a\n"


@dataclass
class ImageBlob:
    """Raw image bytes carved out of a data group."""

    data: bytes
    fmt: str  # "jpeg" | "jp2" | "j2k" | "png"
    offset: int

    @property
    def suffix(self) -> str:
        return {"jpeg": ".jpg", "jp2": ".jp2", "j2k": ".j2k", "png": ".png"}[self.fmt]


def find_image(buf: bytes) -> ImageBlob | None:
    """Return the first embedded image found in ``buf``, or None."""
    candidates: list[tuple[int, str]] = []
    for magic, fmt in (
        (JPEG_MAGIC, "jpeg"),
        (JP2_MAGIC, "jp2"),
        (J2K_MAGIC, "j2k"),
        (PNG_MAGIC, "png"),
    ):
        idx = buf.find(magic)
        if idx >= 0:
            candidates.append((idx, fmt))
    if not candidates:
        return None
    offset, fmt = min(candidates)
    return ImageBlob(data=buf[offset:], fmt=fmt, offset=offset)


def to_png(blob: ImageBlob) -> bytes | None:
    """Transcode an image blob to PNG bytes for Kivy.

    Kivy cannot load JPEG2000, and its JPEG loader is fussy about the odd
    truncated stream, so everything goes through Pillow / glymur first.
    Returns None when no decoder for the format is installed.
    """
    if blob.fmt in ("jpeg", "png"):
        png = _png_via_pillow(blob.data)
        if png is not None:
            return png
    if blob.fmt in ("jp2", "j2k"):
        png = _png_via_pillow(
            blob.data
        )  # Pillow has JPEG2000 support when built with openjpeg
        if png is not None:
            return png
        return _png_via_glymur(blob.data)
    return None


def _png_via_pillow(data: bytes) -> bytes | None:
    try:
        from PIL import Image
    except ImportError:
        log.warning("Pillow is not installed - cannot decode portrait")
        return None
    try:
        with Image.open(io.BytesIO(data)) as im:
            im.load()
            out = io.BytesIO()
            im.convert("RGB").save(out, format="PNG")
            return out.getvalue()
    except Exception as exc:  # a truncated portrait must not kill the render
        log.info("Pillow could not decode image: %s", exc)
        return None


def _png_via_glymur(data: bytes) -> bytes | None:
    try:
        import glymur
        import numpy as np
        from PIL import Image
    except ImportError:
        log.warning("glymur/numpy/Pillow missing - cannot decode JPEG2000 portrait")
        return None
    import tempfile
    from pathlib import Path

    tmp = Path(tempfile.mkdtemp(prefix="pm3passport-jp2-")) / "portrait.jp2"
    try:
        tmp.write_bytes(data)
        arr = glymur.Jp2k(str(tmp))[:]
        out = io.BytesIO()
        Image.fromarray(np.asarray(arr)).convert("RGB").save(out, format="PNG")
        return out.getvalue()
    except Exception as exc:
        log.info("glymur could not decode JPEG2000: %s", exc)
        return None
    finally:
        try:
            tmp.unlink(missing_ok=True)
            tmp.parent.rmdir()
        except OSError:
            pass


def decode_to_png(buf: bytes) -> tuple[bytes | None, ImageBlob | None]:
    """Convenience: carve an image out of a DG and transcode it to PNG."""
    blob = find_image(buf)
    if blob is None:
        return None, None
    return to_png(blob), blob
