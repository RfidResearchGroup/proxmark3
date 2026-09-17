"""Scan screen end to end: synthetic frames in, auto-filled BAC fields out.

Uses a fake camera so it runs on a build machine with no webcam, but exercises
the real OCR pipeline and the real acceptance rule.
"""

from __future__ import annotations

import glob
import os
import tempfile
import time
from pathlib import Path

import pytest

cv2 = pytest.importorskip("cv2")
numpy = pytest.importorskip("numpy")

from epassport.ocr import mrz_ocr  # noqa: E402

FONT = (
    Path(__file__).parent.parent
    / "epassport"
    / "assets"
    / "fonts"
    / "DejaVuSansMono.ttf"
)
L1 = "P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<"
L2 = "L898902C36UTO7408122F1204159ZE184226B<<<<<10"

pytestmark = pytest.mark.skipif(
    not mrz_ocr.tesseract_available()[0], reason="the tesseract binary is not installed"
)


def render_page(width: int = 1280, height: int = 900):
    """A synthetic data page with the MRZ where the guide box expects it."""
    from PIL import Image, ImageDraw, ImageFont

    img = Image.new("RGB", (width, height), (243, 238, 226))
    draw = ImageDraw.Draw(img)
    top = mrz_ocr.crop_to_guide  # documents the coupling below
    assert top is not None
    band_top = int(height * 0.60)
    draw.rectangle((0, band_top, width, int(height * 0.86)), fill=(250, 247, 240))
    size = int(width / 44 * 1.45)
    font = ImageFont.truetype(str(FONT), size)
    char_w = (width * 0.94) / 44
    for row, line in enumerate((L1, L2)):
        x = width * 0.03
        y = band_top + size * 0.35 + row * size * 1.35
        for ch in line:
            draw.text((x, y), ch, font=font, fill=(18, 18, 26))
            x += char_w
    return numpy.array(img)[:, :, ::-1].copy()


def test_the_pipeline_reads_a_frame_framed_by_the_guide() -> None:
    from epassport.ui.scan import GUIDE

    result = mrz_ocr.read_frame(render_page(), guide=GUIDE)
    assert result.checks_ok, f"{result.reason} / {result.lines}"
    # The dates and their check digits are fully verified.
    assert result.mrz.date_of_birth.value == "740812"
    assert result.mrz.date_of_expiry.value == "120415"
    assert result.mrz.nationality == "UTO"
    # The document number's shape is verified; individual characters are not -
    # see test_check_digits_cannot_see_every_ocr_slip.
    assert len(result.mrz.bac_document_number) == 9


def test_acceptance_needs_two_frames_then_yields_bac_input() -> None:
    from epassport.pm3.client import BacInput
    from epassport.ui.scan import GUIDE

    frame = render_page()
    acceptor = mrz_ocr.Acceptor()
    first = acceptor.offer(mrz_ocr.read_frame(frame, guide=GUIDE))
    assert not first.accepted
    second = acceptor.offer(mrz_ocr.read_frame(frame, guide=GUIDE))
    assert second.accepted

    parsed = second.mrz
    validated = BacInput(mrz_line2=parsed.mrz_line2).validated()
    assert validated.args()[0] == "-m"
    assert len(validated.args()[1]) == 44
    assert validated.args()[1][13:19] == "740812"
    assert validated.args()[1][21:27] == "120415"


def test_a_blank_frame_is_never_accepted() -> None:
    from epassport.ui.scan import GUIDE

    blank = numpy.full((900, 1280, 3), 235, dtype=numpy.uint8)
    acceptor = mrz_ocr.Acceptor()
    for _ in range(3):
        assert not acceptor.offer(mrz_ocr.read_frame(blank, guide=GUIDE)).accepted


def test_ocr_scratch_files_stay_out_of_slash_tmp() -> None:
    """A picture of somebody's MRZ must not be written to a shared /tmp."""
    original = tempfile.tempdir
    try:
        mrz_ocr.use_private_tempdir()
        assert tempfile.tempdir is not None
        scratch = Path(tempfile.tempdir)
        assert scratch.is_dir()
        assert scratch.stat().st_mode & 0o077 == 0, "OCR scratch dir must be owner-only"

        before = set(glob.glob("/tmp/tess_*"))
        mrz_ocr.read_frame(render_page())
        after = set(glob.glob("/tmp/tess_*"))
        assert after == before, "tesseract wrote scratch files into /tmp"

        mrz_ocr.clear_private_tempdir()
        assert not any(scratch.iterdir())
    finally:
        tempfile.tempdir = original


def test_camera_thread_stops_cleanly_without_a_camera(monkeypatch) -> None:
    """No camera must mean a clear message, not a hung thread."""
    from epassport.ocr.camera import CameraThread

    class DeadCapture:
        def __init__(self, *_a, **_k) -> None:
            pass

        def isOpened(self) -> bool:
            return False

        def release(self) -> None:
            pass

        def set(self, *_a) -> None:
            pass

        def read(self):
            return False, None

    monkeypatch.setattr(cv2, "VideoCapture", DeadCapture)
    errors: list[str] = []
    camera = CameraThread(index=0, on_error=errors.append)
    camera.start()
    for _ in range(100):
        if errors:
            break
        time.sleep(0.02)
    camera.stop()
    assert errors, "a missing camera must report an error"
    assert "/dev/video" in errors[0]
    assert not camera.running
