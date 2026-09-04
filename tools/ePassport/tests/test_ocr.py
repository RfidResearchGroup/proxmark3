"""MRZ OCR post-processing and the two-frame acceptance rule."""

from __future__ import annotations

import pytest

from epassport.ocr import mrz_ocr

GOOD = """
some header noise
P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<
L898902C36UTO7408122F1204159ZE184226B<<<<<10
"""

# The same strip with the fillers misread as guillemets and a stray space.
NOISY = """
P«UTOERIKSSON««ANNA«MARIA«««««««««««««««««««
L898902C36UTO7408122F1204159ZE184226B««««« 10
"""

BAD_CHECK = """
P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<
L898902C30UTO7408122F1204159ZE184226B<<<<<10
"""


def test_clean_read_parses_and_validates() -> None:
    result = mrz_ocr.parse_raw(GOOD)
    assert result.mrz is not None
    assert result.mrz.surname == "ERIKSSON"
    assert result.checks_ok


def test_ocr_confusions_are_repaired_before_validation() -> None:
    result = mrz_ocr.parse_raw(NOISY)
    assert result.checks_ok, result.reason
    assert result.mrz.document_number.value == "L898902C3"


def test_bad_check_digit_is_reported_and_never_accepted() -> None:
    acceptor = mrz_ocr.Acceptor()
    for _ in range(5):
        result = acceptor.offer(mrz_ocr.parse_raw(BAD_CHECK))
        assert not result.accepted
    assert "check digits failed" in result.reason


def test_two_consecutive_agreeing_frames_are_required() -> None:
    acceptor = mrz_ocr.Acceptor()
    first = acceptor.offer(mrz_ocr.parse_raw(GOOD))
    assert not first.accepted
    assert "1/2" in first.reason
    second = acceptor.offer(mrz_ocr.parse_raw(GOOD))
    assert second.accepted


def test_a_disagreeing_frame_resets_the_streak() -> None:
    acceptor = mrz_ocr.Acceptor()
    acceptor.offer(mrz_ocr.parse_raw(GOOD))
    acceptor.offer(mrz_ocr.parse_raw(BAD_CHECK))  # a junk frame
    assert not acceptor.offer(mrz_ocr.parse_raw(GOOD)).accepted  # back to 1/2


def test_no_mrz_length_line_is_reported_not_raised() -> None:
    result = mrz_ocr.parse_raw("just some words\nand more words")
    assert result.mrz is None
    assert "no line of MRZ length" in result.reason


def test_candidate_lines_only_keeps_mrz_widths() -> None:
    lines = mrz_ocr.candidate_lines("A" * 44 + "\n" + "B" * 43 + "\n" + "C" * 30)
    assert [len(line) for line in lines] == [44, 30]


def test_tesseract_availability_reports_a_remedy() -> None:
    available, reason = mrz_ocr.tesseract_available()
    assert available or "install" in reason


cv2 = pytest.importorskip("cv2")
numpy = pytest.importorskip("numpy")


def test_preprocess_returns_a_binary_image() -> None:
    frame = numpy.full((120, 480, 3), 220, dtype=numpy.uint8)
    cv2.putText(
        frame, "P<UTOERIKSSON", (10, 70), cv2.FONT_HERSHEY_SIMPLEX, 1.0, (0, 0, 0), 2
    )
    out = mrz_ocr.preprocess(frame)
    assert out.ndim == 2
    assert set(numpy.unique(out)) <= {0, 255}


def test_crop_to_guide_without_margin_is_exact() -> None:
    frame = numpy.zeros((100, 200, 3), dtype=numpy.uint8)
    cropped = mrz_ocr.crop_to_guide(frame, (0.1, 0.5, 0.8, 0.4), margin=0.0)
    assert cropped.shape[0] == 40 and cropped.shape[1] == 160


def test_crop_to_guide_adds_a_margin_so_tilted_pages_keep_their_edges() -> None:
    frame = numpy.zeros((100, 200, 3), dtype=numpy.uint8)
    exact = mrz_ocr.crop_to_guide(frame, (0.1, 0.5, 0.8, 0.4), margin=0.0)
    padded = mrz_ocr.crop_to_guide(frame, (0.1, 0.5, 0.8, 0.4))
    assert padded.shape[0] > exact.shape[0]
    assert padded.shape[1] > exact.shape[1]


def test_crop_to_guide_clamps_to_the_frame() -> None:
    frame = numpy.zeros((100, 200, 3), dtype=numpy.uint8)
    whole = mrz_ocr.crop_to_guide(frame, (0.0, 0.0, 1.0, 1.0))
    assert whole.shape == frame.shape
    # A degenerate guide falls back to the whole frame rather than crashing.
    assert mrz_ocr.crop_to_guide(frame, (0.0, 0.0, 0.005, 0.005)).shape == frame.shape


def test_normalize_scale_lifts_a_thin_strip_and_caps_a_huge_one() -> None:
    thin = numpy.zeros((40, 800, 3), dtype=numpy.uint8)
    assert mrz_ocr.normalize_scale(thin).shape[0] >= mrz_ocr.MIN_STRIP_HEIGHT
    huge = numpy.zeros((900, 3000, 3), dtype=numpy.uint8)
    assert mrz_ocr.normalize_scale(huge).shape[0] <= mrz_ocr.MAX_STRIP_HEIGHT
    ok = numpy.zeros((mrz_ocr.MAX_STRIP_HEIGHT - 20, 1200, 3), dtype=numpy.uint8)
    assert mrz_ocr.normalize_scale(ok).shape == ok.shape


def test_deskew_leaves_straight_text_alone() -> None:
    img = numpy.full((120, 600, 3), 240, dtype=numpy.uint8)
    cv2.putText(
        img, "P<UTOERIKSSON", (10, 80), cv2.FONT_HERSHEY_SIMPLEX, 1.2, (0, 0, 0), 3
    )
    assert mrz_ocr.deskew(img).shape == img.shape


# ---------------------------------------------------- width repair & line 2
L2 = "L898902C36UTO7408122F1204159ZE184226B<<<<<10"
L1 = "P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<"


def test_a_short_filler_run_on_the_name_line_is_repaired() -> None:
    # Tesseract habitually miscounts long runs of '<'.
    short = L1[:38]
    assert short.endswith("<")
    result = mrz_ocr.parse_raw(short + "\n" + L2)
    assert result.checks_ok, result.reason
    assert result.mrz.surname == "ERIKSSON"


def test_an_over_long_filler_run_is_trimmed() -> None:
    result = mrz_ocr.parse_raw(L1 + "<<<" + "\n" + L2)
    assert result.checks_ok, result.reason


def test_a_line_ending_in_a_check_digit_is_never_padded() -> None:
    # Losing characters from line 2 must fail, not be silently filled in.
    assert mrz_ocr._fit_to_width(L2[:41], 44) is None
    assert mrz_ocr._fit_to_width("ABC", 44) is None


def test_a_wrong_length_line_can_map_to_more_than_one_format() -> None:
    buckets = mrz_ocr.candidates_by_width(L1[:38])
    assert len(buckets[44]) == 1 and len(buckets[36]) == 1
    assert len(buckets[44][0]) == 44 and len(buckets[36][0]) == 36


def test_positional_coercion_repairs_a_country_code() -> None:
    # "UTO" misread as "UT0" breaks the composite check until it is repaired.
    result = mrz_ocr.parse_raw(L1 + "\n" + L2.replace("UTO", "UT0"))
    assert result.checks_ok, result.reason
    assert result.mrz.nationality == "UTO"


def test_a_lone_line2_is_accepted_because_it_self_validates() -> None:
    result = mrz_ocr.parse_raw(L2)
    assert result.checks_ok
    assert result.line2_only
    assert result.mrz.bac_document_number == "L898902C3"
    assert result.mrz.date_of_birth.value == "740812"
    assert result.mrz.date_of_expiry.value == "120415"


def test_a_corrupted_lone_line2_is_rejected() -> None:
    corrupted = L2[:-1] + ("9" if L2[-1] != "9" else "8")
    assert not mrz_ocr.parse_raw(corrupted).checks_ok


def test_a_lone_line1_is_not_enough() -> None:
    result = mrz_ocr.parse_raw(L1)
    assert not result.checks_ok


def test_lone_line2_still_needs_two_agreeing_frames() -> None:
    acceptor = mrz_ocr.Acceptor()
    assert not acceptor.offer(mrz_ocr.parse_raw(L2)).accepted
    assert acceptor.offer(mrz_ocr.parse_raw(L2)).accepted


# ------------------------------------------- what check digits cannot catch
def test_check_digits_cannot_see_every_ocr_slip() -> None:
    """The 7-3-1 checksum is mod 10, so value differences of 10 are invisible.

    This is not a bug in the implementation - it is a property of the ICAO
    scheme, and it is exactly why a scan fills an editable form instead of
    starting a read on its own.
    """
    from epassport.emrtd import mrz as mrzlib

    for good, blind in (("L", "1"), ("S", "8"), ("G", "6"), ("Z", "5")):
        number = f"{good}898902C3"
        swapped = f"{blind}898902C3"
        assert mrzlib.check_digit(number) == mrzlib.check_digit(swapped)


def test_confusions_that_check_digits_do_catch() -> None:
    from epassport.emrtd import mrz as mrzlib

    # O(24) vs 0(0) differ by 24, so this one IS detected - which is why the
    # positional coercion of country codes is worth doing.
    assert mrzlib.check_digit("UTO") != mrzlib.check_digit("UT0")


def test_blind_confusions_are_symmetric_and_exclude_identity() -> None:
    from epassport.emrtd import mrz as mrzlib

    table = mrzlib.blind_confusions()
    for char, others in table.items():
        assert char not in others
        for other in others:
            assert char in table[other]


def test_ambiguous_positions_flags_the_risky_characters() -> None:
    from epassport.emrtd import mrz as mrzlib

    assert mrzlib.ambiguous_positions("L1") == [0, 1]
    assert mrzlib.ambiguous_positions("XXX") == []


def test_result_reports_unverifiable_document_number_characters() -> None:
    result = mrz_ocr.parse_raw(L2)
    assert "L" in result.unverifiable_characters
    assert mrz_ocr.OcrResult().unverifiable_characters == ""


# ------------------------------------------------------- the cheap OCR gate
def test_the_gate_rejects_a_blank_strip() -> None:
    blank = numpy.full((180, 1100, 3), 235, dtype=numpy.uint8)
    worth, why = mrz_ocr.looks_like_text(blank)
    assert not worth
    assert "box" in why


def test_the_gate_rejects_an_almost_black_strip() -> None:
    dark = numpy.full((180, 1100, 3), 4, dtype=numpy.uint8)
    dark[40:60, :] = 250  # a sliver of light so Otsu has two classes
    worth, why = mrz_ocr.looks_like_text(dark)
    assert not worth


def test_the_gate_rejects_a_single_blob() -> None:
    """A photo or a hand is one mass of ink, not two lines."""
    blob = numpy.full((180, 1100, 3), 240, dtype=numpy.uint8)
    cv2.rectangle(blob, (100, 40), (900, 140), (20, 20, 20), -1)
    worth, why = mrz_ocr.looks_like_text(blob)
    assert not worth
    assert "both MRZ lines" in why


def test_the_gate_accepts_two_lines_of_text() -> None:
    strip = numpy.full((180, 1100, 3), 240, dtype=numpy.uint8)
    for row in (55, 125):
        cv2.putText(
            strip,
            "P<UTOERIKSSON<<ANNA",
            (20, row),
            cv2.FONT_HERSHEY_SIMPLEX,
            1.4,
            (10, 10, 10),
            3,
        )
    worth, why = mrz_ocr.looks_like_text(strip)
    assert worth, why


def test_ink_bands_counts_lines() -> None:
    mask = numpy.zeros((100, 200), dtype=numpy.uint8)
    mask[10:20, :] = 255
    mask[50:62, :] = 255
    assert mrz_ocr.ink_bands(mask, floor=0.1) == 2
    mask[80:81, :] = 255  # a single row is noise, not a line
    assert mrz_ocr.ink_bands(mask, floor=0.1) == 2


def test_a_gated_frame_costs_no_ocr_call(monkeypatch) -> None:
    """The whole point of the gate is to not pay for tesseract."""
    calls: list[int] = []
    monkeypatch.setattr(mrz_ocr, "ocr_text", lambda *a, **k: calls.append(1) or "")
    blank = numpy.full((900, 1280, 3), 235, dtype=numpy.uint8)
    result = mrz_ocr.read_frame(blank, guide=(0.06, 0.60, 0.88, 0.26))
    assert calls == []
    assert not result.checks_ok


def test_variant_escalation_stops_when_nothing_is_recognised(monkeypatch) -> None:
    calls: list[int] = []

    def nothing(*_a, **_k):
        calls.append(1)
        return "qqq\nqqq"  # no line of MRZ length

    monkeypatch.setattr(mrz_ocr, "ocr_text", nothing)
    monkeypatch.setattr(mrz_ocr, "looks_like_text", lambda img: (True, ""))
    strip = numpy.full((200, 1200, 3), 240, dtype=numpy.uint8)
    mrz_ocr.read_frame(strip)
    assert len(calls) == 2, "a third pass cannot help when two found nothing"


def test_all_variants_run_while_there_is_partial_signal(monkeypatch) -> None:
    calls: list[int] = []

    def partial(*_a, **_k):
        calls.append(1)
        return L1 + "\n" + L2[:-1] + "9"  # right shape, bad composite

    monkeypatch.setattr(mrz_ocr, "ocr_text", partial)
    monkeypatch.setattr(mrz_ocr, "looks_like_text", lambda img: (True, ""))
    strip = numpy.full((200, 1200, 3), 240, dtype=numpy.uint8)
    mrz_ocr.read_frame(strip)
    assert len(calls) == len(mrz_ocr.VARIANTS)


def test_the_last_winning_variant_is_tried_first_next_time() -> None:
    mrz_ocr._last_winner = "adaptive"
    try:
        assert mrz_ocr.ordered_variants()[0][0] == "adaptive"
    finally:
        mrz_ocr._last_winner = ""
    assert mrz_ocr.ordered_variants() == mrz_ocr.VARIANTS


def test_best_language_is_cached() -> None:
    """It shells out to tesseract; paying that per frame was measurable."""
    mrz_ocr.best_language.cache_clear()
    first = mrz_ocr.best_language()
    assert mrz_ocr.best_language() is first
    assert mrz_ocr.best_language.cache_info().hits >= 1
