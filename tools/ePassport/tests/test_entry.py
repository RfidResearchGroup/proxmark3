"""Manual-entry sanitising and live validation (no GUI needed)."""

from __future__ import annotations

import pytest

from epassport.ui.entry import (
    date_problem,
    sanitize_date,
    sanitize_docnum,
    sanitize_line2,
)


def test_docnum_is_uppercased_filtered_and_capped() -> None:
    assert sanitize_docnum("l898902c3") == "L898902C3"
    assert sanitize_docnum("L8989 02C3!") == "L898902C3"
    assert sanitize_docnum("1234567890123") == "123456789"
    assert sanitize_docnum("ab<<") == "AB<<"


def test_date_is_digits_only_and_capped() -> None:
    assert sanitize_date("74-08-12") == "740812"
    assert sanitize_date("74081234") == "740812"
    assert sanitize_date("abc") == ""


def test_line2_is_capped_at_44() -> None:
    assert len(sanitize_line2("X" * 60)) == 44
    assert sanitize_line2("l898902c3<") == "L898902C3<"


@pytest.mark.parametrize(
    "value,expected",
    [
        ("740812", ""),
        ("74081", "YYMMDD"),
        ("741312", "month must be 01-12"),
        ("740012", "month must be 01-12"),
        ("740230", "day must be 01-29"),
        ("740431", "day must be 01-30"),
        ("740229", ""),  # leap-safe: MRZ years are ambiguous, so 29 Feb is allowed
    ],
)
def test_date_problem_messages(value: str, expected: str) -> None:
    assert date_problem(value) == expected


# ------------------------------------------------------- the form as a whole
from epassport.pm3.client import AUTH_AUTO, AUTH_BAC, AUTH_PACE  # noqa: E402
from epassport.ui.entry import auth_hint, build_input, validate_form  # noqa: E402

TRIPLE = dict(
    document_number="L898902C3", date_of_birth="740812", date_of_expiry="120415"
)
LINE2 = "L898902C36UTO7408122F1204159ZE184226B<<<<<10"


def test_a_can_alone_is_enough_to_read() -> None:
    """Regression: entering a CAN left the MRZ markers set, so Read stayed
    disabled on a form that was perfectly valid."""
    state = validate_form(can="123456")
    assert state.valid
    assert state.docnum_error == ""
    assert state.dob_error == ""
    assert state.expiry_error == ""
    assert state.can_error == ""
    assert build_input(can="123456").args() == ["--can", "123456"]


def test_the_mrz_triple_alone_is_enough() -> None:
    state = validate_form(**TRIPLE)
    assert state.valid
    assert state.can_error == ""


def test_line2_alone_is_enough() -> None:
    state = validate_form(mrz_line2=LINE2)
    assert state.valid
    assert build_input(mrz_line2=LINE2).args() == ["-m", LINE2]


def test_an_untouched_form_is_invalid_but_says_nothing_alarming() -> None:
    state = validate_form()
    assert not state.valid
    assert state.note == ""
    assert state.docnum_error == "required"


def test_a_can_plus_mrz_is_refused_with_a_usable_message() -> None:
    state = validate_form(can="123456", **TRIPLE)
    assert not state.valid
    assert "clear the MRZ" in state.can_error


def test_a_can_of_the_wrong_length_is_refused() -> None:
    assert validate_form(can="1" * 15).can_error == "1-14 digits"
    assert not validate_form(can="1" * 15).valid


def test_an_unusual_can_length_is_allowed_but_flagged() -> None:
    state = validate_form(can="1234")
    assert state.valid
    assert "usually 6 digits" in state.note


def test_an_incomplete_triple_keeps_read_disabled() -> None:
    state = validate_form(document_number="L898902C3", date_of_birth="740812")
    assert not state.valid
    assert state.expiry_error == "YYMMDD"


def test_a_bad_date_keeps_read_disabled() -> None:
    state = validate_form(**{**TRIPLE, "date_of_birth": "741301"})
    assert not state.valid
    assert "month" in state.dob_error


def test_a_short_line2_is_flagged() -> None:
    state = validate_form(mrz_line2=LINE2[:40], **TRIPLE)
    assert not state.valid
    assert "40/44" in state.line2_error


def test_forcing_bac_with_a_can_is_refused() -> None:
    state = validate_form(can="123456", mode=AUTH_BAC)
    assert not state.valid
    assert "PACE-only" in state.note


def test_forcing_pace_with_nothing_is_refused() -> None:
    state = validate_form(mode=AUTH_PACE)
    assert not state.valid


def test_the_hint_describes_the_chosen_mode() -> None:
    assert "PACE is tried first" in auth_hint(AUTH_AUTO, "")
    assert "Forcing BAC" in auth_hint(AUTH_BAC, "")
    assert "no BAC fallback" in auth_hint(AUTH_PACE, "")
    assert "Card Access Number" in auth_hint(AUTH_AUTO, "123456")


def test_mode_is_carried_into_the_command() -> None:
    assert build_input(can="123456", mode=AUTH_PACE).args() == [
        "--can",
        "123456",
        "--pace",
    ]
    assert build_input(mode=AUTH_BAC, **TRIPLE).args()[-1] == "--bac"
    assert build_input(mode=AUTH_AUTO, **TRIPLE).args()[-1] == "120415"


def test_the_note_explains_why_read_is_disabled() -> None:
    state = validate_form(can="123456", **TRIPLE)
    assert not state.valid
    assert "clear the MRZ" in state.note, "the note must name the blocker"
