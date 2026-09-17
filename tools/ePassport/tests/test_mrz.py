"""Golden ICAO 9303 vectors, plus deliberately corrupted ones."""

from __future__ import annotations

import datetime as dt

import pytest

from epassport.emrtd import mrz

TODAY = dt.date(2026, 8, 21)

# ICAO 9303 part 4 specimen (Utopia).
TD3 = [
    "P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<",
    "L898902C36UTO7408122F1204159ZE184226B<<<<<10",
]

# ICAO 9303 part 5 specimen.
TD1 = [
    "I<UTOD231458907<<<<<<<<<<<<<<<",
    "7408122F1204159UTO<<<<<<<<<<<6",
    "ERIKSSON<<ANNA<MARIA<<<<<<<<<<",
]

# ICAO 9303 part 6 specimen.
TD2 = [
    "I<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<",
    "D231458907UTO7408122F1204159<<<<<<<6",
]


def test_char_value_covers_the_whole_alphabet() -> None:
    assert mrz.char_value("<") == 0
    assert mrz.char_value("0") == 0
    assert mrz.char_value("9") == 9
    assert mrz.char_value("A") == 10
    assert mrz.char_value("Z") == 35
    with pytest.raises(mrz.MrzError):
        mrz.char_value("a")


@pytest.mark.parametrize(
    "data,digit",
    [
        ("D23145890", "7"),
        ("740812", "2"),
        ("120415", "9"),
        ("L898902C3", "6"),
    ],
)
def test_check_digit_vectors(data: str, digit: str) -> None:
    assert mrz.check_digit(data) == digit
    assert mrz.verify(data, digit)


def test_filler_check_digit_only_valid_for_empty_field() -> None:
    assert mrz.verify("<<<<<<", "<")
    assert not mrz.verify("ABC<<<", "<")


def test_td3_specimen() -> None:
    m = mrz.parse(TD3, today=TODAY)
    assert m.kind == "TD3"
    assert m.document_code == "P"
    assert m.document_type == "PASSPORT"
    assert m.issuing_state == "UTO"
    assert m.issuing_state_name == "Utopia"
    assert m.surname == "ERIKSSON"
    assert m.given_names == "ANNA MARIA"
    assert m.document_number.value == "L898902C3"
    assert m.nationality == "UTO"
    assert m.sex == "F"
    assert m.optional_data.value == "ZE184226B"
    assert m.all_checks_ok
    assert m.failed_checks() == []


def test_td3_dates_use_the_sliding_window() -> None:
    m = mrz.parse(TD3, today=TODAY)
    assert m.dob == dt.date(1974, 8, 12)  # not 2074
    assert m.expiry == dt.date(2012, 4, 15)  # expired, but not 1912
    assert m.dob_text == "12 AUG 1974"
    assert m.expiry_text == "15 APR 2012"


def test_expiry_in_the_near_future_stays_in_this_century() -> None:
    line1 = "P<SWEANDERSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<"
    line2 = mrz.build_td3_line2(
        "12345678", "890101", "300401", nationality="SWE", sex="F"
    )
    m = mrz.parse([line1, line2], today=TODAY)
    assert m.dob == dt.date(1989, 1, 1)
    assert m.expiry == dt.date(2030, 4, 1)
    assert m.issuing_state_name == "Sweden"
    assert m.all_checks_ok, m.failed_checks()


def test_td1_specimen() -> None:
    m = mrz.parse(TD1, today=TODAY)
    assert m.kind == "TD1"
    assert m.document_number.value == "D23145890"
    assert m.nationality == "UTO"
    assert m.surname == "ERIKSSON"
    assert m.given_names == "ANNA MARIA"
    assert m.dob == dt.date(1974, 8, 12)
    assert m.all_checks_ok, m.failed_checks()


def test_td2_specimen() -> None:
    m = mrz.parse(TD2, today=TODAY)
    assert m.kind == "TD2"
    assert m.document_number.value == "D23145890"
    assert m.surname == "ERIKSSON"
    assert m.all_checks_ok, m.failed_checks()


def test_document_number_longer_than_nine_chars() -> None:
    # Number "ABC123456789" overflows into the optional-data field.
    number = "ABC123456789"
    head, rest = number[:9], number[9:]
    line1 = "P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<"
    optional = (rest + mrz.check_digit(number)).ljust(14, "<")
    body = head + "<" + "UTO" + "740812" + "2" + "F" + "120415" + "9" + optional
    body += mrz.check_digit(optional)
    line2 = body + mrz.check_digit(body[0:10] + body[13:20] + body[21:43])
    m = mrz.parse([line1, line2], today=TODAY)
    assert m.document_number.value == number
    assert m.document_number.ok
    assert m.composite.ok


@pytest.mark.parametrize(
    "pos,label",
    [
        (9, "document number"),
        (19, "date of birth"),
        (27, "date of expiry"),
        (43, "composite"),
    ],
)
def test_corrupted_check_digits_are_reported_not_raised(pos: int, label: str) -> None:
    line2 = list(TD3[1])
    line2[pos] = "0" if line2[pos] != "0" else "1"
    m = mrz.parse([TD3[0], "".join(line2)], today=TODAY)
    assert label in m.failed_checks()
    assert not m.all_checks_ok
    # ...but the document still renders.
    assert m.surname == "ERIKSSON"


def test_corrupted_payload_flags_composite_too() -> None:
    line2 = TD3[1][:13] + "990101" + TD3[1][19:]
    m = mrz.parse([TD3[0], line2], today=TODAY)
    assert "date of birth" in m.failed_checks()
    assert "composite" in m.failed_checks()


def test_ocr_noise_is_cleaned_before_parsing() -> None:
    noisy = [
        "P«UTOERIKSSON««ANNA«MARIA«««««««««««««««« «««",
        "L898902C36UTO7408122F1204159ZE184226B«««« «10",
    ]
    m = mrz.parse(noisy, today=TODAY)
    assert m.surname == "ERIKSSON"
    assert m.all_checks_ok


def test_bad_geometry_raises() -> None:
    with pytest.raises(mrz.MrzError):
        mrz.parse(["TOO SHORT"])
    with pytest.raises(mrz.MrzError):
        mrz.parse([])


def test_illegal_characters_raise() -> None:
    with pytest.raises(mrz.MrzError):
        mrz.parse(["P#UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<", TD3[1]])


def test_build_td3_line2_round_trips() -> None:
    line2 = mrz.build_td3_line2(
        "L898902C3", "740812", "120415", nationality="UTO", sex="F"
    )
    assert len(line2) == 44
    m = mrz.parse([TD3[0], line2], today=TODAY)
    assert m.all_checks_ok, m.failed_checks()
    assert m.document_number.value == "L898902C3"
    assert m.bac_document_number == "L898902C3"


def test_split_names_handles_single_and_missing_given_names() -> None:
    assert mrz.split_names("ERIKSSON<<ANNA<MARIA<<<<") == ("ERIKSSON", "ANNA MARIA")
    assert mrz.split_names("ERIKSSON<<<<<<") == ("ERIKSSON", "")
    assert mrz.split_names("VAN<DER<BERG<<JAN<<<") == ("VAN DER BERG", "JAN")


# --------------------------------- document numbers longer than nine characters
def _td3_with_long_number(number: str = "AB1234567890") -> list[str]:
    """ICAO puts the overflow in the optional-data field.

    Positions 1-9 hold the first nine characters, position 10 a filler in
    place of the check digit, and the optional-data field opens with the rest
    of the number followed by the check digit for the whole of it.
    """
    head, rest = number[:9], number[9:]
    dob, expiry = "740812", "120415"
    optional = (rest + mrz.check_digit(number)).ljust(14, "<")
    body = (
        head
        + "<"
        + "UTO"
        + dob
        + mrz.check_digit(dob)
        + "F"
        + expiry
        + mrz.check_digit(expiry)
        + optional
        + mrz.check_digit(optional)
    )
    line2 = body + mrz.check_digit(body[0:10] + body[13:20] + body[21:43])
    return ["P<UTOERIKSSON<<ANNA<MARIA".ljust(44, "<"), line2]


def test_a_long_document_number_is_put_back_together() -> None:
    parsed = mrz.parse(_td3_with_long_number())
    assert parsed.document_number.value == "AB1234567890"
    assert parsed.document_number.ok is True


def test_the_overflow_does_not_linger_in_the_optional_field() -> None:
    """It is part of the document number, not data the State chose to add.

    Left there it was reported as the holder's personal number, since that
    falls back to the MRZ optional-data field when DG11 carries none.
    """
    parsed = mrz.parse(_td3_with_long_number())
    assert parsed.optional_data.value == ""


def test_a_nine_character_number_leaves_the_optional_field_alone() -> None:
    dob, expiry = "740812", "120415"
    optional = "ZE184226B".ljust(14, "<")
    body = (
        "L898902C"
        + "<"
        + mrz.check_digit("L898902C<")
        + "UTO"
        + dob
        + mrz.check_digit(dob)
        + "F"
        + expiry
        + mrz.check_digit(expiry)
        + optional
        + mrz.check_digit(optional)
    )
    line2 = body + mrz.check_digit(body[0:10] + body[13:20] + body[21:43])
    parsed = mrz.parse(["P<UTOERIKSSON<<ANNA".ljust(44, "<"), line2])
    assert parsed.optional_data.value == "ZE184226B"
