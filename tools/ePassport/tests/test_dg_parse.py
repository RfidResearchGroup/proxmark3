"""Data-group decoding, driven by the checked-in synthetic dumps."""

from __future__ import annotations

from pathlib import Path

import pytest

from epassport.emrtd import dg
from epassport.emrtd.model import FileState
from epassport.emrtd.tlv import encode


@pytest.fixture(scope="session")
def record(td3: Path):
    return dg.load_dump(td3)


# ------------------------------------------------------------- synthetic
def test_parse_com_tag_list() -> None:
    com = dg.parse_com(
        encode(
            0x60,
            encode(0x5F01, b"0107")
            + encode(0x5F36, b"040000")
            + encode(0x5C, b"\x61\x75\x6b"),
        )
    )
    assert com.lds_version == "01.07"
    assert com.unicode_version == "04.00.00"
    assert com.present_dgs == [1, 2, 11]


def test_parse_dg1_splits_a_td3_blob_into_two_lines() -> None:
    blob = "P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<L898902C36UTO7408122F1204159ZE184226B<<<<<10"
    m = dg.parse_dg1(encode(0x61, encode(0x5F1F, blob.encode())))
    assert m is not None and m.kind == "TD3"
    assert m.surname == "ERIKSSON"


def test_parse_dg1_returns_none_on_garbage() -> None:
    assert dg.parse_dg1(encode(0x61, encode(0x5F1F, b"NOT AN MRZ"))) is None
    assert dg.parse_dg1(b"") is None


def test_dg11_separator_expansion() -> None:
    p = dg.parse_dg11(
        encode(
            0x6B,
            encode(0x5F0E, b"ERIKSSON<<ANNA<MARIA")
            + encode(0x5F11, b"STOCKHOLM<SWEDEN"),
        )
    )
    assert p.full_name == "ERIKSSON, ANNA MARIA"
    assert p.place_of_birth == "STOCKHOLM SWEDEN"


def test_dg12_dates_stay_raw_for_the_model_to_format() -> None:
    d = dg.parse_dg12(
        encode(
            0x6C,
            encode(0x5F19, b"UTOPIA PASSPORT AGENCY") + encode(0x5F26, b"20200401"),
        )
    )
    assert d.issuing_authority == "UTOPIA PASSPORT AGENCY"
    assert d.date_of_issue == "20200401"


def test_extract_image_finds_jpeg_after_a_cbeff_header() -> None:
    from PIL import Image
    import io

    buf = io.BytesIO()
    Image.new("RGB", (8, 8), (1, 2, 3)).save(buf, "JPEG")
    png = dg.extract_image(b"\x7f\x61\x0a" + b"\x00" * 40 + buf.getvalue())
    assert png.startswith(b"\x89PNG")


def test_extract_image_on_empty_and_imageless_input() -> None:
    assert dg.extract_image(b"") == b""
    assert dg.extract_image(b"\x00" * 64) == b""


# ------------------------------------------------------------ real dumps
def test_full_record_from_sample_dump(record) -> None:
    assert record.mrz is not None
    assert record.surname == "ERIKSSON"
    assert record.given_names == "ANNA MARIA"
    assert record.display_name == "ANNA MARIA ERIKSSON"
    assert record.mrz.all_checks_ok
    assert record.warnings == []


def test_portrait_and_signature_decode(record) -> None:
    assert record.portrait_png.startswith(b"\x89PNG")
    assert record.signature_png.startswith(b"\x89PNG")


def test_dg11_and_dg12_populate_the_page(record) -> None:
    assert record.place_of_birth == "STOCKHOLM SWEDEN"
    assert record.issuing_authority == "UTOPIA PASSPORT AGENCY"
    assert record.date_of_issue == "01 APR 2020"
    assert record.full_date_of_birth == "12 AUG 1974"


def test_dg14_and_dg15_summarised(record) -> None:
    assert any("Active Authentication" in p for p in record.security.protocols)
    assert record.security.aa_algorithm.startswith("RSA")
    assert record.security.aa_key_size == "1024 bit"


def test_sod_hashes_all_match(record) -> None:
    assert record.sod.available, record.sod.message
    assert record.sod.hash_algorithm == "SHA-256"
    assert "Utopia Document Signer 01" in record.sod.signer_subject
    assert record.sod.hashes
    assert all(h.status == "match" for h in record.sod.hashes)
    assert record.sod.mismatches == []


def test_tampered_dg2_is_flagged(td3_tampered: Path) -> None:
    tampered = dg.load_dump(td3_tampered)
    bad = tampered.sod.mismatches
    assert [h.dg for h in bad] == [2]
    # everything else still renders
    assert tampered.surname == "ERIKSSON"
    assert tampered.portrait_png.startswith(b"\x89PNG")


def test_eac_groups_are_protected_not_errors(record) -> None:
    assert record.file("EF_DG3").state == FileState.PROTECTED
    assert record.file("EF_DG4").state == FileState.PROTECTED
    assert record.file("EF_DG1").state == FileState.PRESENT
    assert record.file("EF_DG5").state == FileState.ABSENT
    assert record.has_dg(2) and not record.has_dg(5)


def test_td1_dump_without_sod(td1: Path) -> None:
    r = dg.load_dump(td1)
    assert r.mrz.kind == "TD1"
    assert r.portrait_png.startswith(b"\x89PNG")
    assert not r.sod.available
    assert "not dumped" in r.sod.message
    # EF_COM announces DG3 which was not dumped: reported as protected.
    assert r.file("EF_DG3").state == FileState.PROTECTED


def test_empty_directory_yields_a_warning(tmp_path: Path) -> None:
    """A read that dumped nothing used to surface as a DG1 problem.

    Every file is missing when the directory is empty; DG1 was just the first
    one checked, so "EF_DG1 is missing - no MRZ to render" sent you looking at
    the wrong file instead of at the read that produced nothing.
    """
    r = dg.load_dump(tmp_path)
    assert r.mrz is None
    assert r.is_empty
    assert any("no files" in w.lower() for w in r.warnings)
    assert not any("EF_DG1" in w for w in r.warnings)


def test_uppercase_bin_suffix_is_accepted(tmp_path: Path, td3: Path) -> None:
    (tmp_path / "EF_DG1.BIN").write_bytes((td3 / "EF_DG1.bin").read_bytes())
    r = dg.load_dump(tmp_path)
    assert r.mrz is not None and r.surname == "ERIKSSON"


# --------------------------------------------- optional data groups absent
def test_missing_dg11_dg12_are_reported_as_not_on_chip(
    tmp_path: Path, td3: Path
) -> None:
    """Plenty of real passports carry no DG11/DG12 at all.

    The page must say so rather than showing an empty field, which reads as
    "the app failed to parse it".
    """
    for name in ("EF_COM", "EF_DG1", "EF_DG2"):
        (tmp_path / f"{name}.bin").write_bytes((td3 / f"{name}.bin").read_bytes())
    r = dg.load_dump(tmp_path)
    assert not r.has_dg(11) and not r.has_dg(12)
    assert r.place_of_birth == r.NOT_ON_CHIP
    assert r.date_of_issue == r.NOT_ON_CHIP
    assert r.issuing_authority == r.NOT_ON_CHIP
    assert r.is_missing(r.place_of_birth)


def test_personal_number_falls_back_to_the_mrz_optional_field(
    tmp_path: Path, td3: Path
) -> None:
    """Sweden and others put the national number in MRZ optional data."""
    for name in ("EF_COM", "EF_DG1", "EF_DG2"):
        (tmp_path / f"{name}.bin").write_bytes((td3 / f"{name}.bin").read_bytes())
    r = dg.load_dump(tmp_path)
    assert r.personal_number == "ZE184226B"  # the specimen's optional data
    assert r.personal_number_source == "MRZ"
    assert not r.is_missing(r.personal_number)


def test_dg11_personal_number_wins_over_the_mrz(record) -> None:
    assert record.personal_number == "19740812-1234"
    assert record.personal_number_source == "DG11"


def test_present_optional_groups_are_not_marked_missing(record) -> None:
    for value in (
        record.place_of_birth,
        record.date_of_issue,
        record.issuing_authority,
    ):
        assert not record.is_missing(value)


def test_image_for_returns_the_decoded_picture(record) -> None:
    """The FILES tab shows a picture for the files that carry one."""
    assert record.image_for("EF_DG2").startswith(b"\x89PNG")
    assert record.image_for("EF_DG7").startswith(b"\x89PNG")


def test_image_for_is_case_insensitive_like_file_lookup(record) -> None:
    assert record.image_for("ef_dg2") == record.image_for("EF_DG2")


def test_image_for_is_empty_for_files_that_carry_no_picture(record) -> None:
    assert record.image_for("EF_COM") == b""
    assert record.image_for("EF_SOD") == b""
    assert record.image_for("nonsense") == b""


def test_a_dump_with_files_is_not_empty(record) -> None:
    assert not record.is_empty


def test_a_dump_missing_only_dg1_still_names_dg1(tmp_path: Path, td3: Path) -> None:
    import shutil

    shutil.copy(td3 / "EF_COM.bin", tmp_path / "EF_COM.bin")
    r = dg.load_dump(tmp_path)
    assert not r.is_empty
    assert any("EF_DG1 is missing" in w for w in r.warnings)
