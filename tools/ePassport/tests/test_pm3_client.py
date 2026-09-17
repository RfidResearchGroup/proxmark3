"""pm3 client: input validation, error classification, cancel, dry-run."""

from __future__ import annotations

import threading
import time
from pathlib import Path

import pytest

from epassport.pm3 import client, errors
from epassport.pm3.client import (
    BacInput,
    Pm3Client,
    Pm3Result,
    strip_ansi,
    validate_date,
    validate_mrz_field,
)

#: Recorded pm3 sessions, written to a temp directory by the ``logs`` fixture.
#: They live here rather than in ``samples/`` so the repository carries no
#: throwaway log files - ``--dry-run`` takes any log you have recorded.
RECORDED: dict[str, str] = {
    "dump_success.log": """\
[+] Using UART port /dev/ttyACM0
[usb] pm3 --> hf emrtd dump -n L898902C3 -d 740812 -e 120415 --dir /tmp/dump
[+] Selected eMRTD application
[=] Attempting Basic Access Control
[+] Basic Access Control successful
[=] Reading EF_COM
[+] Read EF_COM, 27 bytes
[=] Data groups present: [1, 2, 7, 11, 12, 14, 15]
[=] Reading EF_DG1
[+] Read EF_DG1, 93 bytes
[+] Saved to /tmp/dump/EF_DG1.bin
[=] Reading EF_DG2
[+] Read EF_DG2, 6678 bytes
[+] Saved to /tmp/dump/EF_DG2.bin
[=] Reading EF_DG7
[+] Read EF_DG7, 4439 bytes
[+] Saved to /tmp/dump/EF_DG7.bin
[=] Reading EF_DG11
[+] Read EF_DG11, 128 bytes
[+] Saved to /tmp/dump/EF_DG11.bin
[=] Reading EF_DG12
[+] Read EF_DG12, 53 bytes
[+] Saved to /tmp/dump/EF_DG12.bin
[=] Reading EF_DG14
[+] Read EF_DG14, 33 bytes
[+] Saved to /tmp/dump/EF_DG14.bin
[=] Reading EF_DG15
[+] Read EF_DG15, 165 bytes
[+] Saved to /tmp/dump/EF_DG15.bin
[=] Reading EF_SOD
[+] Read EF_SOD, 1678 bytes
[+] Saved to /tmp/dump/EF_SOD.bin
[+] Dump completed
""",
    "dump_bac_failed.log": """\
[+] Using UART port /dev/ttyACM0
[usb] pm3 --> hf emrtd dump -n L898902C3 -d 740813 -e 120415 --dir /tmp/dump
[+] Selected eMRTD application
[=] Attempting Basic Access Control
[!] Couldn't do external authentication. Did you supply the correct MRZ info?
""",
    "no_device.log": "[=] Waiting for Proxmark3 to appear...\n",
    "no_card.log": """\
[+] Using UART port /dev/ttyACM0
[usb] pm3 --> hf emrtd info -n L898902C3 -d 740812 -e 120415
[!] Couldn't select the MRTD application.
""",
    "dump_pace_can.log": """\
[+] Using UART port /dev/ttyACM0
[usb] pm3 --> hf emrtd dump --can 123456 --dir /tmp/dump
[+] Selected eMRTD application
[=] Trying PACE with the CAN
[+] Authentication with PACE successful ( ECDH, CAN )
[=] Reading EF_DG1
[+] Read EF_DG1, 93 bytes
[+] Saved to /tmp/dump/EF_DG1.bin
[+] Dump completed
""",
    "pace_wrong_can.log": """\
[+] Using UART port /dev/ttyACM0
[usb] pm3 --> hf emrtd dump --can 111111 --pace --dir /tmp/dump
[+] Selected eMRTD application
[=] Trying PACE with the CAN
[!] PACE: wrong password, 2 attempt(s) left before the password is blocked
""",
}


@pytest.fixture(scope="session")
def logs(tmp_path_factory) -> Path:
    directory = tmp_path_factory.mktemp("pm3-logs")
    for name, body in RECORDED.items():
        (directory / name).write_text(body, encoding="utf-8")
    return directory


# --------------------------------------------------------------- validation
@pytest.mark.parametrize(
    "bad",
    ["L898902C3; rm -rf /", "L8989 02C3", "L898902c3\n-x", "$(id)", "`id`", "a|b"],
)
def test_shell_metacharacters_are_rejected(bad: str) -> None:
    with pytest.raises(Exception):
        validate_mrz_field(bad, name="document number", maxlen=9)


def test_valid_document_number_is_uppercased() -> None:
    assert validate_mrz_field("l898902c3", name="doc", maxlen=9) == "L898902C3"
    assert validate_mrz_field("1234<<<<<", name="doc", maxlen=9) == "1234<<<<<"


def test_document_number_length_cap() -> None:
    with pytest.raises(Exception):
        validate_mrz_field("1234567890", name="doc", maxlen=9)


@pytest.mark.parametrize(
    "bad", ["7408122", "74081", "741332", "740800", "abcdef", "74-08-12", ""]
)
def test_bad_dates_rejected(bad: str) -> None:
    with pytest.raises(Exception):
        validate_date(bad, name="dob")


def test_good_dates_accepted() -> None:
    assert validate_date("740812", name="dob") == "740812"
    assert validate_date("001231", name="dob") == "001231"


def test_partial_triple_is_refused_not_silently_dropped() -> None:
    with pytest.raises(Exception) as info:
        BacInput("L898902C3", "740812", "").validated()
    assert "date of expiry" in str(info.value)


def test_mrz_line2_takes_precedence_and_must_be_the_right_length() -> None:
    line = "L898902C36UTO7408122F1204159ZE184226B<<<<<10"
    got = BacInput(document_number="IGNORED", mrz_line2=line).validated()
    assert got.args() == ["-m", line]
    with pytest.raises(Exception):
        BacInput(mrz_line2="TOOSHORT").validated()


# ------------------------------------------------------------ command build
def test_build_command_is_one_string_with_all_three_bac_fields() -> None:
    cmd = Pm3Client.build_command(
        "dump", BacInput("L898902C3", "740812", "120415"), Path("/tmp/d")
    )
    assert cmd == "hf emrtd dump -n L898902C3 -d 740812 -e 120415 --dir /tmp/d"


def test_build_command_offline_info_takes_only_a_dir() -> None:
    assert (
        Pm3Client.build_command("info", None, Path("/tmp/d"))
        == "hf emrtd info --dir /tmp/d"
    )


def test_argv_passes_the_command_as_a_single_element(tmp_path: Path) -> None:
    fake = tmp_path / "pm3"
    fake.write_text("#!/bin/sh\n")
    fake.chmod(0o755)
    client = Pm3Client(fake)
    argv = client.argv_for("hf emrtd info -n X -d 740812 -e 120415")
    assert argv[1] == "-c"
    assert len(argv) == 3
    assert " " in argv[2]


def test_missing_binary_yields_a_typed_error(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("PM3_BIN", raising=False)
    monkeypatch.setattr("epassport.pm3.client.find_pm3_binary", lambda _=None: None)
    client = Pm3Client()
    client.binary = None
    result = client.run("hf emrtd info")
    assert isinstance(result.error, errors.Pm3NotFound)
    assert "PATH" in result.error.remedy


# ----------------------------------------------------------- classification
def test_ansi_is_stripped() -> None:
    assert strip_ansi("\x1b[32m[+]\x1b[0m ok") == "[+] ok"


@pytest.mark.parametrize(
    "log,expected",
    [
        ("no_device.log", errors.NoDeviceError),
        ("no_card.log", errors.NoCardError),
        ("dump_bac_failed.log", errors.BacFailedError),
    ],
)
def test_recorded_logs_classify(log: str, expected: type, logs: Path) -> None:
    lines = (logs / log).read_text().splitlines()
    err = errors.classify(lines)
    assert isinstance(err, expected)
    assert err.remedy


def test_successful_log_classifies_as_no_error(logs: Path) -> None:
    assert errors.classify((logs / "dump_success.log").read_text().splitlines()) is None


def test_bac_remedy_mentions_the_date_format() -> None:
    assert "YYMMDD" in errors.BacFailedError().remedy


# ------------------------------------------------------------------ dry run
def test_dry_run_replays_a_log_and_reports_progress(logs: Path) -> None:
    client = Pm3Client(dry_run_log=logs / "dump_success.log")
    seen: list[str] = []
    progress: list[str] = []
    result = client.run(
        "hf emrtd dump",
        on_line=seen.append,
        on_progress=lambda done, total, name: progress.append(name),
    )
    assert result.ok
    assert result.returncode == 0
    assert any("Basic Access Control successful" in line for line in seen)
    assert "EF_DG1" in progress and "EF_SOD" in progress
    assert len(progress) == len(set(progress))  # each file counted once


def test_dry_run_of_a_failed_log_surfaces_the_typed_error(logs: Path) -> None:
    client = Pm3Client(dry_run_log=logs / "dump_bac_failed.log")
    result = client.run("hf emrtd dump")
    assert isinstance(result.error, errors.BacFailedError)
    assert not result.ok


def test_cancel_stops_a_dry_run_promptly(logs: Path) -> None:
    client = Pm3Client(dry_run_log=logs / "dump_success.log")
    holder: list[Pm3Result] = []

    def work() -> None:
        holder.append(client.run("hf emrtd dump"))

    thread = threading.Thread(target=work)
    thread.start()
    time.sleep(0.05)
    client.cancel()
    thread.join(timeout=5)
    assert not thread.is_alive()
    assert isinstance(holder[0].error, errors.CancelledError)


# --------------------------------------------------------- real subprocess
def test_cancel_kills_a_real_child_process(tmp_path: Path) -> None:
    fake = tmp_path / "pm3"
    fake.write_text('#!/bin/sh\necho "[=] starting"\nsleep 60\n')
    fake.chmod(0o755)
    client = Pm3Client(fake, timeout=30)
    holder: list[Pm3Result] = []
    thread = threading.Thread(target=lambda: holder.append(client.run("hf emrtd dump")))
    thread.start()
    for _ in range(100):
        if client.running:
            break
        time.sleep(0.02)
    client.cancel()
    thread.join(timeout=10)
    assert not thread.is_alive(), "cancel must not leave the app hanging"
    assert isinstance(holder[0].error, errors.CancelledError)
    assert not client.running


def test_timeout_terminates_the_process(tmp_path: Path) -> None:
    fake = tmp_path / "pm3"
    fake.write_text('#!/bin/sh\nwhile true; do echo "[=] tick"; sleep 0.05; done\n')
    fake.chmod(0o755)
    client = Pm3Client(fake, timeout=0.4)
    result = client.run("hf emrtd dump")
    assert isinstance(result.error, errors.TimeoutError_)
    assert not client.running


def test_non_executable_binary_is_reported(tmp_path: Path) -> None:
    fake = tmp_path / "pm3"
    fake.write_text("#!/bin/sh\n")
    fake.chmod(0o644)
    result = Pm3Client(fake).run("hf emrtd info")
    assert isinstance(result.error, errors.Pm3NotExecutable)
    assert "chmod" in result.error.remedy


# ------------------------------------------------------- PACE and the CAN
from epassport.pm3.client import (
    AUTH_AUTO,
    AUTH_BAC,
    AUTH_PACE,
    validate_can,
)  # noqa: E402


def test_can_must_be_digits() -> None:
    assert validate_can("123456") == "123456"
    for bad in ("12x456", "12 34", "", "1234567890abcd", "-1"):
        with pytest.raises(Exception):
            validate_can(bad)


def test_can_length_bounds() -> None:
    assert validate_can("1") == "1"
    assert len(validate_can("1" * 14)) == 14
    with pytest.raises(Exception):
        validate_can("1" * 15)


def test_can_builds_a_pace_command() -> None:
    cmd = Pm3Client.build_command("dump", BacInput(can="123456"), Path("/tmp/d"))
    assert cmd == "hf emrtd dump --can 123456 --dir /tmp/d"


def test_forcing_pace_and_bac_adds_the_right_flag() -> None:
    assert Pm3Client.build_command(
        "dump", BacInput(can="123456", mode=AUTH_PACE), None
    ).endswith("--pace")
    triple = BacInput("L898902C3", "740812", "120415", mode=AUTH_BAC)
    assert Pm3Client.build_command("dump", triple, None).endswith("--bac")
    assert not Pm3Client.build_command(
        "dump", triple.__class__(**{**vars(triple), "mode": AUTH_AUTO}), None
    ).endswith(("--bac", "--pace"))


def test_can_and_mrz_are_mutually_exclusive() -> None:
    with pytest.raises(Exception) as info:
        BacInput("L898902C3", "740812", "120415", can="123456").validated()
    assert "mutually exclusive" in str(info.value)


def test_bac_cannot_use_a_can() -> None:
    with pytest.raises(Exception) as info:
        BacInput(can="123456", mode=AUTH_BAC).validated()
    assert "PACE-only" in str(info.value)


def test_pace_needs_some_password() -> None:
    with pytest.raises(Exception) as info:
        BacInput(mode=AUTH_PACE).validated()
    assert "PACE needs a password" in str(info.value)


def test_unknown_mode_is_rejected() -> None:
    with pytest.raises(Exception):
        BacInput(can="123456", mode="telepathy").validated()


def test_unusual_can_length_warns_but_is_allowed() -> None:
    checked = BacInput(can="1234").validated()
    assert checked.args() == ["--can", "1234"]
    assert "usually 6 digits" in checked.warnings()[0]
    assert BacInput(can="123456").validated().warnings() == []


def test_mechanism_describes_what_will_be_attempted() -> None:
    assert BacInput(can="123456").mechanism == "PACE (CAN)"
    assert BacInput("L898902C3", "740812", "120415").mechanism == "PACE/BAC (MRZ)"
    assert BacInput("L898902C3", "740812", "120415", mode=AUTH_BAC).mechanism == "BAC"
    assert BacInput(can="123456", mode=AUTH_PACE).mechanism == "PACE (CAN)"


@pytest.mark.parametrize(
    "line,expected",
    [
        (
            "[!] PACE: wrong password, 2 attempt(s) left before the password is blocked",
            errors.CanWrongError,
        ),
        ("[!] PACE: invalid CAN", errors.CanWrongError),
        (
            "[!] PACE: the document rejected the algorithm we selected (6A80)",
            errors.PaceAlgorithmError,
        ),
        (
            "[!] PACE: the document's authentication token is wrong, aborting",
            errors.PaceFailedError,
        ),
        (
            "[!] BAC needs MRZ data, the CAN is a PACE only password.",
            errors.MissingBacInputError,
        ),
    ],
)
def test_pace_failures_classify(line: str, expected: type) -> None:
    err = errors.classify([line])
    assert isinstance(err, expected)
    assert err.remedy


def test_wrong_can_remedy_warns_about_blocking() -> None:
    assert "block" in errors.CanWrongError().remedy


def test_mechanism_is_detected_from_the_log() -> None:
    assert (
        errors.detect_mechanism(
            ["[+] Authentication with PACE successful ( ECDH, CAN )"]
        )
        == "PACE"
    )
    assert errors.detect_mechanism(["[+] Basic Access Control successful"]) == "BAC"
    assert errors.detect_mechanism(["[=] nothing happened"]) == ""


def test_a_recorded_pace_session_reports_success_and_its_mechanism(logs: Path) -> None:
    client = Pm3Client(dry_run_log=logs / "dump_pace_can.log")
    result = client.run("hf emrtd dump --can 123456")
    assert result.ok, result.error
    assert errors.detect_mechanism(result.lines) == "PACE"


def test_a_recorded_wrong_can_session_classifies_as_a_wrong_can(logs: Path) -> None:
    client = Pm3Client(dry_run_log=logs / "pace_wrong_can.log")
    result = client.run("hf emrtd dump --can 111111 --pace")
    assert isinstance(result.error, errors.CanWrongError)
    assert errors.detect_mechanism(result.lines) == ""


# ------------------------------------------------ keeping the client output
def test_a_dump_leaves_its_log_behind(tmp_path: Path) -> None:
    """A read that fails writes no files, so without this there is no evidence.

    An empty dump directory is all a failed read used to leave, which made it
    impossible to say afterwards why the chip gave up nothing.
    """
    result = Pm3Result(
        command="dump",
        argv=["pm3", "-c", "hf emrtd dump"],
        returncode=0,
        lines=["[=] Reading EF_COM", "[-] Failed"],
        dump_dir=tmp_path,
    )
    path = client.write_log(result)
    assert path == tmp_path / client.LOG_NAME
    written = path.read_text()
    assert "[-] Failed" in written
    assert "[=] Reading EF_COM" in written


MRZ_LINE2 = "FE21053688POL1003097M3312201<<<<<<<<<<<<<<04"


@pytest.mark.parametrize(
    "command",
    [
        f"hf emrtd dump -m {MRZ_LINE2} --dir /tmp/d",
        "hf emrtd dump -n L898902C3 -d 740812 -e 120415 --dir /tmp/d",
        "hf emrtd dump --can 123456 --dir /tmp/d",
    ],
)
def test_the_log_does_not_carry_the_key_material(tmp_path: Path, command: str) -> None:
    """A failed read leaves this behind where it used to leave nothing.

    ``command`` is the whole built command line and the client echoes it back
    in its own output, so the MRZ, the document number and the CAN all reach
    the log unless they are scrubbed out of both.
    """
    result = Pm3Result(
        command=command,
        argv=["pm3", "-c", command],
        returncode=0,
        lines=[f"[+] execute command from commandline: {command}"],
        dump_dir=tmp_path,
    )
    written = client.write_log(result).read_text()
    for secret in (MRZ_LINE2, "L898902C3", "740812", "120415", "123456"):
        assert secret not in written
    assert "--dir" in written  # the dump path is not a secret and stays


def test_writing_a_log_without_a_dump_dir_is_a_no_op() -> None:
    result = Pm3Result(command="dump", argv=[], returncode=0, dump_dir=None)
    assert client.write_log(result) is None


@pytest.mark.parametrize(
    "line, expected",
    [
        ("[!] PACE: invalid MRZ data", errors.BacFailedError),
        (
            "[!] PACE: this document offers no algorithm we can do",
            errors.PaceAlgorithmError,
        ),
        (
            "[!] PACE was forced but this document has no usable EF_CardAccess.",
            errors.PaceAlgorithmError,
        ),
        ("[!] PACE: mapped generator is not on the curve", errors.PaceFailedError),
        ("[!] PACE: shared secret is the point at infinity", errors.PaceFailedError),
        ("[!] Couldn't reconnect to the document.", errors.CardLostError),
        ("[!] Secure select got no response", errors.CardLostError),
        ("[!] Secure select response failed the MAC check", errors.CardLostError),
        (
            "[!] Couldn't build the MRZ information string.",
            errors.MissingBacInputError,
        ),
        (
            "[!] Date of birth date format is incorrect, cannot continue.",
            errors.MissingBacInputError,
        ),
        (
            "[!] Expiry date format is incorrect, cannot continue.",
            errors.MissingBacInputError,
        ),
    ],
)
def test_fatal_client_messages_classify(line: str, expected: type) -> None:
    """Each of these ends in a return false in the client, and left no error.

    Unmatched, they surfaced as the generic "read produced no files" instead
    of saying which thing went wrong.
    """
    err = errors.classify([line])
    assert isinstance(err, expected)
    assert err.remedy


def test_an_absent_optional_file_is_not_a_failure() -> None:
    """The client selects each file in turn, so a missing one is answered 6A82.

    That is ordinary during a good read - classifying it would turn a working
    dump into an error.
    """
    lines = [
        "[=] Reading EF_COM",
        "[!] Secure select rejected by the document (6A82 - File not found)",
        "[!] Failed to secure select 0103",
        "[+] Read EF_DG1",
    ]
    assert errors.classify(lines) is None


# --------------------------------- a failed attempt that was recovered from
_FALLBACK = [
    "[=] Read EF_CardAccess, len 22",
    "[=] Trying PACE with the MRZ",
    "[!!] PACE: step 4 (mutual authentication) failed (6300), the document rejected it",
    "[=] PACE failed, falling back to BAC",
    "[+] Basic Access Control successful",
    "[+] Saved 93 bytes to binary file `EF_DG1.bin`",
]


def test_a_failed_pace_attempt_is_not_the_outcome_when_bac_gets_in() -> None:
    """Falling back to BAC is ordinary, and the read that follows works.

    Every line was matched on its own, so the superseded PACE failure was
    reported as the result: a dump with every file in it announced itself as
    "PACE authentication failed" and dropped the user on the log tab.
    """
    assert errors.detect_mechanism(_FALLBACK) == "BAC"
    assert errors.classify(_FALLBACK) is None


def test_a_failure_after_authentication_still_counts() -> None:
    """Only the authentication attempt is superseded, not what follows it."""
    lines = _FALLBACK + ["[!!] Couldn't reconnect to the document."]
    assert isinstance(errors.classify(lines), errors.CardLostError)


def test_both_mechanisms_failing_is_still_a_failure() -> None:
    """Nothing got in here, so the MRZ verdict stands."""
    lines = [
        "[=] Trying PACE with the MRZ",
        "[!!] PACE: step 4 (mutual authentication) failed (6300), the document rejected it",
        "[=] PACE failed, falling back to BAC",
        "[!!] Couldn't do external authentication. Did you supply the correct MRZ info?",
    ]
    assert errors.detect_mechanism(lines) == ""
    assert isinstance(errors.classify(lines), errors.BacFailedError)


def test_a_real_dump_run_leaves_its_log(tmp_path: Path) -> None:
    """Exercise run(), not write_log().

    run() received the whole built command - "hf emrtd dump -n ... --dir ..." -
    and was comparing it to the bare subcommand, so the log was never written
    for an actual read.  Calling write_log() directly in a test hid that.
    """
    fake = tmp_path / "pm3"
    fake.write_text('#!/bin/sh\necho "[=] Read EF_CardAccess, len 22"\n')
    fake.chmod(0o755)
    dump_dir = tmp_path / "dump"
    dump_dir.mkdir()

    client_under_test = Pm3Client(fake)
    command = Pm3Client.build_command("dump", None, dump_dir)
    result = client_under_test.run(command, dump_dir=dump_dir)

    assert result.log_path == dump_dir / client.LOG_NAME
    assert "Read EF_CardAccess" in result.log_path.read_text()


def test_a_card_that_stops_answering_is_not_an_mrz_problem() -> None:
    """The client blames the MRZ whenever external authentication fails.

    That line is printed regardless of why, so when the chip simply stopped
    responding it still asked whether the MRZ was right - sending you to check
    digits that were never tested.  No APDU came back at all here.
    """
    lines = [
        "[=] Read EF_CardAccess, len 22",
        "[=] Trying PACE with the MRZ",
        "[!!] APDU: no APDU response",
        "[!!] PACE: MSE:Set AT got no response",
        "[=] PACE failed, falling back to BAC",
        "[!!] APDU: no APDU response",
        "[!!] Couldn't do external authentication. Did you supply the correct MRZ info?",
    ]
    err = errors.classify(lines)
    assert isinstance(err, errors.NoApduResponseError)
    assert "not an\nMRZ" in err.remedy


def test_a_document_that_rejects_the_key_is_still_an_mrz_problem() -> None:
    """The chip answered and said no - there the MRZ verdict is the right one."""
    lines = [
        "[=] Trying PACE with the MRZ",
        "[!!] PACE: step 4 (mutual authentication) failed (6300), the document rejected it",
        "[=] PACE failed, falling back to BAC",
        "[!!] Couldn't do external authentication. Did you supply the correct MRZ info?",
    ]
    assert isinstance(errors.classify(lines), errors.BacFailedError)


@pytest.mark.parametrize(
    "line",
    ["[!] No ISO14443-A Card in field", "[!] No ISO14443-B Card in field"],
)
def test_no_card_in_field_says_so(line: str) -> None:
    """Both are printed when the poll finds nothing, A and B alike.

    Unmatched, a read that never saw the passport was reported as one that
    produced no files, which describes the outcome and not the cause.
    """
    assert isinstance(errors.classify([line]), errors.NoCardError)
