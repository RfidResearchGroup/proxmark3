"""Typed pm3 failures, each carrying a plain-English remedy for the UI."""

from __future__ import annotations

import re
from dataclasses import dataclass


class Pm3Error(Exception):
    """Base class.  ``title`` and ``remedy`` are what the UI panel shows."""

    title = "Proxmark3 error"
    remedy = "See the log pane for the raw client output."

    def __init__(self, message: str = "", *, detail: str = "") -> None:
        super().__init__(message or self.title)
        self.detail = detail

    @property
    def message(self) -> str:
        return str(self)


class Pm3NotFound(Pm3Error):
    title = "pm3 client not found"
    remedy = (
        "Set the pm3 binary path in Settings, or put 'pm3' on your PATH.\n"
        "In a proxmark3 source tree the wrapper script is at ./pm3."
    )


class Pm3NotExecutable(Pm3Error):
    title = "pm3 client is not executable"
    remedy = "Run: chmod +x <path-to-pm3>"


class NoDeviceError(Pm3Error):
    title = "No Proxmark3 found"
    remedy = (
        "Plug the Proxmark3 in and check it enumerates (ls /dev/ttyACM*).\n"
        "If you are in the dialout group you may need to log out and back in."
    )


class PortBusyError(Pm3Error):
    title = "Proxmark3 port is busy"
    remedy = "Another pm3 session already owns the device - close it and try again."


class NoCardError(Pm3Error):
    title = "No passport in the field"
    remedy = (
        "Lay the passport flat on the antenna, data page down, and keep it still.\n"
        "Passport covers are shielded: open the book so the chip page is over the coil."
    )


class NothingReadError(Pm3Error):
    title = "The read produced no files"
    remedy = (
        "The client finished without reporting a failure, but wrote nothing.\n"
        "Check the log pane for what it actually said - a mismatched MRZ or CAN,\n"
        "or a chip that needs PACE the client could not negotiate, both land here."
    )


class CardLostError(Pm3Error):
    title = "Lost the card mid-transaction"
    remedy = "The chip left the field before the dump finished. Do not move the passport while it reads."


class NoApduResponseError(Pm3Error):
    title = "The chip stopped answering"
    remedy = (
        "A command got no reply, so the key was never tested - this is not an\n"
        "MRZ or a CAN problem, and no attempt was counted against the chip.\n"
        "Failing at the same step on every run points at the chip or the reader\n"
        "rather than at the passport having moved.  pm3.log in the dump\n"
        "directory has the exchange."
    )


class BacFailedError(Pm3Error):
    title = "BAC authentication failed"
    remedy = (
        "Check the MRZ digits. Both dates are YYMMDD, not DDMMYY:\n"
        "  date of birth  - the holder's, from MRZ line 2 positions 14-19\n"
        "  date of expiry - MRZ line 2 positions 22-27\n"
        "The document number must include its trailing '<' fillers only if you typed the full field."
    )


class PaceOnlyError(Pm3Error):
    title = "Document requires PACE"
    remedy = (
        "This chip refuses BAC and only speaks PACE.\n"
        "Supply the Card Access Number (CAN) printed on the document, or leave the\n"
        "mode on Automatic so the client tries PACE with the MRZ first."
    )


class CanWrongError(Pm3Error):
    title = "Wrong CAN"
    remedy = (
        "The document rejected that Card Access Number.\n"
        "The CAN is the short number printed on the data page - usually 6 digits,\n"
        "often next to the photo or in the machine-readable zone's margin.\n"
        "Careful: the chip counts wrong attempts and will block the password."
    )


class PaceFailedError(Pm3Error):
    title = "PACE authentication failed"
    remedy = (
        "The chip accepted the password but the PACE exchange did not complete.\n"
        "Keep the document still on the antenna and try again; if it persists,\n"
        "force BAC with the MRZ instead."
    )


class PaceAlgorithmError(Pm3Error):
    title = "PACE algorithm rejected"
    remedy = (
        "The document refused the PACE algorithm the client offered.\n"
        "Try the MRZ with BAC instead - this chip wants something 'hf emrtd'\n"
        "does not currently negotiate."
    )


class MissingBacInputError(Pm3Error):
    title = "Incomplete BAC input"
    remedy = "Document number, date of birth and date of expiry are all required, or a full 44-char MRZ line 2."


class TimeoutError_(Pm3Error):
    title = "pm3 timed out"
    remedy = "The client did not finish in time. Raise the timeout in Settings, or check the device."


class CancelledError(Pm3Error):
    title = "Cancelled"
    remedy = "The read was cancelled."


@dataclass(frozen=True)
class _Rule:
    pattern: re.Pattern[str]
    exc: type[Pm3Error]


#: Matched against every log line, in order.  Patterns are taken from the
#: strings the client and the pm3 wrapper actually print - see
#: client/src/cmdhfemrtd.c and the pm3 shell script.
RULES: tuple[_Rule, ...] = (
    _Rule(re.compile(r"Waiting for Proxmark3 to appear", re.I), NoDeviceError),
    _Rule(re.compile(r"No port found", re.I), NoDeviceError),
    _Rule(re.compile(r"insufficient privileges", re.I), NoDeviceError),
    _Rule(
        re.compile(
            r"(port .* busy|Resource temporarily unavailable|Device or resource busy)",
            re.I,
        ),
        PortBusyError,
    ),
    _Rule(re.compile(r"OFFLINE.*mode", re.I), NoDeviceError),
    # Ranked above the MRZ verdict: the client prints that line whenever
    # external authentication fails, so it also fires when the chip never
    # answered and the key was consequently never tested.
    _Rule(re.compile(r"APDU: no APDU response", re.I), NoApduResponseError),
    _Rule(re.compile(r"Did you supply the correct MRZ info", re.I), BacFailedError),
    _Rule(
        re.compile(r"Challenge failed, rnd_ifd does not match", re.I), BacFailedError
    ),
    _Rule(
        re.compile(r"enforces authentication, but you didn't supply MRZ data", re.I),
        MissingBacInputError,
    ),
    _Rule(re.compile(r"Couldn't get challenge", re.I), CardLostError),
    _Rule(re.compile(r"Couldn't reconnect to the document", re.I), CardLostError),
    # "Secure select rejected" is deliberately absent: the client selects each
    # file in turn, so an absent optional DG answers 6A82 during a good read.
    _Rule(re.compile(r"Secure select got no response", re.I), CardLostError),
    _Rule(
        re.compile(r"Secure select response failed the MAC check", re.I), CardLostError
    ),
    _Rule(re.compile(r"Couldn't select the MRTD application", re.I), NoCardError),
    _Rule(re.compile(r"Can't select card", re.I), NoCardError),
    _Rule(re.compile(r"No ISO14443-[AB] Card in field", re.I), NoCardError),
    _Rule(
        re.compile(r"(iso14443a card select failed|No known/supported 14a tag)", re.I),
        NoCardError,
    ),
    _Rule(re.compile(r"Failed to read EF_COM", re.I), CardLostError),
    _Rule(
        re.compile(r"Couldn't build the MRZ information string", re.I),
        MissingBacInputError,
    ),
    _Rule(
        re.compile(r"(Date of birth|Expiry) date format is incorrect", re.I),
        MissingBacInputError,
    ),
    # PACE, most specific first: a wrong password is actionable, the rest is not.
    _Rule(re.compile(r"PACE.*wrong password", re.I), CanWrongError),
    _Rule(re.compile(r"PACE: invalid CAN", re.I), CanWrongError),
    _Rule(re.compile(r"PACE: invalid MRZ data", re.I), BacFailedError),
    _Rule(
        re.compile(r"CAN (has to be numeric|length is incorrect)", re.I), CanWrongError
    ),
    _Rule(re.compile(r"PACE.*rejected the algorithm", re.I), PaceAlgorithmError),
    _Rule(re.compile(r"PACE.*offers no algorithm we can do", re.I), PaceAlgorithmError),
    _Rule(
        re.compile(r"PACE was forced.*no usable EF_CardAccess", re.I),
        PaceAlgorithmError,
    ),
    _Rule(
        re.compile(
            r"PACE: (mapped generator|shared secret).*"
            r"(not on the curve|point at infinity)",
            re.I,
        ),
        PaceFailedError,
    ),
    _Rule(
        re.compile(r"PACE.*(authentication token is wrong|echoed our ephemeral)", re.I),
        PaceFailedError,
    ),
    _Rule(
        re.compile(
            r"PACE: .*(failed|got no response|malformed|missing data object)", re.I
        ),
        PaceFailedError,
    ),
    _Rule(re.compile(r"PACE needs a password", re.I), MissingBacInputError),
    _Rule(re.compile(r"mutually exclusive", re.I), MissingBacInputError),
    _Rule(re.compile(r"BAC needs MRZ data", re.I), MissingBacInputError),
    _Rule(re.compile(r"PACE.*(only|required|not supported)", re.I), PaceOnlyError),
)


#: Lines that mean authentication succeeded, and by which mechanism.
SUCCESS_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"Authentication with PACE successful", re.I), "PACE"),
    (re.compile(r"Basic Access Control successful", re.I), "BAC"),
)


def detect_mechanism(lines: list[str]) -> str:
    """Which mechanism actually unlocked the chip, or "" if none did."""
    for pattern, name in SUCCESS_PATTERNS:
        for line in lines:
            if pattern.search(line):
                return name
    return ""


#: Failures that describe one authentication attempt.  The client tries PACE
#: and falls back to BAC, so a later success means the attempt was superseded
#: rather than fatal - reporting it would fail a dump that has every file.
_ATTEMPT_ERRORS = (
    BacFailedError,
    CanWrongError,
    MissingBacInputError,
    PaceAlgorithmError,
    PaceFailedError,
    PaceOnlyError,
)


def classify(lines: list[str]) -> Pm3Error | None:
    """Return the most specific failure implied by the collected log lines."""
    authenticated = bool(detect_mechanism(lines))
    for rule in RULES:
        if authenticated and rule.exc in _ATTEMPT_ERRORS:
            continue
        for line in lines:
            if rule.pattern.search(line):
                return rule.exc(detail=line.strip())
    return None
