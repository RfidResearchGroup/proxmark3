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


class CardLostError(Pm3Error):
    title = "Lost the card mid-transaction"
    remedy = "The chip left the field before the dump finished. Do not move the passport while it reads."


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
    _Rule(re.compile(r"Did you supply the correct MRZ info", re.I), BacFailedError),
    _Rule(
        re.compile(r"Challenge failed, rnd_ifd does not match", re.I), BacFailedError
    ),
    _Rule(
        re.compile(r"enforces authentication, but you didn't supply MRZ data", re.I),
        MissingBacInputError,
    ),
    _Rule(re.compile(r"Couldn't get challenge", re.I), CardLostError),
    _Rule(re.compile(r"Couldn't select the MRTD application", re.I), NoCardError),
    _Rule(re.compile(r"Can't select card", re.I), NoCardError),
    _Rule(
        re.compile(r"(iso14443a card select failed|No known/supported 14a tag)", re.I),
        NoCardError,
    ),
    _Rule(re.compile(r"Failed to read EF_COM", re.I), CardLostError),
    # PACE, most specific first: a wrong password is actionable, the rest is not.
    _Rule(re.compile(r"PACE.*wrong password", re.I), CanWrongError),
    _Rule(re.compile(r"PACE: invalid CAN", re.I), CanWrongError),
    _Rule(
        re.compile(r"CAN (has to be numeric|length is incorrect)", re.I), CanWrongError
    ),
    _Rule(re.compile(r"PACE.*rejected the algorithm", re.I), PaceAlgorithmError),
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


def classify(lines: list[str]) -> Pm3Error | None:
    """Return the most specific failure implied by the collected log lines."""
    for rule in RULES:
        for line in lines:
            if rule.pattern.search(line):
                return rule.exc(detail=line.strip())
    return None
