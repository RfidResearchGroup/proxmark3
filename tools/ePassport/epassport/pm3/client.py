"""Drive the pm3 client in one-shot command mode, from a worker thread.

The client is never invoked through a shell: the whole ``-c`` command string
is one argv element and every MRZ-derived value is validated against
``[0-9A-Z<]`` before it is allowed anywhere near it.
"""

from __future__ import annotations

import os
import re
import shutil
import signal
import subprocess
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterable, Sequence

from ..config import DUMP_LOG_NAME as LOG_NAME
from . import errors

#: Matches every ANSI CSI/OSC escape the client emits for colour.
ANSI_RE = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~]|\][^\x07]*(?:\x07|\x1B\\))")

#: The only characters ICAO allows in an MRZ.  Everything else is rejected
#: before it reaches the command string.
MRZ_SAFE = re.compile(r"^[0-9A-Z<]+$")

#: The Card Access Number is printed on the document and is always numeric.
#: The client accepts 1-14 digits and warns when it is not the usual 6.
CAN_SAFE = re.compile(r"^[0-9]{1,14}$")
CAN_USUAL_LENGTH = 6

#: How the chip should be unlocked.  ``auto`` lets the client try PACE and
#: fall back to BAC, which is what you want unless you are testing.
AUTH_AUTO = "auto"
AUTH_PACE = "pace"
AUTH_BAC = "bac"


def validate_can(value: str) -> str:
    """Normalise a Card Access Number, or raise :class:`ValidationError`."""
    digits = value.strip()
    if not digits:
        raise ValidationError("CAN is empty")
    if not CAN_SAFE.match(digits):
        raise ValidationError("CAN must be 1-14 digits, numbers only")
    return digits


#: pm3 prints one of these per data group while dumping.
_PROGRESS_RE = re.compile(
    r"(?:Read|Dumping|Saved)\s+(?:file\s+)?(EF_[A-Za-z0-9_]+)", re.I
)
_SAVED_RE = re.compile(r"saved to\s+(.+?)\s*$", re.I)


def strip_ansi(text: str) -> str:
    return ANSI_RE.sub("", text)


class ValidationError(ValueError):
    """Raised for input that must never reach the pm3 command string."""


def validate_mrz_field(value: str, *, name: str, maxlen: int | None = None) -> str:
    up = value.strip().upper()
    if not up:
        raise ValidationError(f"{name} is empty")
    if not MRZ_SAFE.match(up):
        raise ValidationError(f"{name} may only contain 0-9, A-Z and '<'")
    if maxlen is not None and len(up) > maxlen:
        raise ValidationError(f"{name} must be at most {maxlen} characters")
    return up


def validate_date(value: str, *, name: str) -> str:
    digits = value.strip()
    if not re.fullmatch(r"\d{6}", digits):
        raise ValidationError(f"{name} must be exactly 6 digits, YYMMDD")
    month, day = int(digits[2:4]), int(digits[4:6])
    if not 1 <= month <= 12:
        raise ValidationError(f"{name}: month {month:02d} is not 01-12")
    if not 1 <= day <= 31:
        raise ValidationError(f"{name}: day {day:02d} is not a valid day")
    return digits


@dataclass
class BacInput:
    """The key material for the chip.

    Either the MRZ (as the ``-n``/``-d``/``-e`` triple or a full line 2) or a
    Card Access Number.  The two are mutually exclusive as PACE passwords, and
    BAC can only ever use the MRZ.  The pm3 client enforces the same rules;
    checking here just turns a failed run into a sentence.
    """

    document_number: str = ""
    date_of_birth: str = ""
    date_of_expiry: str = ""
    mrz_line2: str = ""
    can: str = ""
    mode: str = AUTH_AUTO

    @property
    def has_mrz(self) -> bool:
        return bool(
            self.mrz_line2.strip()
            or (
                self.document_number.strip()
                and self.date_of_birth.strip()
                and self.date_of_expiry.strip()
            )
        )

    @property
    def has_can(self) -> bool:
        return bool(self.can.strip())

    @property
    def mechanism(self) -> str:
        """What this input will attempt, for the status bar."""
        if self.mode == AUTH_BAC:
            return "BAC"
        if self.has_can:
            return "PACE (CAN)"
        if self.mode == AUTH_PACE:
            return "PACE (MRZ)"
        return "PACE/BAC (MRZ)"

    def warnings(self) -> list[str]:
        """Non-fatal notes to show before a read."""
        if self.can and len(self.can) != CAN_USUAL_LENGTH:
            return [
                f"The CAN is usually {CAN_USUAL_LENGTH} digits; yours is "
                f"{len(self.can)}. Trying it anyway."
            ]
        return []

    def validated(self) -> "BacInput":
        """Return a normalised copy, or raise :class:`ValidationError`."""
        if self.mode not in (AUTH_AUTO, AUTH_PACE, AUTH_BAC):
            raise ValidationError(f"unknown authentication mode {self.mode!r}")
        if self.has_can and self.has_mrz:
            raise ValidationError(
                "the CAN and the MRZ are mutually exclusive - supply one or the other"
            )
        if self.mode == AUTH_BAC and self.has_can and not self.has_mrz:
            raise ValidationError("BAC needs MRZ data; the CAN is a PACE-only password")
        if self.mode == AUTH_PACE and not (self.has_can or self.has_mrz):
            raise ValidationError("PACE needs a password: supply a CAN, or the MRZ")
        if self.has_can:
            return BacInput(can=validate_can(self.can), mode=self.mode)
        if self.mrz_line2.strip():
            line = validate_mrz_field(self.mrz_line2, name="MRZ line 2")
            if len(line) not in (36, 44):
                raise ValidationError(
                    "MRZ line 2 must be 44 characters (TD3) or 36 (TD2)"
                )
            return BacInput(mrz_line2=line, mode=self.mode)
        # All three or none - a partial triple silently drops pm3 to no-BAC mode.
        missing = [
            name
            for name, value in (
                ("document number", self.document_number),
                ("date of birth", self.date_of_birth),
                ("date of expiry", self.date_of_expiry),
            )
            if not value.strip()
        ]
        if missing:
            raise ValidationError("missing " + ", ".join(missing))
        return BacInput(
            document_number=validate_mrz_field(
                self.document_number, name="document number", maxlen=9
            ),
            date_of_birth=validate_date(self.date_of_birth, name="date of birth"),
            date_of_expiry=validate_date(self.date_of_expiry, name="date of expiry"),
            mode=self.mode,
        )

    def args(self) -> list[str]:
        """The pm3 argument fragment for this key material."""
        if self.can:
            out = ["--can", self.can]
        elif self.mrz_line2:
            out = ["-m", self.mrz_line2]
        else:
            out = [
                "-n",
                self.document_number,
                "-d",
                self.date_of_birth,
                "-e",
                self.date_of_expiry,
            ]
        if self.mode == AUTH_PACE:
            out.append("--pace")
        elif self.mode == AUTH_BAC:
            out.append("--bac")
        return out

    def is_empty(self) -> bool:
        return not (self.has_mrz or self.has_can)


@dataclass
class Pm3Result:
    """Outcome of one pm3 invocation."""

    command: str
    argv: list[str]
    returncode: int | None
    lines: list[str] = field(default_factory=list)
    error: errors.Pm3Error | None = None
    duration: float = 0.0
    dump_dir: Path | None = None
    log_path: Path | None = None

    @property
    def ok(self) -> bool:
        return self.error is None and self.returncode == 0

    @property
    def text(self) -> str:
        return "\n".join(self.lines)


#: The arguments that carry key material: MRZ line, document number, dates, CAN.
_KEY_MATERIAL = re.compile(r"(?<![\w-])(--can|-[mnde])(\s+)(\S+)")


def redact(text: str) -> str:
    """Blank the key material out of a command line.

    The client echoes its own command line back, so scrubbing what we write is
    not enough on its own - every line has to go through this.
    """
    return _KEY_MATERIAL.sub(lambda m: f"{m.group(1)}{m.group(2)}<redacted>", text)


def write_log(result: "Pm3Result") -> Path | None:
    """Write the client output into the dump directory.  Returns the path.

    A failed read leaves this where it used to leave an empty directory, so the
    MRZ, document number and CAN are redacted: they would otherwise be a
    plaintext copy of the holder's details written out as a side effect.
    """
    directory = result.dump_dir
    if directory is None:
        return None
    directory = Path(directory)
    header = (
        f"# pm3 {redact(result.command)}"
        f", exit {result.returncode}, {result.duration:.1f}s"
    )
    body = "\n".join(redact(line) for line in result.lines)
    try:
        directory.mkdir(parents=True, exist_ok=True)
        path = directory / LOG_NAME
        path.write_text(f"{header}\n{body}\n", encoding="utf-8")
    except OSError:
        return None
    return path


def find_pm3_binary(configured: str | os.PathLike[str] | None = None) -> Path | None:
    """$PM3_BIN -> configured path -> PATH -> ~/pm3/pm3 -> repo-relative ./pm3."""
    candidates: list[Path] = []
    env = os.environ.get("PM3_BIN")
    if env:
        candidates.append(Path(env).expanduser())
    if configured:
        candidates.append(Path(configured).expanduser())
    which = shutil.which("pm3")
    if which:
        candidates.append(Path(which))
    candidates.append(Path.home() / "pm3" / "pm3")
    # Developing inside a proxmark3 tree: walk up looking for its ./pm3 wrapper.
    for parent in Path(__file__).resolve().parents:
        wrapper = parent / "pm3"
        if wrapper.is_file() and (parent / "client").is_dir():
            candidates.append(wrapper)
            break
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    return None


class Pm3Client:
    """Runs ``pm3 -c "<command>"`` and streams its output line by line.

    Call :meth:`run` from a worker thread - it blocks.  ``on_line`` is invoked
    for every stripped output line as it arrives, ``on_progress`` with
    ``(done, total, label)`` whenever a data group is read.
    """

    def __init__(
        self,
        binary: str | os.PathLike[str] | None = None,
        *,
        timeout: float = 120.0,
        dry_run_log: str | os.PathLike[str] | None = None,
    ) -> None:
        self.binary = find_pm3_binary(binary)
        self.timeout = timeout
        self.dry_run_log = Path(dry_run_log) if dry_run_log else None
        self._process: subprocess.Popen[str] | None = None
        self._lock = threading.Lock()
        self._cancelled = threading.Event()

    # -- command construction --------------------------------------------
    @staticmethod
    def build_command(
        subcommand: str,
        bac: BacInput | None,
        dump_dir: Path | None,
        extra: Sequence[str] = (),
    ) -> str:
        """Build the single ``-c`` string.  Never interpolates raw user input."""
        parts = ["hf", "emrtd", subcommand]
        if bac is not None and not bac.is_empty():
            parts += bac.validated().args()
        if dump_dir is not None:
            parts += ["--dir", str(dump_dir)]
        parts += list(extra)
        return " ".join(parts)

    def argv_for(self, command: str) -> list[str]:
        if self.binary is None:
            raise errors.Pm3NotFound()
        if not os.access(self.binary, os.X_OK):
            raise errors.Pm3NotExecutable(detail=str(self.binary))
        return [str(self.binary), "-c", command]

    # -- execution --------------------------------------------------------
    def run(
        self,
        command: str,
        *,
        on_line: Callable[[str], None] | None = None,
        on_progress: Callable[[int, int, str], None] | None = None,
        dump_dir: Path | None = None,
        expected_files: int = 0,
    ) -> Pm3Result:
        """Run one pm3 command to completion.  Blocks; never raises for a
        pm3-level failure - the failure lands in ``result.error``."""
        self._cancelled.clear()
        started = time.monotonic()

        if self.dry_run_log is not None:
            return self._replay(command, on_line, on_progress, dump_dir, started)

        try:
            argv = self.argv_for(command)
        except errors.Pm3Error as exc:
            return Pm3Result(command=command, argv=[], returncode=None, error=exc)

        lines: list[str] = []
        seen_files: set[str] = set()

        def emit(raw: str) -> None:
            line = strip_ansi(raw.rstrip("\n"))
            lines.append(line)
            if on_line is not None:
                on_line(line)
            match = _PROGRESS_RE.search(line)
            if match and on_progress is not None:
                name = match.group(1)
                if name not in seen_files:
                    seen_files.add(name)
                    on_progress(len(seen_files), expected_files, name)

        try:
            process = subprocess.Popen(
                argv,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                start_new_session=True,  # own process group, so cancel kills children
                cwd=str(self.binary.parent) if self.binary else None,
            )
        except OSError as exc:
            return Pm3Result(
                command=command,
                argv=argv,
                returncode=None,
                error=errors.Pm3NotFound(detail=str(exc)),
            )

        with self._lock:
            self._process = process

        timed_out = False
        deadline = started + self.timeout
        try:
            assert process.stdout is not None
            for raw in process.stdout:
                emit(raw)
                if self._cancelled.is_set():
                    break
                if time.monotonic() > deadline:
                    timed_out = True
                    break
            if timed_out or self._cancelled.is_set():
                self._terminate(process)
            returncode = process.wait(timeout=10)
        except Exception as exc:  # pragma: no cover - defensive
            self._terminate(process)
            returncode = process.poll()
            lines.append(f"[ePassport] {exc.__class__.__name__}: {exc}")
        finally:
            with self._lock:
                self._process = None

        result = Pm3Result(
            command=command,
            argv=argv,
            returncode=returncode,
            lines=lines,
            duration=time.monotonic() - started,
            dump_dir=dump_dir,
        )
        if self._cancelled.is_set():
            result.error = errors.CancelledError()
        elif timed_out:
            result.error = errors.TimeoutError_(
                detail=f"no completion within {self.timeout:.0f} s"
            )
        else:
            result.error = errors.classify(lines)
        # Keyed on the directory, not the command: run() is handed the whole
        # built command line, so matching a bare subcommand never fires.
        if dump_dir is not None:
            result.log_path = write_log(result)
        return result

    # -- cancellation -----------------------------------------------------
    def cancel(self) -> None:
        """Ask the running command to stop.  Safe to call from the UI thread."""
        self._cancelled.set()
        with self._lock:
            process = self._process
        if process is not None:
            self._terminate(process)

    @property
    def running(self) -> bool:
        with self._lock:
            return self._process is not None

    @staticmethod
    def _terminate(process: subprocess.Popen[str]) -> None:
        """SIGTERM the whole process group, SIGKILL it 3 s later."""
        if process.poll() is not None:
            return
        try:
            os.killpg(os.getpgid(process.pid), signal.SIGTERM)
        except (ProcessLookupError, PermissionError, OSError):
            try:
                process.terminate()
            except OSError:
                return
        try:
            process.wait(timeout=3)
            return
        except subprocess.TimeoutExpired:
            pass
        try:
            os.killpg(os.getpgid(process.pid), signal.SIGKILL)
        except (ProcessLookupError, PermissionError, OSError):
            try:
                process.kill()
            except OSError:
                pass

    # -- dry run ----------------------------------------------------------
    def _replay(
        self,
        command: str,
        on_line: Callable[[str], None] | None,
        on_progress: Callable[[int, int, str], None] | None,
        dump_dir: Path | None,
        started: float,
    ) -> Pm3Result:
        """Replay a recorded pm3 log so the whole app works with no hardware."""
        try:
            raw = self.dry_run_log.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            return Pm3Result(
                command=command,
                argv=[],
                returncode=None,
                error=errors.Pm3Error(str(exc)),
            )
        lines: list[str] = []
        seen: set[str] = set()
        for raw_line in raw.splitlines():
            if self._cancelled.is_set():
                return Pm3Result(
                    command=command,
                    argv=[],
                    returncode=None,
                    lines=lines,
                    error=errors.CancelledError(),
                )
            line = strip_ansi(raw_line)
            lines.append(line)
            if on_line is not None:
                on_line(line)
            match = _PROGRESS_RE.search(line)
            if match and on_progress is not None:
                name = match.group(1)
                if name not in seen:
                    seen.add(name)
                    on_progress(len(seen), 0, name)
            time.sleep(0.01)  # worker thread only - keeps the log pane readable
        return Pm3Result(
            command=command,
            argv=["<dry-run>", str(self.dry_run_log)],
            returncode=0,
            lines=lines,
            error=errors.classify(lines),
            duration=time.monotonic() - started,
            dump_dir=dump_dir,
        )


def count_expected_files(lines: Iterable[str]) -> int:
    """How many data groups EF_COM announced, for a determinate progress bar."""
    for line in lines:
        match = re.search(r"announced.*?(\[[^\]]*\])", line)
        if match:
            return len([p for p in match.group(1).strip("[]").split(",") if p.strip()])
    return 0
