"""Paths, persisted settings and the app data directory.

Dumps contain live personal data, so the data directory is created 0700 and
nothing sensitive is written outside it.
"""

from __future__ import annotations

import datetime as dt
import json
import logging
import os
from dataclasses import asdict, dataclass, field
from pathlib import Path

log = logging.getLogger(__name__)

APP_NAME = "ePassport"

#: Directory names this app used to go by.  Dumps hold real personal data and
#: are not reproducible without the document in hand, so a rename must carry
#: them across rather than silently start a fresh, empty directory.
LEGACY_NAMES = ("pm3-passport",)

#: The client output kept beside a dump.  It is evidence about the read, not
#: a file off the chip, so it does not count towards a dump's contents.
DUMP_LOG_NAME = "pm3.log"


def _adopt_legacy(base: Path, name: str) -> Path:
    """Return ``base/name``, moving an older directory into place first."""
    path = base / name
    if path.exists():
        return path
    for legacy in LEGACY_NAMES:
        old = base / legacy
        if not old.is_dir():
            continue
        try:
            old.rename(path)
        except OSError as exc:
            log.warning("could not move %s to %s: %s", old, path, exc)
            return old  # keep using the old location rather than lose it
        log.info("moved %s to %s", old, path)
        return path
    return path


def data_dir() -> Path:
    """``$XDG_DATA_HOME/ePassport``, created 0700."""
    base = os.environ.get("XDG_DATA_HOME") or (Path.home() / ".local" / "share")
    path = _adopt_legacy(Path(base), APP_NAME)
    path.mkdir(parents=True, exist_ok=True)
    _harden(path)
    return path


def config_path() -> Path:
    base = os.environ.get("XDG_CONFIG_HOME") or (Path.home() / ".config")
    path = _adopt_legacy(Path(base), APP_NAME)
    path.mkdir(parents=True, exist_ok=True)
    _harden(path)
    return path / "settings.json"


def dumps_dir() -> Path:
    path = data_dir() / "dumps"
    path.mkdir(parents=True, exist_ok=True)
    _harden(path)
    return path


def new_dump_dir(now: dt.datetime | None = None) -> Path:
    """A fresh, app-managed directory named for the UTC timestamp."""
    stamp = (now or dt.datetime.now(dt.timezone.utc)).strftime("%Y%m%dT%H%M%SZ")
    path = dumps_dir() / stamp
    suffix = 1
    while path.exists():
        path = dumps_dir() / f"{stamp}-{suffix}"
        suffix += 1
    path.mkdir(parents=True)
    _harden(path)
    return path


@dataclass
class DumpEntry:
    """One dump directory, as listed in the Dumps browser."""

    path: Path
    modified: float = 0.0
    files: int = 0
    size: int = 0

    @property
    def name(self) -> str:
        return self.path.name

    @property
    def when(self) -> str:
        """The UTC stamp in the directory name, rendered readably."""
        stem = self.path.name
        try:
            moment = dt.datetime.strptime(stem[:16], "%Y%m%dT%H%M%SZ")
        except ValueError:
            return stem
        return moment.strftime("%Y-%m-%d %H:%M:%S UTC")

    @property
    def is_empty(self) -> bool:
        return self.files == 0

    @property
    def summary(self) -> str:
        if self.is_empty:
            return "empty - the read did not complete"
        return f"{self.files} files, {self.size / 1024:.1f} kB"


def list_dumps() -> list[DumpEntry]:
    """Every dump in the app's dumps directory, newest first."""
    root = dumps_dir()
    out: list[DumpEntry] = []
    for entry in root.iterdir():
        if not entry.is_dir():
            continue
        files = [f for f in entry.iterdir() if f.is_file() and f.name != DUMP_LOG_NAME]
        try:
            modified = entry.stat().st_mtime
        except OSError:
            modified = 0.0
        out.append(
            DumpEntry(
                path=entry,
                modified=modified,
                files=len(files),
                size=sum(f.stat().st_size for f in files if f.is_file()),
            )
        )
    # Sort by the UTC stamp in the name: several dumps created in the same
    # second share an mtime, and the resulting order looks arbitrary.  The
    # name is the read time and is unique by construction.
    return sorted(out, key=lambda d: (d.name, d.modified), reverse=True)


def prune_empty_dumps() -> int:
    """Remove dump directories left behind by reads that never produced a file."""
    removed = 0
    for entry in list_dumps():
        if entry.is_empty:
            try:
                # rmdir refuses a directory that still holds the log; drop that
                # first, and let anything unexpected keep the directory alive.
                (entry.path / DUMP_LOG_NAME).unlink(missing_ok=True)
                entry.path.rmdir()
                removed += 1
            except OSError as exc:
                log.debug("could not remove empty dump %s: %s", entry.path, exc)
    return removed


def _harden(path: Path) -> None:
    try:
        path.chmod(0o700)
    except OSError as exc:  # e.g. a mounted share that ignores modes
        log.debug("could not chmod 0700 %s: %s", path, exc)


def browse_start(last_dump: str = "") -> Path:
    """Where the folder picker should open.

    A dump you opened last time was picked *inside* some folder, so offer that
    folder again rather than the app's own dumps directory - otherwise every
    trip through the picker starts from scratch.
    """
    if last_dump:
        candidate = Path(last_dump).expanduser().resolve()
        if candidate.is_dir():
            if candidate.parent.is_dir():
                return candidate.parent
        elif candidate.parent.is_dir():
            return candidate.parent
    return dumps_dir()


def project_root() -> Path:
    """The directory holding the ``ePassport`` script and ``samples/``."""
    return Path(__file__).resolve().parent.parent


def samples_dir() -> Path | None:
    """The generated sample dumps, if they have been built.

    They are not checked in - ``tools_make_sample.py`` creates them - so this
    is None until someone runs it.
    """
    path = project_root() / "samples"
    return path if path.is_dir() else None


def assets_dir() -> Path:
    return Path(__file__).resolve().parent / "assets"


def font(name: str) -> str:
    """Path to a bundled font, falling back to Kivy's default if absent."""
    candidate = assets_dir() / "fonts" / name
    return str(candidate) if candidate.is_file() else "Roboto"


@dataclass
class Settings:
    """Persisted user settings.  Deliberately holds no MRZ data by default."""

    pm3_binary: str = ""
    timeout_seconds: float = 120.0
    camera_index: int = 0
    dark_chrome: bool = False
    remember_bac: bool = False
    last_document_number: str = ""
    last_date_of_birth: str = ""
    last_date_of_expiry: str = ""
    last_dump_dir: str = ""
    tesseract_cmd: str = ""
    #: "fit" fills the window with whatever document is loaded; "true" puts
    #: every format on one millimetre scale, so MRZ print matches across them.
    page_scale_mode: str = "fit"
    #: Chosen so the content area comes out at the reference document's own
    #: 125:88 - otherwise a passport is letterboxed on first run, which reads
    #: as the app failing to use the window rather than as a shape mismatch.
    window_width: int = 1100
    window_height: int = 850
    warnings: list[str] = field(default_factory=list)

    # -- persistence ------------------------------------------------------
    @classmethod
    def load(cls, path: Path | None = None) -> "Settings":
        path = path or config_path()
        if not path.is_file():
            return cls()
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            log.warning("ignoring unreadable settings file %s: %s", path, exc)
            return cls()
        known = {f for f in cls.__dataclass_fields__}
        settings = cls(**{k: v for k, v in raw.items() if k in known})
        if not settings.remember_bac:
            settings.forget_bac()
        return settings

    def save(self, path: Path | None = None) -> None:
        path = path or config_path()
        data = asdict(self)
        if not self.remember_bac:
            for key in (
                "last_document_number",
                "last_date_of_birth",
                "last_date_of_expiry",
            ):
                data[key] = ""
        try:
            path.write_text(json.dumps(data, indent=2), encoding="utf-8")
            path.chmod(0o600)
        except OSError as exc:
            log.warning("could not save settings to %s: %s", path, exc)

    def forget_bac(self) -> None:
        self.last_document_number = ""
        self.last_date_of_birth = ""
        self.last_date_of_expiry = ""
