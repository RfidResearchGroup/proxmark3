"""Camera capture on a worker thread, frames handed to Kivy as textures.

``kivy.uix.camera.Camera`` is unreliable on Linux, so this drives
``cv2.VideoCapture`` directly and blits the frames itself.
"""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass
from typing import Callable

log = logging.getLogger(__name__)

#: How many /dev/videoN nodes to probe when the configured index fails.
PROBE_LIMIT = 6


def opencv_available() -> bool:
    try:
        import cv2  # noqa: F401
    except ImportError:
        return False
    return True


@dataclass
class Frame:
    """One captured frame: raw BGR array plus its dimensions."""

    array: object  # numpy.ndarray, kept untyped so numpy stays optional
    width: int
    height: int


class CameraThread:
    """Grabs frames in the background and calls ``on_frame`` with each one.

    ``on_frame`` runs on the capture thread - never touch Kivy widgets from
    it; schedule with ``Clock`` instead.
    """

    def __init__(
        self,
        index: int = 0,
        *,
        width: int = 1280,
        height: int = 720,
        fps: float = 30.0,
        on_frame: Callable[[Frame], None] | None = None,
        on_error: Callable[[str], None] | None = None,
    ) -> None:
        self.index = index
        self.width = width
        self.height = height
        self.interval = 1.0 / max(fps, 1.0)
        self.on_frame = on_frame
        self.on_error = on_error
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._capture = None
        self.last_error = ""

    # -- lifecycle ---------------------------------------------------------
    def start(self) -> bool:
        if self._thread is not None:
            return True
        if not opencv_available():
            self._fail(
                "OpenCV is not installed - run: pip install opencv-python-headless"
            )
            return False
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._run, name="ePassport-camera", daemon=True
        )
        self._thread.start()
        return True

    def stop(self) -> None:
        """Release the camera.  Safe to call twice, and from the UI thread."""
        self._stop.set()
        thread, self._thread = self._thread, None
        if thread is not None and thread.is_alive():
            thread.join(timeout=2.0)

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    # -- capture loop ------------------------------------------------------
    def _open(self, cv2, index: int):
        """Open one index, or return None.

        V4L2 exposes metadata-only nodes that open successfully but never
        deliver a frame, so a successful first read is the real test.
        """
        capture = cv2.VideoCapture(index)
        if not capture.isOpened():
            capture.release()
            return None
        capture.set(cv2.CAP_PROP_FRAME_WIDTH, self.width)
        capture.set(cv2.CAP_PROP_FRAME_HEIGHT, self.height)
        ok, frame = capture.read()
        if not ok or frame is None:
            capture.release()
            return None
        return capture

    def _run(self) -> None:
        import cv2

        # Many Linux systems expose several /dev/videoN for one physical
        # camera, only one of which actually delivers frames - so try the
        # neighbours rather than giving up on the configured index.
        tried: list[int] = []
        capture = None
        for index in [self.index] + [i for i in range(PROBE_LIMIT) if i != self.index]:
            tried.append(index)
            capture = self._open(cv2, index)
            if capture is not None:
                if index != self.index:
                    log.info(
                        "camera %d delivered no frames, using %d", self.index, index
                    )
                self.index = index
                break
        if capture is None:
            self._fail(
                "No working camera found (tried "
                + ", ".join(f"/dev/video{i}" for i in tried)
                + "). Check permissions, or set the index in Settings."
            )
            return
        self._capture = capture
        misses = 0
        try:
            while not self._stop.is_set():
                started = time.monotonic()
                ok, frame = capture.read()
                if not ok or frame is None:
                    misses += 1
                    if misses > 30:
                        self._fail("The camera stopped delivering frames.")
                        break
                    time.sleep(0.05)
                    continue
                misses = 0
                if self.on_frame is not None:
                    try:
                        self.on_frame(Frame(frame, frame.shape[1], frame.shape[0]))
                    except Exception:  # a bad consumer must not kill capture
                        log.exception("camera frame consumer raised")
                elapsed = time.monotonic() - started
                if elapsed < self.interval:
                    time.sleep(self.interval - elapsed)
        finally:
            capture.release()
            self._capture = None

    def _fail(self, message: str) -> None:
        self.last_error = message
        log.warning("camera: %s", message)
        if self.on_error is not None:
            self.on_error(message)


def frame_to_texture(frame: Frame):
    """Convert a BGR frame to a Kivy texture (RGB, right way up)."""
    import cv2
    from kivy.graphics.texture import Texture

    rgb = cv2.cvtColor(frame.array, cv2.COLOR_BGR2RGB)
    flipped = cv2.flip(rgb, 0)  # Kivy textures start at the bottom-left
    texture = Texture.create(size=(frame.width, frame.height), colorfmt="rgb")
    texture.blit_buffer(flipped.tobytes(), colorfmt="rgb", bufferfmt="ubyte")
    return texture


@dataclass
class CameraDevice:
    """One selectable capture device."""

    index: int
    name: str = ""
    path: str = ""
    #: V4L2 sub-index within the physical device.  0 is the capture node;
    #: higher numbers are usually metadata-only and deliver no frames.
    node: int = 0
    works: bool | None = None  # None = not probed yet

    @property
    def label(self) -> str:
        name = self.name or "camera"
        suffix = {True: "", False: "  (no frames)", None: ""}[self.works]
        return f"{self.index}: {name}{suffix}"


#: Where Linux advertises V4L2 devices, and their human-readable names.
V4L2_SYSFS = "/sys/class/video4linux"


def _sysfs_devices(root=None) -> list[CameraDevice]:
    """Enumerate V4L2 devices by name, without opening them."""
    from pathlib import Path as _Path

    root = _Path(root or V4L2_SYSFS)
    if not root.is_dir():
        return []
    devices: list[CameraDevice] = []
    for entry in sorted(root.glob("video*")):
        try:
            index = int(entry.name.removeprefix("video"))
        except ValueError:
            continue
        name = _read_text(entry / "name")
        node = _read_int(entry / "index", default=0)
        devices.append(
            CameraDevice(index=index, name=name, path=f"/dev/{entry.name}", node=node)
        )
    return devices


def _read_text(path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace").strip()
    except OSError:
        return ""


def _read_int(path, *, default: int) -> int:
    text = _read_text(path)
    try:
        return int(text)
    except ValueError:
        return default


def list_cameras(
    *, probe: bool = False, limit: int = PROBE_LIMIT, root=None
) -> list[CameraDevice]:
    """Every capture device we could offer the user.

    Enumeration is by name from sysfs where available, because opening a
    device to look at it is disruptive if something else is using it.  Pass
    ``probe=True`` to additionally check which ones deliver frames - that is
    slow, so do it on a worker thread.
    """
    devices = _sysfs_devices(root)
    if not devices:
        devices = [CameraDevice(index=i, name=f"camera {i}") for i in range(limit)]
    if probe and opencv_available():
        for device in devices:
            device.works = probe_camera(device.index)
        # A device that delivers frames sorts above one that does not.
        devices.sort(key=lambda d: (d.works is not True, d.node, d.index))
    else:
        devices.sort(key=lambda d: (d.node, d.index))
    return devices


def probe_camera(index: int) -> bool:
    """True when this index actually delivers a frame."""
    if not opencv_available():
        return False
    import cv2

    capture = cv2.VideoCapture(index)
    try:
        if not capture.isOpened():
            return False
        ok, frame = capture.read()
        return bool(ok and frame is not None)
    finally:
        capture.release()


def list_camera_indices(limit: int = PROBE_LIMIT) -> list[int]:
    """Indices that deliver frames.  Slow; call off the UI thread."""
    return [d.index for d in list_cameras(probe=True, limit=limit) if d.works]
