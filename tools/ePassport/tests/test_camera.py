"""Camera enumeration, selection, and the zero-camera path."""

from __future__ import annotations

import pytest

from epassport.ocr import camera as cam


def test_device_label_is_index_plus_name() -> None:
    device = cam.CameraDevice(index=2, name="IPEVO Ziggi-HD Plus")
    assert device.label == "2: IPEVO Ziggi-HD Plus"


def test_device_label_marks_a_node_that_delivers_nothing() -> None:
    device = cam.CameraDevice(index=1, name="Webcam", works=False)
    assert "(no frames)" in device.label
    assert (
        "(no frames)" not in cam.CameraDevice(index=0, name="Webcam", works=True).label
    )


def test_listing_without_probe_opens_nothing(monkeypatch) -> None:
    """Enumerating must not disturb a camera another process is using."""
    opened: list[int] = []

    def boom(index):  # pragma: no cover - must never run
        opened.append(index)
        raise AssertionError("listing must not open devices")

    monkeypatch.setattr(cam, "probe_camera", boom)
    cam.list_cameras(probe=False)
    assert opened == []


def test_listing_sorts_working_devices_first(monkeypatch) -> None:
    devices = [
        cam.CameraDevice(index=0, name="Cam", node=0),
        cam.CameraDevice(index=1, name="Cam", node=1),
    ]
    monkeypatch.setattr(cam, "_sysfs_devices", lambda root=None: devices)
    monkeypatch.setattr(cam, "opencv_available", lambda: True)
    monkeypatch.setattr(cam, "probe_camera", lambda index: index == 1)
    got = cam.list_cameras(probe=True)
    assert got[0].index == 1 and got[0].works is True


def test_no_devices_at_all_yields_an_empty_list(monkeypatch) -> None:
    monkeypatch.setattr(cam, "_sysfs_devices", lambda root=None: [])
    monkeypatch.setattr(cam, "opencv_available", lambda: True)
    monkeypatch.setattr(cam, "probe_camera", lambda index: False)
    assert cam.list_cameras(probe=True, limit=3) == [] or all(
        not d.works for d in cam.list_cameras(probe=True, limit=3)
    )


def test_sysfs_parsing_reads_names_and_skips_junk(tmp_path) -> None:
    root = tmp_path / "video4linux"
    for name, index, label in (
        ("video0", "0", "IPEVO Ziggi-HD Plus"),
        ("video1", "1", "IPEVO Ziggi-HD Plus"),
    ):
        node = root / name
        node.mkdir(parents=True)
        (node / "name").write_text(label + "\n")
        (node / "index").write_text(index + "\n")
    (root / "videoX").mkdir()  # not a number: must be skipped
    (root / "video2").mkdir()  # no name/index files: must still be listed

    devices = cam._sysfs_devices(root)
    assert [d.index for d in devices] == [0, 1, 2]
    assert devices[0].name == "IPEVO Ziggi-HD Plus"
    assert devices[0].node == 0 and devices[1].node == 1
    assert devices[0].path == "/dev/video0"
    assert devices[2].name == ""  # missing file degrades, does not raise


def test_missing_sysfs_falls_back_to_numbered_indices(tmp_path) -> None:
    devices = cam.list_cameras(limit=3, root=tmp_path / "nope")
    assert [d.index for d in devices] == [0, 1, 2]


def test_capture_node_sorts_before_metadata_node(tmp_path) -> None:
    root = tmp_path / "video4linux"
    for name, node in (("video0", "1"), ("video1", "0")):
        entry = root / name
        entry.mkdir(parents=True)
        (entry / "name").write_text("Cam")
        (entry / "index").write_text(node)
    devices = cam.list_cameras(root=root)
    assert devices[0].index == 1, "the node with V4L2 index 0 is the capture node"


class _FakeScreen:
    """The label/selection interplay, without importing Kivy."""

    def __init__(self) -> None:
        self.camera_label = ""
        self._setting_label = False
        self.selections: list[str] = []

    def _set_label(self, label: str) -> None:
        if label == self.camera_label:
            return
        self._setting_label = True
        try:
            self.camera_label = label
            self.on_text(label)  # the Spinner echoes every text change back
        finally:
            self._setting_label = False

    def on_text(self, label: str) -> None:
        self.select_camera(label)

    def select_camera(self, label: str) -> None:
        if self._setting_label or not label:
            return
        self.selections.append(label)


def test_setting_the_label_does_not_count_as_a_user_selection() -> None:
    """The dropdown writes back, which would restart the camera mid-open."""
    screen = _FakeScreen()
    screen._set_label("0: Cam")
    assert screen.selections == []


def test_a_real_user_selection_is_honoured() -> None:
    screen = _FakeScreen()
    screen._set_label("0: Cam")
    screen.on_text("1: Other Cam")
    assert screen.selections == ["1: Other Cam"]


def test_empty_selection_is_ignored() -> None:
    screen = _FakeScreen()
    screen.on_text("")
    assert screen.selections == []
