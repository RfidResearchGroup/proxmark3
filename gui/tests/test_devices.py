import os
import tempfile
from pm3_gui import devices


def test_find_flash_script_with_local_tmp_script(tmp_path, monkeypatch):
    # Create a fake flash script in cwd
    fake = tmp_path / "pm3-flash"
    fake.write_text("#!/bin/sh\necho fake flash\n")
    fake.chmod(0o755)

    # Monkeypatch cwd to tmp_path so find_flash_script will find it
    monkeypatch.chdir(tmp_path)
    path = devices.find_flash_script()
    assert path is not None
    assert os.path.basename(path).startswith("pm3-flash")
