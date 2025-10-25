"""Device detection and flash script helpers for pm3-gui."""
from typing import List, Tuple, Optional
import os
import shutil

def _repo_roots() -> List[str]:
    # Candidate locations for the proxmark3 repository root: cwd, and two levels up from this file
    roots = [os.getcwd()]
    this_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
    roots.append(this_dir)
    return roots


def find_flash_script(script_names: Optional[List[str]] = None) -> Optional[str]:
    """Find a flashing script (e.g., 'pm3-flash', 'pm3-flash-fullimage') in repo or PATH.

    Returns absolute path or None if not found.
    """
    if script_names is None:
        script_names = ["pm3-flash", "pm3-flash-fullimage", "pm3-flash-bootrom", "pm3-flash-all"]

    # Search repo candidate roots first
    for root in _repo_roots():
        for name in script_names:
            candidate = os.path.join(root, name)
            if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
                return candidate

    # Fallback to PATH
    for name in script_names:
        path = shutil.which(name)
        if path:
            return path

    return None


def list_serial_ports() -> List[Tuple[str, str]]:
    """Return a list of (device, description) tuples for candidate serial ports.

    Uses pyserial if available; otherwise scans common /dev patterns.
    """
    ports = []
    try:
        import serial.tools.list_ports as list_ports
        for p in list_ports.comports():
            ports.append((p.device, p.description))
        return ports
    except Exception:
        # Fallback: naive scan
        candidates = []
        for prefix in ("/dev/ttyACM", "/dev/ttyUSB", "/dev/ttyS", "/dev/cu."):
            for i in range(0, 16):
                p = f"{prefix}{i}"
                if os.path.exists(p):
                    candidates.append(p)
        for p in candidates:
            ports.append((p, "serial"))
        return ports
