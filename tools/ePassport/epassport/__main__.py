"""Support ``python3 -m epassport``.

The real entry point is the ``ePassport.py`` script in the project root; this
shim only exists so the module form keeps working.
"""

from __future__ import annotations

import sys

from .app import main

if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
