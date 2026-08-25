#!/usr/bin/env python3
"""ePassport - an ePassport (eMRTD) viewer for the Proxmark3.

Run this file directly; there is nothing to install:

    ./ePassport
    ./ePassport --dump ~/.local/share/ePassport/dumps/<stamp>
    ./ePassport --help

It works from any directory, and does not need to be on PYTHONPATH.
"""

from __future__ import annotations

import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

MISSING = """\
ePassport needs a dependency that is not installed here:

    {error}

Interpreter: {python}

Install the requirements into the environment you are running:

    {python} -m pip install -r {requirements}

If you keep the dependencies in a virtualenv, activate it first, or run this
script with that interpreter directly:

    /path/to/venv/bin/python {script}
"""


def fail_missing(error: Exception) -> int:
    sys.stderr.write(
        MISSING.format(
            error=error,
            python=sys.executable,
            requirements=os.path.join(HERE, "requirements.txt"),
            script=os.path.abspath(__file__),
        )
    )
    return 1


def main() -> int:
    try:
        from epassport.app import main as run
    except ImportError as exc:
        return fail_missing(exc)
    return run(sys.argv[1:])


if __name__ == "__main__":
    raise SystemExit(main())
