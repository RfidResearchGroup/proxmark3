"""Shared fixtures.

The sample dumps are *generated*, never checked in: the repository should
carry no dumps, logs or images, and a fabricated passport is cheap to rebuild.
Generation costs a second or two (it signs a real EF_SOD), so it happens once
per test session.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


@pytest.fixture(scope="session")
def samples(tmp_path_factory) -> Path:
    """Every sample dump, built into a temporary directory."""
    import tools_make_sample

    return tools_make_sample.build_all(tmp_path_factory.mktemp("samples"))


@pytest.fixture(scope="session")
def td3(samples: Path) -> Path:
    """A TD3 passport with DG11/DG12 and a signed EF_SOD."""
    return samples / "td3_utopia"


@pytest.fixture(scope="session")
def td3_tampered(samples: Path) -> Path:
    """The same document with DG2 replaced after signing."""
    return samples / "td3_utopia_tampered"


@pytest.fixture(scope="session")
def td1(samples: Path) -> Path:
    """A TD1 identity card: no DG11/DG12, no EF_SOD."""
    return samples / "td1_utopia_idcard"
