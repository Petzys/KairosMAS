# tests/conftest.py
from pathlib import Path

import pytest


@pytest.fixture
def banking_policy_path() -> Path:
    return Path(__file__).parent.parent / "kairos" / "config" / "banking-demo.yaml"