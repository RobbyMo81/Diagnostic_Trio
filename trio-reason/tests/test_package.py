"""Smoke tests for the trio-reason package."""

import trio_reason


def test_version_is_string() -> None:
    assert isinstance(trio_reason.__version__, str)
    assert trio_reason.__version__ != ""
