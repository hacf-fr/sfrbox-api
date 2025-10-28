"""Test suite for the sfrbox_api package."""

from collections.abc import Generator

import pytest
from aioresponses import aioresponses


@pytest.fixture(autouse=True)
def mocked_responses() -> Generator[aioresponses]:
    """Fixture for mocking aiohttp responses."""
    with aioresponses() as m:
        yield m
