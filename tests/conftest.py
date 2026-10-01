"""Test suite for the sfrbox_api package."""

from collections.abc import AsyncGenerator

import pytest_asyncio
from aiointercept import aiointercept


@pytest_asyncio.fixture(autouse=True)
async def mocked_responses() -> AsyncGenerator[aiointercept]:
    """Fixture for mocking aiohttp responses."""
    async with aiointercept(mock_external_urls=True) as m:
        yield m
