"""Test cases for the __main__ module."""

from sfrbox_api.helpers import compute_hash


def test_hash() -> None:
    """It matches expected hash."""
    result = compute_hash("afd1baa4cb261bfc08ec2dc0ade3b4", "admin", "password")
    assert len(result) == 64 * 2
    assert result == (
        "3e89f9170f9e64e5132aa6f72a520ffd45f952f259872a60e9acde5dba45ff64"
        "88cc72099f52b8414e5b182b8e1c2b4b87863bd67b0134904adfe00ae6c6499e"
    )
