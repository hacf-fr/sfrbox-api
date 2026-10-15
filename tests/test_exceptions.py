"""Test cases for the exceptions module."""

import pytest

from sfrbox_api.exceptions import SFRBoxApiError
from sfrbox_api.exceptions import SFRBoxAuthenticationError
from sfrbox_api.exceptions import SFRBoxError


@pytest.mark.parametrize("exc_type", [SFRBoxApiError, SFRBoxAuthenticationError])
def test_subclass_of_base_error(exc_type: type[SFRBoxError]) -> None:
    """It can be caught as SFRBoxError."""
    with pytest.raises(SFRBoxError):
        raise exc_type("failure")
