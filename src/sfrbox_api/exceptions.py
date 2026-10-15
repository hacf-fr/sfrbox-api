"""SFR Box exceptions."""


class SFRBoxError(Exception):
    """SFR Box base exception."""


class SFRBoxApiError(SFRBoxError):
    """SFR Box api exception."""


class SFRBoxAuthenticationError(SFRBoxError):
    """SFR Box authentication exception."""
