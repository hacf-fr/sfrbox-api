"""SFR Box helpers."""
import hashlib
import hmac


def _compute_hash(token: str, value: str) -> str:
    """Compute single value hash."""
    hash = hashlib.sha256(value.encode()).hexdigest()
    return hmac.new(token.encode(), hash.encode(), hashlib.sha256).hexdigest()


def compute_hash(token: str, username: str, password: str) -> str:
    """Compute full username/password hash."""
    hmac_username = _compute_hash(token, username)
    hmac_password = _compute_hash(token, password)

    return f"{hmac_username}{hmac_password}"
