"""SFR Box helpers."""
import hashlib
import hmac


def compute_hash(token: str, username: str, password: str) -> str:
    hash_username = hashlib.sha256(username.encode()).hexdigest()
    hmac_username = hmac.new(token.encode(), hash_username.encode(), hashlib.sha256)

    hash_password = hashlib.sha256(password.encode()).hexdigest()
    hmac_password = hmac.new(token.encode(), hash_password.encode(), hashlib.sha256)

    return f"{hmac_username.hexdigest()}{hmac_password.hexdigest()}"
