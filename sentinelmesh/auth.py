import hmac
from functools import wraps

from flask import current_app, g, request

from .errors import ApiError


def _authenticate() -> None:
    header = request.headers.get("Authorization", "")
    scheme, _, presented = header.partition(" ")
    if scheme.lower() != "bearer" or not presented.strip():
        raise ApiError(401, "unauthenticated", "A bearer token is required.")

    presented = presented.strip()

    # Every key is compared even after a match so that timing does not reveal
    # the position of a key in the configured list.
    matched = None
    for key in current_app.config["API_KEYS"]:
        if hmac.compare_digest(key.secret, presented):
            matched = key

    if matched is None:
        raise ApiError(401, "unauthenticated", "Invalid credentials.")

    g.api_key = matched


def require_scope(scope: str):
    def decorator(view):
        @wraps(view)
        def wrapper(*args, **kwargs):
            _authenticate()
            if scope not in g.api_key.scopes:
                raise ApiError(403, "forbidden", f"This credential lacks the {scope!r} scope.")
            return view(*args, **kwargs)

        return wrapper

    return decorator
