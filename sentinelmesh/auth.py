import hmac
from functools import wraps

from flask import current_app, g, request, session

from .errors import ApiError


def _session_principal():
    """The SOC dashboard's signed cookie, carrying an already-validated key name.

    Only the name is stored, so the cookie is never a bearer credential: the
    key is re-resolved from configuration on every request, and a credential
    that has since been removed stops working immediately.
    """
    name = session.get("api_key_name")
    if not name:
        return None
    return next((k for k in current_app.config["API_KEYS"] if k.name == name), None)


def _authenticate() -> None:
    header = request.headers.get("Authorization", "")
    scheme, _, presented = header.partition(" ")

    if scheme.lower() != "bearer" or not presented.strip():
        from_session = _session_principal()
        if from_session is not None:
            g.api_key = from_session
            return
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
