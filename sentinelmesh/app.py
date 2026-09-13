import logging
import uuid

from flask import Flask, g, jsonify, request
from werkzeug.exceptions import HTTPException

from .config import load_config
from .db import init_pool
from .errors import ApiError
from .access import bp as access_bp
from .events import bp as events_bp
from .incidents import bp as incidents_bp
from .responses import bp as responses_bp
from .threats import bp as threats_bp

log = logging.getLogger("sentinelmesh")

# Anything not listed here is reported as a generic internal error, so a stray
# werkzeug or driver description never reaches a client.
SAFE_HTTP_ERRORS = {
    400: ("bad_request", "The request could not be understood."),
    404: ("not_found", "No such resource."),
    405: ("method_not_allowed", "That method is not allowed on this resource."),
    413: ("payload_too_large", "The request body is too large."),
    415: ("unsupported_media_type", "Content-Type must be application/json."),
}


def create_app(overrides: dict | None = None) -> Flask:
    app = Flask(__name__)
    app.config.update(load_config())
    if overrides:
        app.config.update(overrides)

    init_pool(app)
    app.register_blueprint(events_bp)
    app.register_blueprint(threats_bp)
    app.register_blueprint(incidents_bp)
    app.register_blueprint(access_bp)
    app.register_blueprint(responses_bp)
    _register_request_id(app)
    _register_error_handlers(app)
    return app


def _register_request_id(app: Flask) -> None:
    @app.before_request
    def assign_request_id():
        g.request_id = uuid.uuid4().hex

    @app.after_request
    def attach_request_id(response):
        response.headers["X-Request-ID"] = g.get("request_id", "")
        return response


def _register_error_handlers(app: Flask) -> None:
    @app.errorhandler(ApiError)
    def handle_api_error(error: ApiError):
        return jsonify(error.to_dict()), error.status

    @app.errorhandler(HTTPException)
    def handle_http_error(error: HTTPException):
        code, message = SAFE_HTTP_ERRORS.get(error.code, ("request_failed", "The request could not be completed."))
        return jsonify({"error": {"code": code, "message": message}}), error.code

    @app.errorhandler(Exception)
    def handle_unexpected(error: Exception):
        # The request id is the only handle the client gets; the cause stays
        # in the server log.
        log.exception("unhandled error", extra={"request_id": g.get("request_id"), "path": request.path})
        return (
            jsonify(
                {
                    "error": {
                        "code": "internal_error",
                        "message": "An internal error occurred.",
                        "request_id": g.get("request_id"),
                    }
                }
            ),
            500,
        )
