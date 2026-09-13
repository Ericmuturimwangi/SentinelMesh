"""The single error type that is allowed to reach a client."""


class ApiError(Exception):
    """An error whose message is safe to serialise into a response.

    Anything that is not an ApiError is treated as an internal fault: it gets
    logged with a request id and returned as a generic 500, so driver and
    database text never reaches a client.
    """

    def __init__(self, status: int, code: str, message: str, details: list[dict] | None = None):
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message
        self.details = details or []

    def to_dict(self) -> dict:
        body: dict = {"code": self.code, "message": self.message}
        if self.details:
            body["details"] = self.details
        return {"error": body}
