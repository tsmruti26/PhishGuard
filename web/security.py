import logging

from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.exceptions import HTTPException

ALLOWED_ORIGINS = ["http://127.0.0.1:8080", "http://localhost:8080"]


def init_security(app):
    app.config["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024  # 2 MB uploads
    CORS(app, origins=ALLOWED_ORIGINS)
    limiter = Limiter(get_remote_address, app=app, default_limits=["60/minute"])

    logging.basicConfig(filename="phishguard.log", level=logging.INFO)

    @app.after_request
    def security_headers(resp):
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "no-referrer"
        return resp

    @app.errorhandler(Exception)
    def handle_error(e):
        if isinstance(e, HTTPException):
            return e
        app.logger.exception("Unhandled error")
        return {"error": "Internal error"}, 500

    return limiter
