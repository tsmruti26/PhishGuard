import logging
import os

from flask import request
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.exceptions import HTTPException

ALLOWED_ORIGINS = ["http://127.0.0.1:8080", "http://localhost:8080"]

CSP = (
    "default-src 'self'; "
    "script-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com; "
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
    "font-src https://fonts.gstatic.com; "
    "img-src 'self' data:; connect-src 'self'; "
    "object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
)
# Set PHISHGUARD_CSP_REPORT_ONLY=1 to test the policy without blocking anything
CSP_HEADER = (
    "Content-Security-Policy-Report-Only"
    if os.environ.get("PHISHGUARD_CSP_REPORT_ONLY") == "1"
    else "Content-Security-Policy"
)


class SanitizeLogFilter(logging.Filter):
    """Stops attacker-controlled strings from forging extra log lines."""

    def filter(self, record):
        record.msg = record.getMessage().replace("\r", "\\r").replace("\n", "\\n")
        record.args = ()
        return True


def init_security(app):
    app.config["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024
    CORS(app, origins=ALLOWED_ORIGINS)
    limiter = Limiter(get_remote_address, app=app, default_limits=["60/minute"])

    logging.basicConfig(filename="phishguard.log", level=logging.INFO)
    for handler in logging.getLogger().handlers:
        handler.addFilter(SanitizeLogFilter())

    @app.after_request
    def security_headers(resp):
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "no-referrer"
        resp.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        resp.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        resp.headers[CSP_HEADER] = CSP
        if request.path.startswith("/api/"):
            resp.headers["Cache-Control"] = "no-store"
        return resp

    @app.errorhandler(Exception)
    def handle_error(e):
        if isinstance(e, HTTPException):
            return e
        app.logger.exception("Unhandled error")
        return {"error": "Internal error"}, 500

    return limiter