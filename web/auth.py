import hmac
import os
from functools import wraps

from flask import jsonify, request


def require_api_key(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        expected = os.environ.get("PHISHGUARD_API_KEY", "")
        supplied = request.headers.get("X-API-Key", "")
        if not expected or not hmac.compare_digest(supplied.encode(), expected.encode()):
            return jsonify({"error": "Unauthorized"}), 401
        return fn(*args, **kwargs)
    return wrapper