#!/usr/bin/env python3

"""
Day 07 — Password Attacks & Credential Stuffing
Local Flask Authentication Lab

Provides a deliberately simple local authentication endpoint
for observing repeated login attempts and rate limiting.

This application is intended for localhost security training.
"""

from collections import defaultdict, deque
from datetime import datetime, timezone
from threading import Lock
from time import monotonic

from flask import Flask, jsonify, request


app = Flask(__name__)


# ---------------------------------------------------------------------------
# Lab configuration
# ---------------------------------------------------------------------------

HOST = "127.0.0.1"
PORT = 5000

LAB_USERNAME = "admin"
LAB_PASSWORD = "letmein"

MAX_ATTEMPTS = 5
WINDOW_SECONDS = 30
LOCKOUT_SECONDS = 30


# ---------------------------------------------------------------------------
# Attempt tracking
# ---------------------------------------------------------------------------

attempt_history = defaultdict(deque)
lockout_until = {}
state_lock = Lock()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def utc_timestamp():
    """Return the current UTC timestamp."""

    return datetime.now(timezone.utc).isoformat()


def client_key():
    """Identify the local client."""

    return request.remote_addr or "unknown"


def is_locked(client):
    """Return lockout status for a client."""

    now = monotonic()

    with state_lock:
        expires_at = lockout_until.get(client)

        if expires_at is None:
            return False, 0

        if now >= expires_at:
            del lockout_until[client]
            return False, 0

        remaining = int(expires_at - now) + 1
        return True, remaining


def record_failed_attempt(client):
    """
    Record a failed authentication attempt and determine
    whether the rate limit has been reached.
    """

    now = monotonic()

    with state_lock:
        attempts = attempt_history[client]

        cutoff = now - WINDOW_SECONDS

        while attempts and attempts[0] < cutoff:
            attempts.popleft()

        attempts.append(now)

        if len(attempts) >= MAX_ATTEMPTS:
            lockout_until[client] = now + LOCKOUT_SECONDS
            return True, len(attempts)

        return False, len(attempts)


def clear_attempts(client):
    """Clear failed-attempt history after successful authentication."""

    with state_lock:
        attempt_history.pop(client, None)
        lockout_until.pop(client, None)


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.get("/")
def index():
    """Return basic lab information."""

    return jsonify(
        {
            "lab": "Day 07 Password Attacks & Rate Limiting",
            "status": "running",
            "endpoint": "/login",
            "method": "POST",
            "username": LAB_USERNAME,
            "rate_limit": {
                "max_failed_attempts": MAX_ATTEMPTS,
                "window_seconds": WINDOW_SECONDS,
                "lockout_seconds": LOCKOUT_SECONDS,
            },
            "timestamp_utc": utc_timestamp(),
        }
    )


@app.post("/login")
def login():
    """Authenticate against the deliberately local lab account."""

    client = client_key()

    locked, remaining = is_locked(client)

    if locked:
        return (
            jsonify(
                {
                    "success": False,
                    "error": "rate_limited",
                    "message": "Too many failed authentication attempts.",
                    "retry_after_seconds": remaining,
                    "timestamp_utc": utc_timestamp(),
                }
            ),
            429,
        )

    username = request.form.get("username", "")
    password = request.form.get("password", "")

    if username == LAB_USERNAME and password == LAB_PASSWORD:
        clear_attempts(client)

        return (
            jsonify(
                {
                    "success": True,
                    "message": "Welcome, admin!",
                    "timestamp_utc": utc_timestamp(),
                }
            ),
            200,
        )

    locked_now, attempt_count = record_failed_attempt(client)

    if locked_now:
        return (
            jsonify(
                {
                    "success": False,
                    "error": "rate_limited",
                    "message": "Too many failed authentication attempts.",
                    "attempt_count": attempt_count,
                    "retry_after_seconds": LOCKOUT_SECONDS,
                    "timestamp_utc": utc_timestamp(),
                }
            ),
            429,
        )

    return (
        jsonify(
            {
                "success": False,
                "error": "invalid_credentials",
                "message": "Invalid username or password.",
                "attempt_count": attempt_count,
                "remaining_before_lockout": (
                    MAX_ATTEMPTS - attempt_count
                ),
                "timestamp_utc": utc_timestamp(),
            }
        ),
        401,
    )


# ---------------------------------------------------------------------------
# Application entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("=" * 70)
    print("DAY 07 — LOCAL AUTHENTICATION LAB")
    print("=" * 70)
    print(f"Server : http://{HOST}:{PORT}")
    print(f"Login  : http://{HOST}:{PORT}/login")
    print(f"User   : {LAB_USERNAME}")
    print(f"Rate limit: {MAX_ATTEMPTS} failed attempts / {WINDOW_SECONDS}s")
    print(f"Lockout: {LOCKOUT_SECONDS}s")
    print("=" * 70)

    app.run(
        host=HOST,
        port=PORT,
        debug=False,
    )
