#!/usr/bin/env python3

"""
Day 07 — Password Attacks & Credential Stuffing
Local Authentication Attempt Simulator

Sends a controlled list of candidate passwords to an explicitly
authorized authentication lab and records server responses.

Safety:
    By default, only loopback targets are permitted:
        127.0.0.1
        ::1
        localhost

    Remote targets require the explicit --allow-remote flag.

Modes:
    auth
        Stops after authentication success, rate limiting, or error.

    rate-limit
        Continues through failed attempts until HTTP 429 is detected.
        Authentication success also stops the simulation unless
        --continue-after-success is supplied.

Examples:
    python3 brute_force_simulator.py admin

    python3 brute_force_simulator.py admin \
        --mode rate-limit \
        --delay 0.5

    python3 brute_force_simulator.py admin \
        --wordlist wordlist.txt

    python3 brute_force_simulator.py admin \
        --url localhost:5000/login

    python3 brute_force_simulator.py admin \
        --url https://lab.example.test/login \
        --allow-remote
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import logging
import math
import socket
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

import requests


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

TOOL_VERSION = "2.0"

DEFAULT_URL = "http://127.0.0.1:5000/login"
REQUEST_TIMEOUT = 5

BASE_DIR = Path(__file__).resolve().parent
OUTPUT_DIR = BASE_DIR / "output"

JSON_OUTPUT = OUTPUT_DIR / "bruteforce_results.json"
TEXT_OUTPUT = OUTPUT_DIR / "bruteforce_results.txt"

USER_AGENT = f"CyberInternship-Day07-AuthSimulator/{TOOL_VERSION}"

MAX_RESPONSE_BODY = 4096
DEFAULT_MAX_ATTEMPTS = 100

LOOPBACK_HOSTS = {
    "localhost",
}


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Default controlled lab wordlist
# ---------------------------------------------------------------------------

DEFAULT_WORDLIST = [
    "123456",
    "password",
    "admin",
    "letmein",
    "qwerty",
]


# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------

def utc_timestamp() -> str:
    """Return the current UTC timestamp in ISO-8601 format."""

    return datetime.now(timezone.utc).isoformat()


def truncate_text(value: str, limit: int = MAX_RESPONSE_BODY) -> str:
    """Prevent excessively large response bodies from entering reports."""

    if len(value) <= limit:
        return value

    return value[:limit] + "... [truncated]"


# ---------------------------------------------------------------------------
# URL validation
# ---------------------------------------------------------------------------

def is_loopback_hostname(hostname: str) -> bool:
    """
    Determine whether a hostname resolves to loopback.

    localhost is explicitly accepted.

    IP literals are checked directly.

    Other hostnames are resolved using DNS so that a hostname resolving
    to a loopback address is still considered local.
    """

    if not hostname:
        return False

    hostname = hostname.lower().rstrip(".")

    if hostname in LOOPBACK_HOSTS:
        return True

    try:
        address = ipaddress.ip_address(hostname)
        return address.is_loopback

    except ValueError:
        pass

    try:
        addresses = socket.getaddrinfo(
            hostname,
            None,
            type=socket.SOCK_STREAM,
        )

    except socket.gaierror:
        return False

    if not addresses:
        return False

    return all(
        ipaddress.ip_address(
            address[4][0]
        ).is_loopback
        for address in addresses
    )


def normalize_url(url: str, allow_remote: bool = False) -> str:
    """
    Validate and normalize the supplied login URL.

    Examples:

        localhost:5000/login
        ->
        http://localhost:5000/login

    By default only loopback destinations are accepted.
    """

    url = url.strip()

    if not url:
        raise ValueError("URL cannot be empty.")

    if "://" not in url:
        url = f"http://{url}"

    parsed = urlparse(url)

    if parsed.scheme not in {"http", "https"}:
        raise ValueError(
            "URL must use http:// or https://."
        )

    if not parsed.hostname:
        raise ValueError(
            "Invalid URL. Example: "
            "http://127.0.0.1:5000/login"
        )

    if parsed.username or parsed.password:
        raise ValueError(
            "URLs containing embedded credentials are not allowed."
        )

    if parsed.fragment:
        raise ValueError(
            "URL fragments are not allowed."
        )

    if not parsed.path:
        raise ValueError(
            "URL must include an authentication endpoint path."
        )

    if not allow_remote and not is_loopback_hostname(
        parsed.hostname
    ):
        raise ValueError(
            "Remote targets are blocked by default. "
            "Use an explicitly authorized localhost/loopback "
            "lab or supply --allow-remote."
        )

    return url


# ---------------------------------------------------------------------------
# Wordlist handling
# ---------------------------------------------------------------------------

def deduplicate_preserving_order(
    values: list[str],
) -> list[str]:
    """Remove duplicate candidates while preserving order."""

    seen = set()
    result = []

    for value in values:
        if value not in seen:
            seen.add(value)
            result.append(value)

    return result


def load_wordlist(path: str | None = None) -> list[str]:
    """
    Load candidate passwords from a text file.

    Blank lines are ignored.

    Duplicate entries are removed while preserving order.

    If no file is supplied, the controlled default lab wordlist
    is used.
    """

    if path is None:
        return list(DEFAULT_WORDLIST)

    wordlist_path = Path(path).expanduser().resolve()

    if not wordlist_path.exists():
        raise ValueError(
            f"Wordlist file not found: {wordlist_path}"
        )

    if not wordlist_path.is_file():
        raise ValueError(
            f"Wordlist path is not a file: {wordlist_path}"
        )

    try:
        with wordlist_path.open(
            "r",
            encoding="utf-8",
        ) as file:
            candidates = [
                line.strip()
                for line in file
                if line.strip()
            ]

    except OSError as exc:
        raise ValueError(
            f"Unable to read wordlist: {exc}"
        ) from exc

    candidates = deduplicate_preserving_order(candidates)

    if not candidates:
        raise ValueError(
            "The supplied wordlist is empty."
        )

    return candidates


# ---------------------------------------------------------------------------
# HTTP session
# ---------------------------------------------------------------------------

def create_session() -> requests.Session:
    """Create a configured HTTP session."""

    session = requests.Session()

    session.headers.update(
        {
            "User-Agent": USER_AGENT,
            "Accept": "application/json",
        }
    )

    return session


# ---------------------------------------------------------------------------
# Authentication attempt
# ---------------------------------------------------------------------------

def submit_login(
    session: requests.Session,
    url: str,
    username: str,
    password: str,
) -> dict:
    """
    Submit one authentication attempt.

    Candidate passwords are intentionally NOT included in the
    returned evidence to avoid unnecessarily storing credentials.
    """

    timestamp = utc_timestamp()

    try:
        response = session.post(
            url,
            data={
                "username": username,
                "password": password,
            },
            timeout=REQUEST_TIMEOUT,
            allow_redirects=False,
        )

    except requests.Timeout as exc:
        return {
            "timestamp_utc": timestamp,
            "status_code": None,
            "result": "timeout",
            "success": False,
            "error": str(exc),
        }

    except requests.ConnectionError as exc:
        return {
            "timestamp_utc": timestamp,
            "status_code": None,
            "result": "connection_error",
            "success": False,
            "error": str(exc),
        }

    except requests.RequestException as exc:
        return {
            "timestamp_utc": timestamp,
            "status_code": None,
            "result": "request_error",
            "success": False,
            "error": str(exc),
        }

    try:
        body = response.json()

        if not isinstance(body, dict):
            body = {
                "response_type": type(body).__name__
            }

    except ValueError:
        body = {
            "raw_response": truncate_text(
                response.text
            )
        }

    status_code = response.status_code

    if (
        status_code == 200
        and body.get("success") is True
    ):
        result = "success"

    elif status_code == 401:
        result = "invalid_credentials"

    elif status_code == 429:
        result = "rate_limited"

    elif 300 <= status_code < 400:
        result = "redirect_response"

    elif 400 <= status_code < 500:
        result = "client_error"

    elif 500 <= status_code < 600:
        result = "server_error"

    else:
        result = "unexpected_response"

    return {
        "timestamp_utc": timestamp,
        "status_code": status_code,
        "result": result,
        "success": result == "success",
        "server_response": body,
    }


# ---------------------------------------------------------------------------
# Simulation
# ---------------------------------------------------------------------------

def run_simulation(
    url: str,
    username: str,
    wordlist: list[str],
    mode: str = "auth",
    delay: float = 0.0,
    max_attempts: int = DEFAULT_MAX_ATTEMPTS,
    continue_after_success: bool = False,
) -> list[dict]:
    """
    Execute the controlled authentication simulation.

    auth mode:
        Stops after successful authentication, rate limiting,
        or a request error.

    rate-limit mode:
        Continues through failures until HTTP 429 is observed.

    By default, successful authentication also stops the simulation.
    """

    attempts = []

    candidates = wordlist[:max_attempts]

    logger.info(
        "Starting authentication simulation"
    )
    logger.info(
        "Mode: %s",
        mode,
    )
    logger.info(
        "Target endpoint: %s",
        url,
    )
    logger.info(
        "Username: %s",
        username,
    )
    logger.info(
        "Candidate passwords: %d",
        len(candidates),
    )
    logger.info(
        "Delay between attempts: %.2f seconds",
        delay,
    )
    logger.info(
        "Maximum attempts: %d",
        max_attempts,
    )

    with create_session() as session:

        for index, password in enumerate(
            candidates,
            start=1,
        ):
            logger.info(
                "Attempt %d/%d",
                index,
                len(candidates),
            )

            result = submit_login(
                session=session,
                url=url,
                username=username,
                password=password,
            )

            result["attempt_number"] = index

            attempts.append(result)

            outcome = result["result"]
            status = result["status_code"]

            if outcome in {
                "timeout",
                "connection_error",
                "request_error",
            }:
                logger.error(
                    "Request failed: %s",
                    result.get("error"),
                )
                break

            if outcome == "success":
                logger.info(
                    "Authentication succeeded on attempt %d.",
                    index,
                )

                if not continue_after_success:
                    break

            elif outcome == "rate_limited":
                logger.warning(
                    "Server rate limit triggered on attempt %d.",
                    index,
                )
                break

            elif outcome == "invalid_credentials":
                logger.info(
                    "Attempt %d failed with HTTP 401.",
                    index,
                )

            elif outcome == "redirect_response":
                logger.warning(
                    "Redirect response received on attempt %d "
                    "(HTTP %s). Redirects are not followed.",
                    index,
                    status,
                )
                break

            else:
                logger.warning(
                    "Unexpected response on attempt %d: HTTP %s",
                    index,
                    status,
                )

            if index < len(candidates) and delay > 0:
                time.sleep(delay)

    return attempts


# ---------------------------------------------------------------------------
# Report construction
# ---------------------------------------------------------------------------

def build_report(
    url: str,
    username: str,
    wordlist: list[str],
    attempts: list[dict],
    mode: str,
    delay: float,
    max_attempts: int,
) -> dict:
    """Build structured JSON evidence."""

    successful_attempts = [
        attempt
        for attempt in attempts
        if attempt["result"] == "success"
    ]

    failed_attempts = [
        attempt
        for attempt in attempts
        if attempt["result"] == "invalid_credentials"
    ]

    rate_limited_attempts = [
        attempt
        for attempt in attempts
        if attempt["result"] == "rate_limited"
    ]

    request_errors = [
        attempt
        for attempt in attempts
        if attempt["result"] in {
            "timeout",
            "connection_error",
            "request_error",
        }
    ]

    unexpected_responses = [
        attempt
        for attempt in attempts
        if attempt["result"] in {
            "unexpected_response",
            "redirect_response",
            "client_error",
            "server_error",
        }
    ]

    first_rate_limit = (
        rate_limited_attempts[0]
        if rate_limited_attempts
        else None
    )

    retry_after = None

    if first_rate_limit:
        response_body = first_rate_limit.get(
            "server_response",
            {},
        )

        if isinstance(response_body, dict):
            retry_after = response_body.get(
                "retry_after_seconds"
            )

    return {
        "scan_metadata": {
            "timestamp_utc": utc_timestamp(),
            "tool": (
                "Day 07 Authentication "
                "Attempt Simulator"
            ),
            "tool_version": TOOL_VERSION,
            "simulation_type": (
                "local_authentication_testing"
            ),
            "mode": mode,
            "target_endpoint": url,
            "username": username,
            "candidate_count": len(wordlist),
            "tested_candidate_count": len(attempts),
            "max_attempts": max_attempts,
            "delay_seconds": delay,
        },

        "results": {
            "total_attempts": len(attempts),
            "failed_attempts": len(failed_attempts),
            "successful_attempts": len(
                successful_attempts
            ),
            "rate_limited_attempts": len(
                rate_limited_attempts
            ),
            "request_errors": len(request_errors),
            "unexpected_responses": len(
                unexpected_responses
            ),
            "rate_limit_detected": bool(
                rate_limited_attempts
            ),
        },

        "rate_limit_detection": {
            "detected": bool(
                rate_limited_attempts
            ),
            "first_trigger_attempt": (
                first_rate_limit["attempt_number"]
                if first_rate_limit
                else None
            ),
            "http_status": (
                first_rate_limit["status_code"]
                if first_rate_limit
                else None
            ),
            "retry_after_seconds": retry_after,
        },

        "attempts": attempts,

        "defensive_observations": [
            (
                "Repeated failed authentication attempts "
                "are observable at the application layer."
            ),
            (
                "HTTP 429 provides evidence that a "
                "rate-limit control was triggered."
            ),
            (
                "Rate limiting can reduce the number of "
                "authentication attempts available to an attacker."
            ),
            (
                "Authentication success should be determined "
                "using application-level semantics rather than "
                "HTTP status alone."
            ),
            (
                "Automatic redirects are disabled so that the "
                "simulator remains scoped to the supplied endpoint."
            ),
            (
                "Controlled delays reduce unnecessary load "
                "during authorized testing."
            ),
            (
                "MFA provides an additional protection layer "
                "when password-based authentication is compromised."
            ),
        ],
    }


# ---------------------------------------------------------------------------
# Save JSON report
# ---------------------------------------------------------------------------

def save_json_report(report: dict) -> None:
    """Save JSON evidence."""

    OUTPUT_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    with JSON_OUTPUT.open(
        "w",
        encoding="utf-8",
    ) as file:
        json.dump(
            report,
            file,
            indent=2,
            ensure_ascii=False,
        )

    logger.info(
        "JSON report saved to: %s",
        JSON_OUTPUT.resolve(),
    )


# ---------------------------------------------------------------------------
# Save text report
# ---------------------------------------------------------------------------

def save_text_report(report: dict) -> None:
    """Save human-readable evidence."""

    metadata = report["scan_metadata"]
    results = report["results"]
    detection = report["rate_limit_detection"]

    lines = [
        "=" * 70,
        "DAY 07 — AUTHENTICATION ATTEMPT SIMULATION",
        "=" * 70,
        "",
        "SIMULATION METADATA",
        "-" * 70,
        f"Generated UTC       : {metadata['timestamp_utc']}",
        f"Tool version        : {metadata['tool_version']}",
        f"Mode                : {metadata['mode']}",
        f"Endpoint            : {metadata['target_endpoint']}",
        f"Username            : {metadata['username']}",
        f"Candidates          : {metadata['candidate_count']}",
        f"Tested candidates   : {metadata['tested_candidate_count']}",
        f"Maximum attempts    : {metadata['max_attempts']}",
        f"Delay               : {metadata['delay_seconds']} seconds",
        "",
        "RESULTS",
        "-" * 70,
        f"Total attempts       : {results['total_attempts']}",
        f"Failed attempts      : {results['failed_attempts']}",
        f"Successful attempts  : {results['successful_attempts']}",
        (
            "Rate-limited attempts: "
            f"{results['rate_limited_attempts']}"
        ),
        f"Request errors       : {results['request_errors']}",
        (
            "Unexpected responses : "
            f"{results['unexpected_responses']}"
        ),
        (
            "Rate limit detected  : "
            f"{results['rate_limit_detected']}"
        ),
        "",
        "RATE-LIMIT DETECTION",
        "-" * 70,
        f"Detected             : {detection['detected']}",
        (
            "First trigger attempt: "
            f"{detection['first_trigger_attempt']}"
        ),
        (
            "HTTP status          : "
            f"{detection['http_status']}"
        ),
        (
            "Retry-after seconds  : "
            f"{detection['retry_after_seconds']}"
        ),
        "",
        "ATTEMPT LOG",
        "-" * 70,
    ]

    for attempt in report["attempts"]:
        status = attempt["status_code"]

        lines.append(
            f"#{attempt['attempt_number']} | "
            f"HTTP {status} | "
            f"{attempt['result']} | "
            f"{attempt['timestamp_utc']}"
        )

    lines.extend(
        [
            "",
            "DEFENSIVE OBSERVATIONS",
            "-" * 70,
        ]
    )

    for observation in report[
        "defensive_observations"
    ]:
        lines.append(
            f"- {observation}"
        )

    lines.extend(
        [
            "",
            "=" * 70,
            "END OF REPORT",
            "=" * 70,
        ]
    )

    with TEXT_OUTPUT.open(
        "w",
        encoding="utf-8",
    ) as file:
        file.write(
            "\n".join(lines) + "\n"
        )

    logger.info(
        "Text report saved to: %s",
        TEXT_OUTPUT.resolve(),
    )


# ---------------------------------------------------------------------------
# Console summary
# ---------------------------------------------------------------------------

def print_summary(report: dict) -> None:
    """Print a concise simulation summary."""

    results = report["results"]
    detection = report["rate_limit_detection"]

    print()
    print("=" * 70)
    print("🔐 DAY 07: AUTHENTICATION ATTEMPT SIMULATOR")
    print("=" * 70)

    print()
    print("[+] Simulation Complete")

    print(
        f"├── Total Attempts: "
        f"{results['total_attempts']}"
    )

    print(
        f"├── Failed Attempts: "
        f"{results['failed_attempts']}"
    )

    print(
        f"├── Successful Attempts: "
        f"{results['successful_attempts']}"
    )

    print(
        f"├── Rate-Limited Attempts: "
        f"{results['rate_limited_attempts']}"
    )

    print(
        f"├── Request Errors: "
        f"{results['request_errors']}"
    )

    print(
        f"└── Rate Limit Detected: "
        f"{results['rate_limit_detected']}"
    )

    if detection["detected"]:
        print()
        print("[+] Rate-limit evidence")

        print(
            f"├── Trigger Attempt: "
            f"{detection['first_trigger_attempt']}"
        )

        print(
            f"├── HTTP Status: "
            f"{detection['http_status']}"
        )

        print(
            f"└── Retry After: "
            f"{detection['retry_after_seconds']} seconds"
        )

    print()
    print("[+] JSON report:")
    print(f"    {JSON_OUTPUT.resolve()}")

    print("[+] Text report:")
    print(f"    {TEXT_OUTPUT.resolve()}")

    print()
    print("✅ Simulation complete.")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_arguments() -> argparse.Namespace:
    """Parse and validate command-line arguments."""

    parser = argparse.ArgumentParser(
        description=(
            "Day 07 local authentication "
            "attempt simulator."
        )
    )

    parser.add_argument(
        "username",
        help="Lab username to test.",
    )

    parser.add_argument(
        "--url",
        default=DEFAULT_URL,
        help=(
            "Login endpoint. "
            "http:// is automatically added when omitted. "
            f"Default: {DEFAULT_URL}"
        ),
    )

    parser.add_argument(
        "--mode",
        choices=[
            "auth",
            "rate-limit",
        ],
        default="auth",
        help=(
            "Simulation mode. "
            "'auth' stops on success; "
            "'rate-limit' continues until HTTP 429. "
            "Default: auth"
        ),
    )

    parser.add_argument(
        "--wordlist",
        "-w",
        help=(
            "Optional text file containing one "
            "candidate password per line."
        ),
    )

    parser.add_argument(
        "--delay",
        type=float,
        default=0.0,
        help=(
            "Delay in seconds between attempts. "
            "Default: 0.0"
        ),
    )

    parser.add_argument(
        "--max-attempts",
        type=int,
        default=DEFAULT_MAX_ATTEMPTS,
        help=(
            "Maximum number of authentication attempts. "
            f"Default: {DEFAULT_MAX_ATTEMPTS}"
        ),
    )

    parser.add_argument(
        "--allow-remote",
        action="store_true",
        help=(
            "Allow non-loopback targets. "
            "Use only against an explicitly authorized lab."
        ),
    )

    parser.add_argument(
        "--continue-after-success",
        action="store_true",
        help=(
            "Continue testing after successful authentication. "
            "Use only when specifically required by the lab."
        ),
    )

    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {TOOL_VERSION}",
    )

    args = parser.parse_args()

    # ---------------------------------------------------------------
    # URL validation
    # ---------------------------------------------------------------

    try:
        args.url = normalize_url(
            args.url,
            allow_remote=args.allow_remote,
        )

    except ValueError as exc:
        parser.error(str(exc))

    # ---------------------------------------------------------------
    # Delay validation
    # ---------------------------------------------------------------

    if (
        not math.isfinite(args.delay)
        or args.delay < 0
    ):
        parser.error(
            "--delay must be a finite value >= 0."
        )

    # ---------------------------------------------------------------
    # Maximum attempt validation
    # ---------------------------------------------------------------

    if args.max_attempts < 1:
        parser.error(
            "--max-attempts must be at least 1."
        )

    # ---------------------------------------------------------------
    # Wordlist validation
    # ---------------------------------------------------------------

    try:
        args.wordlist = load_wordlist(
            args.wordlist
        )

    except ValueError as exc:
        parser.error(str(exc))

    return args


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    """Program entry point."""

    args = parse_arguments()

    username = args.username.strip()

    if not username:
        logger.error(
            "Username cannot be empty."
        )
        return 1

    attempts = run_simulation(
        url=args.url,
        username=username,
        wordlist=args.wordlist,
        mode=args.mode,
        delay=args.delay,
        max_attempts=args.max_attempts,
        continue_after_success=(
            args.continue_after_success
        ),
    )

    if not attempts:
        logger.error(
            "No authentication attempts were recorded."
        )
        return 1

    report = build_report(
        url=args.url,
        username=username,
        wordlist=args.wordlist,
        attempts=attempts,
        mode=args.mode,
        delay=args.delay,
        max_attempts=args.max_attempts,
    )

    try:
        save_json_report(report)
        save_text_report(report)

    except OSError as exc:
        logger.error(
            "Unable to save report: %s",
            exc,
        )
        return 1

    print_summary(report)

    return 0


if __name__ == "__main__":
    sys.exit(main())
