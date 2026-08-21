#!/usr/bin/env python3
"""
Day 10 - Baiting & Watering Hole Honeypot Tracker
Sqrock Cybersecurity Internship - Phase 1

Authorized local security-awareness simulation.

This program creates a benign local HTTP honeypot that records
requests made to configured bait paths.

Captured data:
    - UTC timestamp
    - source IP address
    - requested path
    - User-Agent
    - HTTP method

No malware, downloads, credentials, or external tracking are used.
"""

import argparse
import json
import logging
import signal
import sys
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any


# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent
INPUT_FILE = BASE_DIR / "input" / "bait_links.json"
JSON_OUTPUT = BASE_DIR / "output" / "honeypot_events.json"
TEXT_OUTPUT = BASE_DIR / "output" / "honeypot_events.txt"


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)

logger = logging.getLogger("day10-honeypot")


# ---------------------------------------------------------------------------
# Global state
# ---------------------------------------------------------------------------

EVENTS: list[dict[str, Any]] = []
BAIT_PATHS: set[str] = set()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def utc_timestamp() -> str:
    """Return the current UTC timestamp in ISO-8601 format."""
    return datetime.now(timezone.utc).isoformat()


def ensure_output_directory() -> None:
    """Create the output directory if necessary."""
    JSON_OUTPUT.parent.mkdir(parents=True, exist_ok=True)


def load_bait_paths() -> set[str]:
    """
    Load configured bait paths from input/bait_links.json.

    Expected format:
    {
        "bait_links": [
            "/free-download",
            "/important-document",
            "/software-update"
        ]
    }
    """
    if not INPUT_FILE.exists():
        logger.warning("Bait configuration not found: %s", INPUT_FILE)
        return {"/bait"}

    try:
        with INPUT_FILE.open("r", encoding="utf-8") as file:
            data = json.load(file)

        links = data.get("bait_links", [])

        if not isinstance(links, list):
            raise ValueError("'bait_links' must be a JSON list")

        paths = set()

        for link in links:
            if not isinstance(link, str):
                continue

            path = link.strip()

            if not path:
                continue

            if not path.startswith("/"):
                path = "/" + path

            paths.add(path)

        if not paths:
            logger.warning("No valid bait paths found. Using /bait.")
            return {"/bait"}

        return paths

    except (json.JSONDecodeError, OSError, ValueError) as exc:
        logger.error("Failed to load bait configuration: %s", exc)
        return {"/bait"}


def save_events() -> None:
    """Persist captured events to JSON and text reports."""
    ensure_output_directory()

    with JSON_OUTPUT.open("w", encoding="utf-8") as file:
        json.dump(
            EVENTS,
            file,
            indent=4,
            ensure_ascii=False,
        )

    with TEXT_OUTPUT.open("w", encoding="utf-8") as file:
        for index, event in enumerate(EVENTS, start=1):
            file.write(f"Event {index}\n")
            file.write("-" * 60 + "\n")

            for key, value in event.items():
                file.write(f"{key}: {value}\n")

            file.write("\n")

    logger.info("JSON report saved to: %s", JSON_OUTPUT)
    logger.info("Text report saved to: %s", TEXT_OUTPUT)


def record_event(handler: BaseHTTPRequestHandler) -> dict[str, Any]:
    """Create and store a honeypot event from an HTTP request."""
    event = {
        "timestamp": utc_timestamp(),
        "ip": handler.client_address[0],
        "method": handler.command,
        "path": handler.path,
        "user_agent": handler.headers.get("User-Agent", "?"),
        "bait_triggered": handler.path.split("?", 1)[0] in BAIT_PATHS,
    }

    EVENTS.append(event)
    save_events()

    return event


# ---------------------------------------------------------------------------
# HTTP Handler
# ---------------------------------------------------------------------------

class HoneyHandler(BaseHTTPRequestHandler):
    """Handle HTTP requests received by the local honeypot."""

    server_version = "Day10-Honeypot/1.0"

    def do_GET(self) -> None:
        """Handle HTTP GET requests."""
        event = record_event(self)

        logger.info(
            "Captured request: %s %s from %s",
            event["method"],
            event["path"],
            event["ip"],
        )

        if event["bait_triggered"]:
            message = (
                "Simulation bait accessed successfully. "
                "No real download or payload was executed."
            )
            status_code = 200
        else:
            message = (
                "Day 10 honeypot active. "
                "This endpoint is part of an authorized local simulation."
            )
            status_code = 200

        body = message.encode("utf-8")

        self.send_response(status_code)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()

        self.wfile.write(body)

    def do_HEAD(self) -> None:
        """Handle HEAD requests without recording unnecessary response data."""
        body = b"Day 10 honeypot"

        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()

    def log_message(self, format_string: str, *args: Any) -> None:
        """Suppress BaseHTTPRequestHandler's default access log."""
        return


# ---------------------------------------------------------------------------
# Server
# ---------------------------------------------------------------------------

def create_server(host: str, port: int) -> ThreadingHTTPServer:
    """Create the honeypot HTTP server."""
    return ThreadingHTTPServer((host, port), HoneyHandler)


def shutdown_handler(signum: int, frame: Any) -> None:
    """Handle termination signals cleanly."""
    logger.info("Shutdown signal received.")
    save_events()
    sys.exit(0)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_arguments() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Day 10 local baiting/watering-hole honeypot simulator."
    )

    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="Interface to bind to. Default: 127.0.0.1",
    )

    parser.add_argument(
        "--port",
        type=int,
        default=8080,
        help="HTTP port. Default: 8080",
    )

    return parser.parse_args()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    """Start the local honeypot."""
    global BAIT_PATHS

    args = parse_arguments()

    if not 1 <= args.port <= 65535:
        logger.error("Invalid port: %s", args.port)
        sys.exit(1)

    BAIT_PATHS = load_bait_paths()
    ensure_output_directory()

    logger.info("Starting Day 10 honeypot simulation")
    logger.info("Bind address: %s", args.host)
    logger.info("Port: %d", args.port)
    logger.info("Configured bait paths: %s", sorted(BAIT_PATHS))

    print()
    print("=" * 72)
    print("🍯 DAY 10 — BAITING & WATERING HOLE HONEYPOT")
    print("=" * 72)
    print()
    print("[+] Authorized local security-awareness simulation")
    print(f"[+] Honeypot: http://{args.host}:{args.port}")
    print("[+] Bait paths:")

    for path in sorted(BAIT_PATHS):
        print(f"    → http://{args.host}:{args.port}{path}")

    print()
    print("[+] Waiting for HTTP requests...")
    print("[+] Press Ctrl+C to stop.")
    print()

    signal.signal(signal.SIGINT, shutdown_handler)
    signal.signal(signal.SIGTERM, shutdown_handler)

    try:
        server = create_server(args.host, args.port)

        with server:
            server.serve_forever()

    except OSError as exc:
        logger.error("Unable to start server: %s", exc)
        sys.exit(1)

    finally:
        save_events()


if __name__ == "__main__":
    main()
