#!/usr/bin/env python3

"""
Day 02 — Email Harvesting & Social Engineering Awareness
Sqrock Cybersecurity Internship — Phase 1

Educational tool for authorized laboratory environments.

Features:
1. Validates HTTP/HTTPS target URLs.
2. Retrieves webpage HTML through an HTTP request.
3. Extracts email-like strings using regex.
4. Normalizes and deduplicates discovered addresses.
5. Categorizes addresses using conservative role-based analysis.
6. Generates defensive security-awareness observations.
7. Produces a structured JSON report.

IMPORTANT:
Only use this tool against systems you own or have
explicit authorization to test.
"""


import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from time import perf_counter
from urllib.parse import urlparse

import requests


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

EMAIL_PATTERN = re.compile(
    r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+"
)

USER_AGENT = (
    "CyberInternship-EmailHarvester/2.0 "
    "(Authorized Security Training)"
)

DEFAULT_OUTPUT = Path(
    "output/email_harvest_report.json"
)

ROLE_PREFIXES = {
    "admin",
    "billing",
    "contact",
    "finance",
    "help",
    "hr",
    "info",
    "sales",
    "support",
}


# ---------------------------------------------------------------------------
# URL Validation
# ---------------------------------------------------------------------------

def validate_url(url: str) -> str:
    """
    Validate that the supplied target uses HTTP or HTTPS
    and contains a hostname.
    """

    parsed = urlparse(url)

    if parsed.scheme not in {"http", "https"}:
        raise ValueError(
            "URL must start with http:// or https://"
        )

    if not parsed.netloc:
        raise ValueError(
            "URL must contain a valid hostname."
        )

    return url


# ---------------------------------------------------------------------------
# HTTP Retrieval
# ---------------------------------------------------------------------------

def fetch_page(url: str) -> requests.Response:
    """
    Retrieve the target webpage.

    This function performs a normal HTTP GET request.
    Therefore, the target web server will receive the request.
    """

    headers = {
        "User-Agent": USER_AGENT
    }

    response = requests.get(
        url,
        headers=headers,
        timeout=10
    )

    response.raise_for_status()

    return response


# ---------------------------------------------------------------------------
# Email Extraction
# ---------------------------------------------------------------------------

def extract_emails(html_text: str) -> list[str]:
    """
    Extract, normalize, and deduplicate email-like strings.

    NOTE:
    A regex match only indicates that a string resembles
    an email address. It does NOT prove that the mailbox exists,
    is active, or can receive messages.
    """

    matches = EMAIL_PATTERN.findall(html_text)

    normalized = {
        email.strip().lower()
        for email in matches
    }

    return sorted(normalized)


# ---------------------------------------------------------------------------
# Security Awareness Analysis
# ---------------------------------------------------------------------------

def analyze_security_awareness(
    emails: list[str]
) -> dict:
    """
    Categorize discovered addresses for defensive
    security-awareness analysis.

    Addresses using recognized organizational role prefixes
    are classified as role-based.

    Everything else remains unclassified because the address
    alone does not prove that it belongs to an individual.
    """

    role_emails = []
    unclassified_emails = []

    for email in emails:
        prefix = email.split("@", 1)[0].lower()

        if prefix in ROLE_PREFIXES:
            role_emails.append(email)
        else:
            unclassified_emails.append(email)

    return {
        "summary": {
            "total_harvested": len(emails),
            "role_based_addresses": len(role_emails),
            "unclassified_addresses": len(
                unclassified_emails
            )
        },

        "categorized": {
            "role_based_addresses": role_emails,
            "unclassified_addresses": unclassified_emails
        },

        "defensive_awareness_notes": [
            (
                "Role-based addresses may represent "
                "organizational functions and should receive "
                "appropriate anti-phishing protections."
            ),
            (
                "Unclassified addresses should not automatically "
                "be assumed to belong to individual users."
            ),
            (
                "Organizations should protect publicly exposed "
                "email addresses with strong authentication, "
                "phishing-resistant controls, and security awareness."
            ),
            (
                "SPF, DKIM, and DMARC can help reduce email "
                "spoofing and improve domain-level email security."
            )
        ]
    }


# ---------------------------------------------------------------------------
# Report Construction
# ---------------------------------------------------------------------------

def build_report(
    url: str,
    response: requests.Response,
    emails: list[str],
    elapsed: float
) -> dict:
    """
    Construct the complete structured scan report.
    """

    awareness_analysis = analyze_security_awareness(
        emails
    )

    return {
        "scan_metadata": {
            "target": url,
            "scan_type": (
                "Authorized Email Harvesting "
                "& Security Awareness Analysis"
            ),
            "timestamp_utc": datetime.now(
                timezone.utc
            ).isoformat(),
            "execution_time_seconds": round(
                elapsed,
                3
            )
        },

        "http_info": {
            "status_code": response.status_code,
            "content_type": response.headers.get(
                "Content-Type",
                "Unknown"
            ),
            "content_length": len(
                response.content
            )
        },

        "results": {
            "email_count": len(emails),
            "emails": emails
        },

        "security_awareness_analysis": awareness_analysis
    }


# ---------------------------------------------------------------------------
# JSON Output
# ---------------------------------------------------------------------------

def save_json(
    report: dict,
    output_file: Path
) -> None:
    """
    Save the structured report as formatted JSON.

    The parent directory is created automatically if required.
    """

    output_file.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    with output_file.open(
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            report,
            file,
            indent=4,
            ensure_ascii=False
        )

        file.write("\n")


# ---------------------------------------------------------------------------
# Main Program
# ---------------------------------------------------------------------------

def main() -> None:

    parser = argparse.ArgumentParser(
        description=(
            "Authorized Email Harvesting & "
            "Security Awareness Analysis Tool"
        )
    )

    parser.add_argument(
        "url",
        help=(
            "Authorized HTTP/HTTPS target URL "
            "(example: http://127.0.0.1/cyber-lab/contact.html)"
        )
    )

    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT,
        help=(
            "JSON output path "
            "(default: output/email_harvest_report.json)"
        )
    )

    args = parser.parse_args()

    try:

        target_url = validate_url(
            args.url
        )

        print(
            "[+] Day 02: Email Harvesting "
            "& Security Awareness"
        )

        print(
            "[+] Operational Boundary: "
            "Authorized Target Only"
        )

        print(
            f"[+] Target URL: {target_url}\n"
        )

        start_time = perf_counter()

        response = fetch_page(
            target_url
        )

        emails = extract_emails(
            response.text
        )

        elapsed_time = (
            perf_counter()
            - start_time
        )

        report = build_report(
            target_url,
            response,
            emails,
            elapsed_time
        )

        save_json(
            report,
            args.output
        )

        awareness = report[
            "security_awareness_analysis"
        ]

        summary = awareness[
            "summary"
        ]

        print(
            f"[+] HTTP Response Status: "
            f"{response.status_code}"
        )

        print(
            f"[+] Unique Emails Extracted: "
            f"{len(emails)}"
        )

        for email in emails:
            print(
                f"    └── {email}"
            )

        print(
            "\n[+] Security Awareness Analysis:"
        )

        print(
            "    └── Role-Based Addresses: "
            f"{summary['role_based_addresses']}"
        )

        print(
            "    └── Unclassified Addresses: "
            f"{summary['unclassified_addresses']}"
        )

        print(
            "\n[+] Full report saved to: "
            f"{args.output}"
        )

    except requests.RequestException as error:

        print(
            f"[-] Network Error: {error}",
            file=sys.stderr
        )

        sys.exit(1)

    except ValueError as error:

        print(
            f"[-] Validation Error: {error}",
            file=sys.stderr
        )

        sys.exit(1)

    except OSError as error:

        print(
            f"[-] Output Error: {error}",
            file=sys.stderr
        )

        sys.exit(1)


if __name__ == "__main__":
    main()
