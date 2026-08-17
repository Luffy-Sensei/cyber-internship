#!/usr/bin/env python3

"""
Day 06 — Spear Phishing Awareness Engine

Generates personalized spear-phishing awareness scenarios from
controlled target-profile data.

The engine does not send email. It produces training artifacts
for security-awareness analysis, including:

- Personalized email scenario
- Social-engineering indicators
- Psychological triggers
- Red flags
- Defensive guidance
- Email-authentication considerations
- JSON and text reports
"""

import json
import logging
import re
import sys
from datetime import datetime, timezone
from pathlib import Path


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent

INPUT_DIR = BASE_DIR / "input"
OUTPUT_DIR = BASE_DIR / "output"

TARGET_FILE = INPUT_DIR / "target.json"

JSON_OUTPUT = OUTPUT_DIR / "awareness_scenarios.json"
TEXT_OUTPUT = OUTPUT_DIR / "awareness_email.txt"

TOOL_NAME = "Day 06 Spear Phishing Awareness Engine"
TOOL_VERSION = "1.0"


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Input handling
# ---------------------------------------------------------------------------

def load_target():
    """Load and validate the controlled target profile."""

    if not TARGET_FILE.exists():
        raise RuntimeError(
            f"Target file not found: {TARGET_FILE}"
        )

    try:
        with TARGET_FILE.open("r", encoding="utf-8") as file:
            target = json.load(file)

    except json.JSONDecodeError as exc:
        raise RuntimeError(
            f"Invalid target JSON: {exc}"
        ) from exc
    if not isinstance(target, dict):
        raise RuntimeError(
            f"Target file must contain a single JSON object (dictionary), got {type(target).__name__}"
        )
    required_fields = ["name", "email", "company", "location"]

    missing = [
        field
        for field in required_fields
        if not target.get(field)
    ]

    if missing:
        raise RuntimeError(
            "Missing required target fields: "
            + ", ".join(missing)
        )

    return target


# ---------------------------------------------------------------------------
# Scenario generation
# ---------------------------------------------------------------------------

def generate_email(target):
    """Generate the personalized awareness email scenario."""

    company = target["company"]
    name = target["name"]
    location = target["location"]
    email = target["email"]

    # Sanitize company name for clean RFC-compliant domain formatting
    sanitized_domain = re.sub(r"[^a-z0-9]", "", company.lower())
    from_address = f"IT Security <it-security@{sanitized_domain}.example>"

    subject = f"Action Required: Your {company} account will be disabled"

    body = f"""From    : {from_address}
To      : {email}
Subject : {subject}

Hi {name},

Our security team noticed a login associated with
{location}.

Please verify your account within 24 hours to avoid
temporary account suspension.

[VERIFY ACCOUNT]
https://lab.internal/awareness-test

Regards,
IT Security Team

--- AWARENESS TRAINING SCENARIO ---
"""

    return {
        "from": from_address,
        "to": email,
        "subject": subject,
        "body": body,
    }


# ---------------------------------------------------------------------------
# Psychological analysis
# ---------------------------------------------------------------------------

def build_psychological_triggers(target):
    """Describe psychological techniques represented by the scenario."""
    company = target.get("company", "the organization")
    location = target.get("location", "a specified location")

    return [
        {
            "trigger": "authority",
            "severity": "high",
            "reason": f"The sender impersonates internal IT Security at {company}.",
            "defense": "Verify suspicious IT alerts via direct out-of-band communication channels.",
        },
        {
            "trigger": "urgency",
            "severity": "high",
            "reason": "Imposes an artificial 24-hour verification deadline to induce pressure.",
            "defense": "Pause and evaluate security actions regardless of stated deadlines.",
        },
        {
            "trigger": "fear",
            "severity": "medium",
            "reason": f"Threatens account suspension to compromise recipient judgment.",
            "defense": "Adhere to standard corporate authentication practices during urgent notices.",
        },
        {
            "trigger": "personalization",
            "severity": "medium",
            "reason": f"Leverages recipient metadata including name, employer ({company}), and location ({location}).",
            "defense": "Recognize that open-source intelligence (OSINT) allows attackers to customize phishing hooks.",
        },
    ]


# ---------------------------------------------------------------------------
# Red-flag analysis
# ---------------------------------------------------------------------------

def build_red_flags():
    """Build awareness indicators represented in the scenario."""

    return [
        {
            "indicator": "Sender impersonation",
            "severity": "high",
            "reason": (
                "The message presents itself as an IT/security "
                "communication."
            ),
        },
        {
            "indicator": "Unexpected security notification",
            "severity": "high",
            "reason": (
                "An unexpected account-security message should "
                "be independently verified."
            ),
        },
        {
            "indicator": "Urgency",
            "severity": "high",
            "reason": (
                "A 24-hour deadline encourages rapid action."
            ),
        },
        {
            "indicator": "Threat of consequences",
            "severity": "medium",
            "reason": (
                "Account suspension is presented as the consequence "
                "of not complying."
            ),
        },
        {
            "indicator": "Verification request",
            "severity": "high",
            "reason": (
                "The recipient is encouraged to follow a supplied "
                "verification path."
            ),
        },
        {
            "indicator": "Personalized hook",
            "severity": "medium",
            "reason": (
                "Publicly observable personal information is used "
                "to increase credibility."
            ),
        },
    ]


# ---------------------------------------------------------------------------
# Defensive guidance
# ---------------------------------------------------------------------------

def build_defensive_guidance():
    """Build defensive recommendations."""

    return [
        {
            "action": "Verify independently",
            "detail": (
                "Contact IT/security through an official internal "
                "channel rather than using contact information "
                "provided by the suspicious message."
            ),
        },
        {
            "action": "Do not trust the display name",
            "detail": (
                "A familiar-looking sender name does not prove "
                "that the message originated from the claimed "
                "organization."
            ),
        },
        {
            "action": "Avoid unexpected links",
            "detail": (
                "Navigate to known official services independently "
                "instead of following suspicious verification links."
            ),
        },
        {
            "action": "Do not allow urgency to bypass procedure",
            "detail": (
                "Security procedures should remain consistent even "
                "when a message claims immediate action is required."
            ),
        },
        {
            "action": "Report suspicious messages",
            "detail": (
                "Forward suspicious messages to the organization's "
                "security or phishing-reporting process."
            ),
        },
    ]


# ---------------------------------------------------------------------------
# Email authentication analysis
# ---------------------------------------------------------------------------

def build_email_authentication_analysis():
    """Explain SPF, DKIM and DMARC relevance."""

    return {
        "SPF": (
            "Checks whether the sending infrastructure is authorized "
            "to send mail for the claimed domain."
        ),
        "DKIM": (
            "Uses a cryptographic signature to provide domain-level "
            "message authentication and integrity information."
        ),
        "DMARC": (
            "Uses domain policy and alignment checks involving SPF "
            "and/or DKIM and provides reporting capabilities."
        ),
        "defensive_note": (
            "Email authentication improves protection against domain "
            "impersonation but does not eliminate every form of "
            "phishing."
        ),
    }


# ---------------------------------------------------------------------------
# Report construction
# ---------------------------------------------------------------------------

def build_report(target, email):
    """Build the complete structured awareness report."""

    psychological_triggers = build_psychological_triggers(target)
    red_flags = build_red_flags()
    defensive_guidance = build_defensive_guidance()
    email_authentication = build_email_authentication_analysis()

    return {
        "scan_metadata": {
            "timestamp_utc": datetime.now(
                timezone.utc
            ).isoformat(),
            "tool": TOOL_NAME,
            "tool_version": TOOL_VERSION,
            "scenario_type": "spear_phishing_awareness",
            "delivery": "simulation_only",
        },

        "target_profile": {
            "name": target["name"],
            "email": target["email"],
            "company": target["company"],
            "location": target["location"],
        },

        "email_scenario": email,

        "psychological_triggers": psychological_triggers,

        "red_flags": red_flags,

        "defensive_guidance": defensive_guidance,

        "email_authentication": email_authentication,

        "statistics": {
            "psychological_trigger_count": len(
                psychological_triggers
            ),
            "red_flag_count": len(red_flags),
            "defensive_guidance_count": len(
                defensive_guidance
            ),
            "authentication_controls": 3,
        },
    }


# ---------------------------------------------------------------------------
# Output generation
# ---------------------------------------------------------------------------

def save_json(report):
    """Save the structured JSON report."""

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


def save_text(report):
    """Save a human-readable training artifact."""

    target = report["target_profile"]
    email = report["email_scenario"]
    triggers = report["psychological_triggers"]
    red_flags = report["red_flags"]
    defenses = report["defensive_guidance"]
    authentication = report["email_authentication"]

    lines = [
        "=" * 72,
        "DAY 06 — SPEAR PHISHING AWARENESS SCENARIO",
        "=" * 72,
        "",
        "TARGET PROFILE",
        "-" * 72,
        f"Name     : {target['name']}",
        f"Email    : {target['email']}",
        f"Company  : {target['company']}",
        f"Location : {target['location']}",
        "",
        "EMAIL SCENARIO",
        "-" * 72,
        f"From    : {email['from']}",
        f"To      : {email['to']}",
        f"Subject : {email['subject']}",
        "",
        email["body"],
        "",
        "PSYCHOLOGICAL TRIGGERS",
        "-" * 72,
    ]

    for trigger in triggers:
        lines.append(
            f"- [{trigger['severity'].upper()}] "
            f"{trigger['trigger']}: "
            f"{trigger['reason']}"
        )
        lines.append(
            f"  Defense: {trigger['defense']}"
        )

    lines.extend(
        [
            "",
            "RED FLAGS",
            "-" * 72,
        ]
    )

    for flag in red_flags:
        lines.append(
            f"- [{flag['severity'].upper()}] "
            f"{flag['indicator']}: "
            f"{flag['reason']}"
        )

    lines.extend(
        [
            "",
            "DEFENSIVE GUIDANCE",
            "-" * 72,
        ]
    )

    for defense in defenses:
        lines.append(
            f"- {defense['action']}: "
            f"{defense['detail']}"
        )

    lines.extend(
        [
            "",
            "EMAIL AUTHENTICATION",
            "-" * 72,
            f"- SPF: {authentication['SPF']}",
            f"- DKIM: {authentication['DKIM']}",
            f"- DMARC: {authentication['DMARC']}",
            "",
            f"Note: {authentication['defensive_note']}",
            "",
            "=" * 72,
            "END OF AWARENESS REPORT",
            "=" * 72,
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

def print_summary(report):
    """Print a concise console summary."""

    target = report["target_profile"]
    statistics = report["statistics"]

    print()
    print("=" * 72)
    print("📧 DAY 06: SPEAR PHISHING AWARENESS ENGINE")
    print("=" * 72)

    print()
    print("[+] Scenario Generation Complete")
    print(f"├── Target: {target['name']}")
    print(f"├── Company: {target['company']}")
    print(f"├── Location: {target['location']}")
    print("└── Delivery: Simulation Only")

    print()
    print("📊 ANALYSIS STATISTICS")
    print(
        f"├── Psychological Triggers: "
        f"{statistics['psychological_trigger_count']}"
    )
    print(
        f"├── Red Flags: "
        f"{statistics['red_flag_count']}"
    )
    print(
        f"├── Defensive Guidance: "
        f"{statistics['defensive_guidance_count']}"
    )
    print(
        f"└── Authentication Controls: "
        f"{statistics['authentication_controls']}"
    )

    print()
    print("🔍 RED FLAGS")

    flags = report["red_flags"]
    for idx, flag in enumerate(flags):
        branch = "└──" if idx == len(flags) - 1 else "├──"
        print(f"{branch} [{flag['severity'].upper()}] {flag['indicator']}")

    print()
    print("[+] JSON report:")
    print(f"    {JSON_OUTPUT.resolve()}")

    print("[+] Text report:")
    print(f"    {TEXT_OUTPUT.resolve()}")

    print()
    print("✅ Generation complete.")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    """Program entry point."""

    try:
        target = load_target()

        email = generate_email(target)

        report = build_report(
            target,
            email,
        )

        save_json(report)
        save_text(report)

        print_summary(report)

    except RuntimeError as exc:
        logger.error("%s", exc)
        sys.exit(1)


if __name__ == "__main__":
    main()
