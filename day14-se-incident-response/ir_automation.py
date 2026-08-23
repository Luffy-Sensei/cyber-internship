#!/usr/bin/env python3

"""
Day 14 — Social Engineering Incident Response Automation

Defensive incident-response simulator for authorized security training.

The tool:
    1. Loads a structured incident.
    2. Validates the incident data.
    3. Determines the response policy.
    4. Simulates containment actions.
    5. Records an audit trail.
    6. Generates JSON and human-readable reports.

IMPORTANT:
This implementation performs NO real security-control changes.
Actions such as account lockout, session revocation, email quarantine,
and domain blocking are simulation-only.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


TOOL_NAME = "Day 14 SE Incident Response Automation"
TOOL_VERSION = "1.0.0"

SUPPORTED_TYPES = {
    "phishing",
    "credential_theft",
    "social_engineering",
    "account_compromise",
}

SUPPORTED_SEVERITIES = {
    "LOW",
    "MEDIUM",
    "HIGH",
    "CRITICAL",
}


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Incident:
    incident_id: str
    incident_type: str
    severity: str
    user: str
    source: str
    description: str


@dataclass(frozen=True)
class ResponseAction:
    action_id: str
    category: str
    action: str
    status: str
    simulation: bool
    reason: str


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

def configure_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO

    logging.basicConfig(
        level=level,
        format="%(asctime)s - %(levelname)s - %(message)s",
    )


# ---------------------------------------------------------------------------
# Input validation
# ---------------------------------------------------------------------------

def validate_incident(data: dict[str, Any]) -> Incident:
    required = {
        "incident_id",
        "type",
        "severity",
        "user",
        "source",
        "description",
    }

    missing = required - data.keys()

    if missing:
        raise ValueError(
            f"Missing required incident fields: {', '.join(sorted(missing))}"
        )

    incident_type = str(data["type"]).strip().lower()
    severity = str(data["severity"]).strip().upper()

    if incident_type not in SUPPORTED_TYPES:
        raise ValueError(
            f"Unsupported incident type: {incident_type}. "
            f"Supported types: {', '.join(sorted(SUPPORTED_TYPES))}"
        )

    if severity not in SUPPORTED_SEVERITIES:
        raise ValueError(
            f"Unsupported severity: {severity}. "
            f"Supported severities: {', '.join(sorted(SUPPORTED_SEVERITIES))}"
        )

    user = str(data["user"]).strip()

    if not user:
        raise ValueError("Incident user cannot be empty.")

    return Incident(
        incident_id=str(data["incident_id"]).strip(),
        incident_type=incident_type,
        severity=severity,
        user=user,
        source=str(data["source"]).strip(),
        description=str(data["description"]).strip(),
    )


# ---------------------------------------------------------------------------
# Response policy engine
# ---------------------------------------------------------------------------

def build_response_plan(incident: Incident) -> list[ResponseAction]:
    actions: list[ResponseAction] = []

    def add(
        action_id: str,
        category: str,
        action: str,
        reason: str,
    ) -> None:
        actions.append(
            ResponseAction(
                action_id=action_id,
                category=category,
                action=action,
                status="SIMULATED",
                simulation=True,
                reason=reason,
            )
        )

    # High-risk incidents receive account/session containment.
    if incident.severity in {"HIGH", "CRITICAL"}:
        add(
            "CON-001",
            "Containment",
            "Lock affected user account",
            "High or critical severity requires account containment.",
        )

        add(
            "CON-002",
            "Containment",
            "Revoke active sessions",
            "Limit the possibility of continued unauthorized access.",
        )

        add(
            "COM-001",
            "Communication",
            "Notify SOC team",
            "Security operations should be informed of significant incidents.",
        )

        add(
            "FOR-001",
            "Forensics",
            "Preserve relevant mail and authentication logs",
            "Preserve evidence before investigation and remediation.",
        )

    # Phishing-specific response.
    if incident.incident_type == "phishing":
        add(
            "PHI-001",
            "Containment",
            "Quarantine suspected phishing message",
            "Prevent additional interaction with the suspected message.",
        )

        add(
            "PHI-002",
            "Containment",
            "Block or review the sender domain",
            "Reduce the chance of repeated phishing delivery.",
        )

        add(
            "PHI-003",
            "Forensics",
            "Perform attachment and URL analysis in an isolated sandbox",
            "Identify potentially malicious content safely.",
        )

    # Credential-theft response.
    if incident.incident_type == "credential_theft":
        add(
            "CRE-001",
            "Containment",
            "Force credential reset through approved identity workflow",
            "Reduce the risk of credential reuse.",
        )

        add(
            "CRE-002",
            "Investigation",
            "Review authentication activity",
            "Identify suspicious authentication behavior.",
        )

    # Account-compromise response.
    if incident.incident_type == "account_compromise":
        add(
            "ACC-001",
            "Investigation",
            "Review recent account activity",
            "Identify unauthorized actions performed by the account.",
        )

        add(
            "ACC-002",
            "Recovery",
            "Verify account security settings",
            "Confirm that unauthorized changes have been removed.",
        )

    # Every incident receives documentation and lessons-learned tracking.
    add(
        "DOC-001",
        "Documentation",
        "Record incident timeline and response decisions",
        "Maintain an auditable incident record.",
    )

    add(
        "LL-001",
        "Lessons Learned",
        "Record follow-up actions and preventive recommendations",
        "Support post-incident improvement.",
    )

    return actions


# ---------------------------------------------------------------------------
# Simulated action execution
# ---------------------------------------------------------------------------

def execute_actions(actions: list[ResponseAction]) -> list[dict[str, Any]]:
    executed: list[dict[str, Any]] = []

    for action in actions:
        logging.info(
            "SIMULATED ACTION %s: %s",
            action.action_id,
            action.action,
        )

        executed.append(asdict(action))

    return executed


# ---------------------------------------------------------------------------
# Report generation
# ---------------------------------------------------------------------------

def build_report(
    incident: Incident,
    actions: list[dict[str, Any]],
    started_at: str,
) -> dict[str, Any]:

    return {
        "metadata": {
            "tool": TOOL_NAME,
            "version": TOOL_VERSION,
            "generated_utc": started_at,
            "mode": "simulation",
            "warning": (
                "No real security controls were modified. "
                "All response actions are simulated."
            ),
        },
        "incident": asdict(incident),
        "response": {
            "action_count": len(actions),
            "actions": actions,
        },
    }


def write_json_report(
    report: dict[str, Any],
    output_path: Path,
) -> None:

    output_path.parent.mkdir(parents=True, exist_ok=True)

    with output_path.open("w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2)


def write_text_report(
    report: dict[str, Any],
    output_path: Path,
) -> None:

    output_path.parent.mkdir(parents=True, exist_ok=True)

    incident = report["incident"]
    response = report["response"]

    lines = [
        "DAY 14 — SE INCIDENT RESPONSE AUTOMATION",
        "=" * 72,
        "",
        "MODE",
        "-" * 72,
        "SIMULATION ONLY",
        "",
        "INCIDENT",
        "-" * 72,
        f"Incident ID : {incident['incident_id']}",
        f"Type        : {incident['incident_type']}",
        f"Severity    : {incident['severity']}",
        f"User        : {incident['user']}",
        f"Source      : {incident['source']}",
        f"Description : {incident['description']}",
        "",
        "RESPONSE ACTIONS",
        "-" * 72,
    ]

    for index, action in enumerate(response["actions"], 1):
        lines.extend(
            [
                f"[{index}] {action['action_id']} — {action['category']}",
                f"Action     : {action['action']}",
                f"Status     : {action['status']}",
                f"Simulation : {action['simulation']}",
                f"Reason     : {action['reason']}",
                "",
            ]
        )

    lines.extend(
        [
            "=" * 72,
            "NOTE: This report documents simulated defensive response actions.",
            "No accounts, sessions, mailboxes, domains, or security controls",
            "were actually modified by this tool.",
            "=" * 72,
            "",
        ]
    )

    output_path.parent.mkdir(parents=True, exist_ok=True)

    output_path.write_text(
        "\n".join(lines),
        encoding="utf-8",
    )


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Defensive SE incident-response automation simulator."
        )
    )

    parser.add_argument(
        "-i",
        "--input",
        default="input/incidents.json",
        help="Input incident JSON file.",
    )

    parser.add_argument(
        "-j",
        "--json-output",
        default="output/ir_incident_report.json",
        help="JSON report output path.",
    )

    parser.add_argument(
        "-t",
        "--text-output",
        default="output/ir_summary.txt",
        help="Human-readable report output path.",
    )

    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose diagnostic logging.",
    )

    return parser.parse_args()


def load_incident(path: Path) -> dict[str, Any]:
    if not path.exists():
        raise FileNotFoundError(f"Input file not found: {path}")

    if not path.is_file():
        raise ValueError(f"Input path is not a file: {path}")

    try:
        with path.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
    except json.JSONDecodeError as exc:
        raise ValueError(
            f"Invalid JSON in {path}: {exc}"
        ) from exc

    if not isinstance(data, dict):
        raise ValueError("Incident JSON must contain one JSON object.")

    return data


def print_summary(
    incident: Incident,
    actions: list[dict[str, Any]],
) -> None:

    print()
    print("=" * 72)
    print("🛡  DAY 14 — SE INCIDENT RESPONSE AUTOMATION")
    print("=" * 72)
    print(f"Incident ID : {incident.incident_id}")
    print(f"Type        : {incident.incident_type}")
    print(f"Severity    : {incident.severity}")
    print(f"User        : {incident.user}")
    print(f"Source      : {incident.source}")
    print(f"Actions     : {len(actions)}")
    print("Mode        : SIMULATION ONLY")
    print()
    print("Response actions:")
    print("-" * 72)

    for index, action in enumerate(actions, 1):
        print(
            f"[{index}] {action['action_id']} "
            f"{action['category']:<15} "
            f"{action['action']}"
        )

    print("-" * 72)
    print("No real security controls were modified.")
    print("=" * 72)
    print()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    args = parse_arguments()
    configure_logging(args.verbose)

    started_at = datetime.now(timezone.utc).isoformat()

    try:
        input_path = Path(args.input)
        json_output = Path(args.json_output)
        text_output = Path(args.text_output)

        logging.info("Starting incident-response simulation")
        logging.info("Input: %s", input_path)

        raw_incident = load_incident(input_path)
        incident = validate_incident(raw_incident)

        logging.info(
            "Validated incident %s (%s / %s)",
            incident.incident_id,
            incident.incident_type,
            incident.severity,
        )

        response_plan = build_response_plan(incident)

        logging.info(
            "Generated %d response actions",
            len(response_plan),
        )

        actions = execute_actions(response_plan)

        report = build_report(
            incident=incident,
            actions=actions,
            started_at=started_at,
        )

        write_json_report(report, json_output)
        write_text_report(report, text_output)

        print_summary(incident, actions)

        print(f"[+] JSON report : {json_output}")
        print(f"[+] Text report : {text_output}")

        logging.info("Incident-response simulation completed successfully")

        return 0

    except (OSError, ValueError, FileNotFoundError) as exc:
        logging.error("%s", exc)
        return 1

    except KeyboardInterrupt:
        logging.warning("Interrupted by user.")
        return 130


if __name__ == "__main__":
    sys.exit(main())
