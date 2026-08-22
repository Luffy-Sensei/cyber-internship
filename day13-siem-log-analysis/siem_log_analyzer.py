#!/usr/bin/env python3
"""
Day 13 — SIEM Log Analyzer v2

Defensive log-analysis tool for detecting authentication and
social-engineering-related anomalies.

Architecture:
    Input -> Parser -> Detection Engine -> Correlation -> Reporters

Supported event types:
    FAILED_LOGIN
    SUCCESS_LOGIN
    EMAIL_RULE_CREATED

Detection rules:
    AUTH-001  Repeated failed authentication attempts
    AUTH-002  Successful login following repeated failures
    AUTH-003  Authentication during unusual hours
    AUTH-004  Multiple source IPs observed for a user
    MAIL-001  Suspicious email forwarding rule created

This tool is intended for authorized defensive security analysis.
"""

from __future__ import annotations

import argparse
import json
import logging
import re
import sys

from collections import Counter, defaultdict
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterable, Optional


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

TOOL_NAME = "Day 13 SIEM Log Analyzer"
TOOL_VERSION = "2.0.0"

DEFAULT_INPUT = Path("input/security.log")
DEFAULT_JSON_OUTPUT = Path("output/siem_alerts.json")
DEFAULT_TEXT_OUTPUT = Path("output/siem_summary.txt")

DEFAULT_FAILED_THRESHOLD = 3
DEFAULT_UNUSUAL_START = 0
DEFAULT_UNUSUAL_END = 5
DEFAULT_CORRELATION_MINUTES = 5

SEVERITY_ORDER = {
    "CRITICAL": 0,
    "HIGH": 1,
    "MEDIUM": 2,
    "LOW": 3,
}

SUPPORTED_EVENTS = {
    "FAILED_LOGIN",
    "SUCCESS_LOGIN",
    "EMAIL_RULE_CREATED",
}

SUSPICIOUS_MAIL_RULES = {
    "forward_all",
    "forward_external",
    "forward_all_external",
    "auto_forward",
    "external_forward",
}

LOG_PATTERN = re.compile(
    r"""
    ^
    (?P<timestamp>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})
    \s+
    (?P<event_type>[A-Z_]+)
    \s+
    user=(?P<user>[^\s]+)
    (?:\s+ip=(?P<ip>[^\s]+))?
    (?:\s+rule=(?P<rule>[^\s]+))?
    \s*$
    """,
    re.VERBOSE,
)


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class SecurityEvent:
    """Normalized representation of a parsed security-log event."""

    timestamp: datetime
    event_type: str
    user: str
    ip: Optional[str]
    rule: Optional[str]
    raw: str
    line_number: int

    def iso_timestamp(self) -> str:
        return self.timestamp.isoformat()


@dataclass
class Alert:
    """Detection alert produced by the detection engine."""

    timestamp: str
    severity: str
    rule_id: str
    title: str
    description: str
    user: Optional[str]
    ip: Optional[str]
    evidence: list[str]


@dataclass
class ParseResult:
    """Parser output including valid events and malformed lines."""

    events: list[SecurityEvent]
    malformed_lines: list[dict]


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

def configure_logging(verbose: bool) -> None:
    """Configure application logging."""

    level = logging.DEBUG if verbose else logging.INFO

    logging.basicConfig(
        level=level,
        format="%(asctime)s - %(levelname)s - %(message)s",
    )


LOGGER = logging.getLogger(TOOL_NAME)


# ---------------------------------------------------------------------------
# Timestamp helpers
# ---------------------------------------------------------------------------

def parse_timestamp(value: str) -> datetime:
    """
    Parse a log timestamp.

    Input logs are treated as UTC because the sample format does not contain
    an explicit timezone.
    """

    parsed = datetime.strptime(value, "%Y-%m-%d %H:%M:%S")
    return parsed.replace(tzinfo=timezone.utc)


def utc_now() -> datetime:
    """Return the current UTC timestamp."""

    return datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# Parser layer
# ---------------------------------------------------------------------------

class SecurityLogParser:
    """Parser for the normalized key/value security-log format."""

    def parse_file(self, path: Path) -> ParseResult:
        """Read and parse a log file."""

        if not path.exists():
            raise FileNotFoundError(f"Input file does not exist: {path}")

        if not path.is_file():
            raise ValueError(f"Input path is not a regular file: {path}")

        events: list[SecurityEvent] = []
        malformed_lines: list[dict] = []

        with path.open("r", encoding="utf-8", errors="replace") as handle:
            for line_number, raw_line in enumerate(handle, start=1):
                line = raw_line.strip()

                if not line:
                    continue

                event = self.parse_line(line, line_number)

                if event is None:
                    malformed_lines.append(
                        {
                            "line_number": line_number,
                            "content": line,
                        }
                    )

                    LOGGER.warning(
                        "Skipping malformed line %d: %s",
                        line_number,
                        line,
                    )
                    continue

                events.append(event)

        events.sort(key=lambda event: event.timestamp)

        return ParseResult(
            events=events,
            malformed_lines=malformed_lines,
        )

    def parse_line(
        self,
        line: str,
        line_number: int,
    ) -> Optional[SecurityEvent]:
        """Parse one security-log line."""

        match = LOG_PATTERN.match(line)

        if not match:
            return None

        event_type = match.group("event_type")

        if event_type not in SUPPORTED_EVENTS:
            return None

        try:
            timestamp = parse_timestamp(match.group("timestamp"))
        except ValueError:
            return None

        user = match.group("user")
        ip = match.group("ip")
        rule = match.group("rule")

        if not user:
            return None

        if event_type == "EMAIL_RULE_CREATED" and not rule:
            return None

        if event_type != "EMAIL_RULE_CREATED" and rule:
            return None

        return SecurityEvent(
            timestamp=timestamp,
            event_type=event_type,
            user=user,
            ip=ip,
            rule=rule,
            raw=line,
            line_number=line_number,
        )


# ---------------------------------------------------------------------------
# Detection engine
# ---------------------------------------------------------------------------

class DetectionEngine:
    """
    Detection engine for authentication and mail-rule anomalies.

    The engine works on normalized SecurityEvent objects rather than raw
    strings, making it easier to add additional parsers later.
    """

    def __init__(
        self,
        failed_threshold: int = DEFAULT_FAILED_THRESHOLD,
        unusual_start: int = DEFAULT_UNUSUAL_START,
        unusual_end: int = DEFAULT_UNUSUAL_END,
        correlation_minutes: int = DEFAULT_CORRELATION_MINUTES,
    ) -> None:

        if failed_threshold < 1:
            raise ValueError("failed_threshold must be >= 1")

        if not 0 <= unusual_start <= 23:
            raise ValueError("unusual_start must be between 0 and 23")

        if not 0 <= unusual_end <= 23:
            raise ValueError("unusual_end must be between 0 and 23")

        if correlation_minutes < 1:
            raise ValueError("correlation_minutes must be >= 1")

        self.failed_threshold = failed_threshold
        self.unusual_start = unusual_start
        self.unusual_end = unusual_end
        self.correlation_window = timedelta(minutes=correlation_minutes)

    def analyze(self, events: list[SecurityEvent]) -> list[Alert]:
        """Run all detection rules."""

        if not events:
            return []

        alerts: list[Alert] = []

        alerts.extend(self.detect_repeated_failures(events))
        alerts.extend(self.detect_success_after_failures(events))
        alerts.extend(self.detect_unusual_hours(events))
        alerts.extend(self.detect_multiple_source_ips(events))
        alerts.extend(self.detect_suspicious_mail_rules(events))

        return self._sort_alerts(alerts)

    # ------------------------------------------------------------------
    # AUTH-001
    # ------------------------------------------------------------------

    def detect_repeated_failures(
        self,
        events: list[SecurityEvent],
    ) -> list[Alert]:
        """Detect users exceeding the failed-login threshold."""

        failures_by_user: dict[str, list[SecurityEvent]] = defaultdict(list)

        for event in events:
            if event.event_type == "FAILED_LOGIN":
                failures_by_user[event.user].append(event)

        alerts: list[Alert] = []

        for user, failures in failures_by_user.items():
            if len(failures) < self.failed_threshold:
                continue

            selected = failures[: self.failed_threshold]
            latest = selected[-1]

            alerts.append(
                Alert(
                    timestamp=latest.iso_timestamp(),
                    severity="HIGH",
                    rule_id="AUTH-001",
                    title="Repeated failed authentication attempts",
                    description=(
                        f"User '{user}' generated {len(failures)} failed "
                        f"login attempts, meeting or exceeding the "
                        f"configured threshold of "
                        f"{self.failed_threshold}."
                    ),
                    user=user,
                    ip=None,
                    evidence=[event.raw for event in selected],
                )
            )

        return alerts

    # ------------------------------------------------------------------
    # AUTH-002
    # ------------------------------------------------------------------

    def detect_success_after_failures(
        self,
        events: list[SecurityEvent],
    ) -> list[Alert]:
        """
        Detect successful authentication shortly after repeated failures.

        Correlation is performed per user and within the configured time
        window. Only the immediately preceding failure sequence is considered.
        """

        alerts: list[Alert] = []

        events_by_user: dict[str, list[SecurityEvent]] = defaultdict(list)

        for event in events:
            if event.event_type in {"FAILED_LOGIN", "SUCCESS_LOGIN"}:
                events_by_user[event.user].append(event)

        for user, user_events in events_by_user.items():
            user_events.sort(key=lambda event: event.timestamp)

            for index, event in enumerate(user_events):
                if event.event_type != "SUCCESS_LOGIN":
                    continue

                failures: list[SecurityEvent] = []

                for previous in reversed(user_events[:index]):
                    delta = event.timestamp - previous.timestamp

                    if delta > self.correlation_window:
                        break

                    if previous.event_type == "SUCCESS_LOGIN":
                        break

                    if previous.event_type == "FAILED_LOGIN":
                        failures.append(previous)

                if len(failures) < self.failed_threshold:
                    continue

                failures.reverse()

                evidence_events = failures + [event]

                alerts.append(
                    Alert(
                        timestamp=event.iso_timestamp(),
                        severity="CRITICAL",
                        rule_id="AUTH-002",
                        title="Successful login following repeated failures",
                        description=(
                            f"User '{user}' successfully logged in after "
                            f"{len(failures)} failed authentication attempts "
                            f"within {self.correlation_window.total_seconds() / 60:.0f} "
                            f"minutes."
                        ),
                        user=user,
                        ip=event.ip,
                        evidence=[
                            evidence_event.raw
                            for evidence_event in evidence_events
                        ],
                    )
                )

        return alerts

    # ------------------------------------------------------------------
    # AUTH-003
    # ------------------------------------------------------------------

    def detect_unusual_hours(
        self,
        events: list[SecurityEvent],
    ) -> list[Alert]:
        """
        Detect authentication activity during unusual hours.

        Reduced-noise behavior:
        - One alert per user per calendar hour.
        - Multiple events in the same hour are combined as evidence.
        """

        grouped: dict[tuple[str, str], list[SecurityEvent]] = defaultdict(list)

        for event in events:
            if event.event_type not in {
                "FAILED_LOGIN",
                "SUCCESS_LOGIN",
            }:
                continue

            hour = event.timestamp.hour

            if self._is_unusual_hour(hour):
                key = (
                    event.user,
                    event.timestamp.strftime("%Y-%m-%d-%H"),
                )
                grouped[key].append(event)

        alerts: list[Alert] = []

        for (user, _), group in grouped.items():
            group.sort(key=lambda event: event.timestamp)

            first = group[0]

            alerts.append(
                Alert(
                    timestamp=first.iso_timestamp(),
                    severity="MEDIUM",
                    rule_id="AUTH-003",
                    title="Authentication during unusual hours",
                    description=(
                        f"Authentication activity for user '{user}' "
                        f"occurred during the configured unusual-hour "
                        f"window ({self.unusual_start:02d}:00-"
                        f"{self.unusual_end:02d}:00)."
                    ),
                    user=user,
                    ip=first.ip,
                    evidence=[event.raw for event in group],
                )
            )

        return alerts

    def _is_unusual_hour(self, hour: int) -> bool:
        """Determine whether an hour falls inside the configured window."""

        if self.unusual_start == self.unusual_end:
            return True

        if self.unusual_start < self.unusual_end:
            return self.unusual_start <= hour < self.unusual_end

        # Supports windows crossing midnight, e.g. 22:00 -> 05:00.
        return hour >= self.unusual_start or hour < self.unusual_end

    # ------------------------------------------------------------------
    # AUTH-004
    # ------------------------------------------------------------------

    def detect_multiple_source_ips(
        self,
        events: list[SecurityEvent],
    ) -> list[Alert]:
        """Detect users authenticating from multiple source IP addresses."""

        ips_by_user: dict[str, set[str]] = defaultdict(set)
        latest_event_by_user: dict[str, SecurityEvent] = {}

        for event in events:
            if event.event_type not in {
                "FAILED_LOGIN",
                "SUCCESS_LOGIN",
            }:
                continue

            if not event.ip:
                continue

            ips_by_user[event.user].add(event.ip)

            current = latest_event_by_user.get(event.user)

            if current is None or event.timestamp > current.timestamp:
                latest_event_by_user[event.user] = event

        alerts: list[Alert] = []

        for user, ips in ips_by_user.items():
            if len(ips) < 2:
                continue

            latest = latest_event_by_user[user]

            alerts.append(
                Alert(
                    timestamp=latest.iso_timestamp(),
                    severity="MEDIUM",
                    rule_id="AUTH-004",
                    title="Multiple source IPs observed for user",
                    description=(
                        f"User '{user}' authenticated from {len(ips)} "
                        f"different source IP addresses."
                    ),
                    user=user,
                    ip=None,
                    evidence=sorted(ips),
                )
            )

        return alerts

    # ------------------------------------------------------------------
    # MAIL-001
    # ------------------------------------------------------------------

    def detect_suspicious_mail_rules(
        self,
        events: list[SecurityEvent],
    ) -> list[Alert]:
        """Detect potentially suspicious email forwarding rules."""

        alerts: list[Alert] = []

        for event in events:
            if event.event_type != "EMAIL_RULE_CREATED":
                continue

            rule = (event.rule or "").lower()

            if rule not in SUSPICIOUS_MAIL_RULES:
                continue

            alerts.append(
                Alert(
                    timestamp=event.iso_timestamp(),
                    severity="HIGH",
                    rule_id="MAIL-001",
                    title="Suspicious email forwarding rule created",
                    description=(
                        f"User '{event.user}' created the potentially "
                        f"suspicious email rule '{event.rule}'."
                    ),
                    user=event.user,
                    ip=event.ip,
                    evidence=[event.raw],
                )
            )

        return alerts

    # ------------------------------------------------------------------
    # Alert ordering
    # ------------------------------------------------------------------

    @staticmethod
    def _sort_alerts(alerts: list[Alert]) -> list[Alert]:
        """Sort alerts consistently by severity and timestamp."""

        return sorted(
            alerts,
            key=lambda alert: (
                SEVERITY_ORDER.get(alert.severity, 99),
                alert.timestamp,
                alert.rule_id,
            ),
        )


# ---------------------------------------------------------------------------
# Reporting layer
# ---------------------------------------------------------------------------

class ReportWriter:
    """Generate machine-readable and human-readable reports."""

    def write_json(
        self,
        path: Path,
        input_path: Path,
        events: list[SecurityEvent],
        malformed_lines: list[dict],
        alerts: list[Alert],
        analysis_timestamp: datetime,
        configuration: dict,
    ) -> None:
        """Write structured JSON output."""

        path.parent.mkdir(parents=True, exist_ok=True)

        event_types = Counter(event.event_type for event in events)
        severity_counts = Counter(alert.severity for alert in alerts)
        rule_counts = Counter(alert.rule_id for alert in alerts)

        document = {
            "schema_version": "2.0",
            "metadata": {
                "tool": TOOL_NAME,
                "version": TOOL_VERSION,
                "input_file": str(input_path),
                "analysis_timestamp_utc": analysis_timestamp.isoformat(),
            },
            "configuration": configuration,
            "statistics": {
                "total_events": len(events),
                "malformed_lines": len(malformed_lines),
                "total_alerts": len(alerts),
                "event_types": dict(sorted(event_types.items())),
                "severity_counts": dict(
                    sorted(
                        severity_counts.items(),
                        key=lambda item: SEVERITY_ORDER.get(item[0], 99),
                    )
                ),
                "rule_counts": dict(sorted(rule_counts.items())),
            },
            "malformed_lines": malformed_lines,
            "alerts": [asdict(alert) for alert in alerts],
        }

        with path.open("w", encoding="utf-8") as handle:
            json.dump(document, handle, indent=2)
            handle.write("\n")

    def write_text(
        self,
        path: Path,
        input_path: Path,
        events: list[SecurityEvent],
        malformed_lines: list[dict],
        alerts: list[Alert],
        analysis_timestamp: datetime,
        configuration: dict,
    ) -> None:
        """Write human-readable text output."""

        path.parent.mkdir(parents=True, exist_ok=True)

        event_types = Counter(event.event_type for event in events)
        severity_counts = Counter(alert.severity for alert in alerts)
        rule_counts = Counter(alert.rule_id for alert in alerts)

        lines: list[str] = [
            "DAY 13 — SIEM LOG ANALYSIS v2",
            "=" * 72,
            "",
            f"Tool version     : {TOOL_VERSION}",
            f"Input file       : {input_path}",
            f"Analysis time    : {analysis_timestamp.isoformat()}",
            "",
            "CONFIGURATION",
            "-" * 72,
            f"Failed threshold : {configuration['failed_threshold']}",
            f"Unusual window   : "
            f"{configuration['unusual_start']:02d}:00-"
            f"{configuration['unusual_end']:02d}:00",
            f"Correlation      : {configuration['correlation_minutes']} minutes",
            "",
            "STATISTICS",
            "-" * 72,
            f"Total events     : {len(events)}",
            f"Malformed lines  : {len(malformed_lines)}",
            f"Total alerts     : {len(alerts)}",
            "",
            "EVENT TYPES",
            "-" * 72,
        ]

        if event_types:
            for name, count in sorted(event_types.items()):
                lines.append(f"{name:<30} {count}")
        else:
            lines.append("No supported events detected.")

        lines.extend(
            [
                "",
                "ALERT SEVERITY",
                "-" * 72,
            ]
        )

        for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            if severity_counts.get(severity):
                lines.append(
                    f"{severity:<30} {severity_counts[severity]}"
                )

        lines.extend(
            [
                "",
                "DETECTION RULES",
                "-" * 72,
            ]
        )

        if rule_counts:
            for rule_id, count in sorted(rule_counts.items()):
                lines.append(f"{rule_id:<30} {count}")
        else:
            lines.append("No detection rules triggered.")

        lines.extend(
            [
                "",
                "ALERT DETAILS",
                "-" * 72,
                "",
            ]
        )

        if not alerts:
            lines.append("No alerts generated.")
            lines.append("")

        for index, alert in enumerate(alerts, start=1):
            lines.extend(
                [
                    f"[{index}] {alert.severity} — {alert.rule_id}",
                    f"Title       : {alert.title}",
                    f"Timestamp   : {alert.timestamp}",
                    f"User        : {alert.user or 'N/A'}",
                    f"IP          : {alert.ip or 'N/A'}",
                    f"Description : {alert.description}",
                    "Evidence:",
                ]
            )

            for evidence in alert.evidence:
                lines.append(f"- {evidence}")

            lines.append("")

        if malformed_lines:
            lines.extend(
                [
                    "MALFORMED LINES",
                    "-" * 72,
                ]
            )

            for item in malformed_lines:
                lines.append(
                    f"Line {item['line_number']}: {item['content']}"
                )

            lines.append("")

        lines.extend(
            [
                "=" * 72,
                "NOTE: Alerts are detection signals and require analyst validation.",
                "=" * 72,
            ]
        )

        with path.open("w", encoding="utf-8") as handle:
            handle.write("\n".join(lines) + "\n")


# ---------------------------------------------------------------------------
# CLI / application layer
# ---------------------------------------------------------------------------

def build_argument_parser() -> argparse.ArgumentParser:
    """Build the command-line argument parser."""

    parser = argparse.ArgumentParser(
        description=(
            "Defensive SIEM-style log analyzer for detecting "
            "authentication and social-engineering-related anomalies."
        )
    )

    parser.add_argument(
        "-i",
        "--input",
        default=str(DEFAULT_INPUT),
        help=f"Input log file (default: {DEFAULT_INPUT})",
    )

    parser.add_argument(
        "-j",
        "--json-output",
        default=str(DEFAULT_JSON_OUTPUT),
        help=f"JSON report path (default: {DEFAULT_JSON_OUTPUT})",
    )

    parser.add_argument(
        "-t",
        "--text-output",
        default=str(DEFAULT_TEXT_OUTPUT),
        help=f"Human-readable report path (default: {DEFAULT_TEXT_OUTPUT})",
    )

    parser.add_argument(
        "--failed-threshold",
        type=int,
        default=DEFAULT_FAILED_THRESHOLD,
        help=(
            "Failed-login threshold for authentication detections "
            f"(default: {DEFAULT_FAILED_THRESHOLD})"
        ),
    )

    parser.add_argument(
        "--unusual-start",
        type=int,
        default=DEFAULT_UNUSUAL_START,
        help=(
            "Start hour for unusual login detection "
            f"(default: {DEFAULT_UNUSUAL_START})"
        ),
    )

    parser.add_argument(
        "--unusual-end",
        type=int,
        default=DEFAULT_UNUSUAL_END,
        help=(
            "End hour for unusual login detection "
            f"(default: {DEFAULT_UNUSUAL_END})"
        ),
    )

    parser.add_argument(
        "--correlation-minutes",
        type=int,
        default=DEFAULT_CORRELATION_MINUTES,
        help=(
            "Failure-to-success correlation window in minutes "
            f"(default: {DEFAULT_CORRELATION_MINUTES})"
        ),
    )

    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose diagnostic logging.",
    )

    return parser


def validate_arguments(args: argparse.Namespace) -> None:
    """Validate CLI configuration."""

    if args.failed_threshold < 1:
        raise ValueError("--failed-threshold must be >= 1")

    if not 0 <= args.unusual_start <= 23:
        raise ValueError("--unusual-start must be between 0 and 23")

    if not 0 <= args.unusual_end <= 23:
        raise ValueError("--unusual-end must be between 0 and 23")

    if args.correlation_minutes < 1:
        raise ValueError("--correlation-minutes must be >= 1")


def print_console_summary(
    events: list[SecurityEvent],
    malformed_lines: list[dict],
    alerts: list[Alert],
    json_path: Path,
    text_path: Path,
) -> None:
    """Print concise analyst-oriented console output."""

    severity_counts = Counter(alert.severity for alert in alerts)

    print()
    print("=" * 72)
    print("🛡  DAY 13 — SIEM LOG ANALYSIS v2")
    print("=" * 72)
    print(f"Events analyzed : {len(events)}")
    print(f"Malformed lines : {len(malformed_lines)}")
    print(f"Alerts generated: {len(alerts)}")
    print()

    print("Alert severity:")

    for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        count = severity_counts.get(severity, 0)

        if count:
            print(f"{severity:<10}: {count}")

    print()
    print("Detection results:")
    print("-" * 72)

    if not alerts:
        print("No detection alerts generated.")
    else:
        for index, alert in enumerate(alerts, start=1):
            print(
                f"[{index}] {alert.severity:<8} "
                f"{alert.rule_id:<8} {alert.title}"
            )

            if alert.user:
                print(f"User: {alert.user}")

            if alert.ip:
                print(f"IP  : {alert.ip}")

    print()
    print("-" * 72)
    print(f"[+] JSON report : {json_path}")
    print(f"[+] Text report : {text_path}")
    print("=" * 72)
    print()


def run(args: argparse.Namespace) -> int:
    """Execute the complete analysis pipeline."""

    input_path = Path(args.input)
    json_path = Path(args.json_output)
    text_path = Path(args.text_output)

    LOGGER.info("Starting SIEM log analysis v%s", TOOL_VERSION)
    LOGGER.info("Input: %s", input_path)

    parser = SecurityLogParser()

    parse_result = parser.parse_file(input_path)

    LOGGER.info(
        "Parsed %d security events",
        len(parse_result.events),
    )

    if LOGGER.isEnabledFor(logging.DEBUG):
        LOGGER.debug(
            "Malformed lines: %d",
            len(parse_result.malformed_lines),
        )

    detector = DetectionEngine(
        failed_threshold=args.failed_threshold,
        unusual_start=args.unusual_start,
        unusual_end=args.unusual_end,
        correlation_minutes=args.correlation_minutes,
    )

    alerts = detector.analyze(parse_result.events)

    LOGGER.info(
        "Generated %d detection alerts",
        len(alerts),
    )

    analysis_timestamp = utc_now()

    configuration = {
        "failed_threshold": args.failed_threshold,
        "unusual_start": args.unusual_start,
        "unusual_end": args.unusual_end,
        "correlation_minutes": args.correlation_minutes,
    }

    writer = ReportWriter()

    writer.write_json(
        path=json_path,
        input_path=input_path,
        events=parse_result.events,
        malformed_lines=parse_result.malformed_lines,
        alerts=alerts,
        analysis_timestamp=analysis_timestamp,
        configuration=configuration,
    )

    writer.write_text(
        path=text_path,
        input_path=input_path,
        events=parse_result.events,
        malformed_lines=parse_result.malformed_lines,
        alerts=alerts,
        analysis_timestamp=analysis_timestamp,
        configuration=configuration,
    )

    print_console_summary(
        events=parse_result.events,
        malformed_lines=parse_result.malformed_lines,
        alerts=alerts,
        json_path=json_path,
        text_path=text_path,
    )

    LOGGER.info("Analysis completed successfully")

    return 0


def main() -> int:
    """Application entry point."""

    argument_parser = build_argument_parser()
    args = argument_parser.parse_args()

    configure_logging(args.verbose)

    try:
        validate_arguments(args)
        return run(args)

    except FileNotFoundError as exc:
        LOGGER.error("%s", exc)
        return 2

    except (OSError, ValueError) as exc:
        LOGGER.error("%s", exc)
        return 2

    except KeyboardInterrupt:
        LOGGER.warning("Analysis interrupted by user")
        return 130

    except Exception:
        LOGGER.exception("Unexpected error during analysis")
        return 1


if __name__ == "__main__":
    sys.exit(main())
