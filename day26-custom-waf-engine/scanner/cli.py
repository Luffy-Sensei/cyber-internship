from __future__ import annotations

import argparse
import json
from pathlib import Path

from scanner.config import DEFAULT_WAF_POLICY, DEFAULT_WAF_RULES
from scanner.engine import WAFDetectionEngine
from scanner.logging import WAFAuditLogger
from scanner.models import HTTPRequest
from scanner.policies import WAFPolicyEngine
from scanner.reporting import WAFReportWriter
from scanner.rules import WAFRuleEngine


BASE_DIR = Path(__file__).resolve().parent.parent
DEFAULT_INPUT = BASE_DIR / "input" / "mock_requests.json"
DEFAULT_LOG = BASE_DIR / "output" / "logs" / "waf-audit.jsonl"
DEFAULT_JSON_REPORT = (
    BASE_DIR / "output" / "reports" / "day26-report.json"
)
DEFAULT_TEXT_REPORT = (
    BASE_DIR / "output" / "reports" / "day26-report.txt"
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Controlled Day 26 WAF inspection engine."
    )

    parser.add_argument(
        "--input",
        type=Path,
        default=DEFAULT_INPUT,
        help="Path to controlled JSON request fixtures.",
    )

    parser.add_argument(
        "--log",
        type=Path,
        default=DEFAULT_LOG,
        help="Path to JSONL audit log.",
    )

    parser.add_argument(
        "--json-report",
        type=Path,
        default=DEFAULT_JSON_REPORT,
        help="Path to JSON report.",
    )

    parser.add_argument(
        "--text-report",
        type=Path,
        default=DEFAULT_TEXT_REPORT,
        help="Path to TXT report.",
    )

    return parser.parse_args()


def load_requests(path: Path) -> tuple[HTTPRequest, ...]:
    if not path.exists():
        raise FileNotFoundError(
            f"Input fixture file not found: {path}"
        )

    with path.open(
        "r",
        encoding="utf-8",
    ) as handle:
        data = json.load(handle)

    if not isinstance(data, list):
        raise ValueError(
            "Input fixture must contain a JSON list."
        )

    requests: list[HTTPRequest] = []

    for item in data:
        if not isinstance(item, dict):
            raise ValueError(
                "Each request fixture must be a JSON object."
            )

        requests.append(
            HTTPRequest(
                request_id=item["request_id"],
                method=item["method"],
                path=item["path"],
                query=item.get("query", ""),
                headers=item.get("headers", {}),
                body=item.get("body", ""),
            )
        )

    return tuple(requests)


def run() -> int:
    args = parse_args()

    requests = load_requests(args.input)

    detection_engine = WAFDetectionEngine(
        WAFRuleEngine(DEFAULT_WAF_RULES)
    )

    policy_engine = WAFPolicyEngine(
        DEFAULT_WAF_POLICY
    )

    audit_logger = WAFAuditLogger(args.log)
    report_writer = WAFReportWriter()

    decisions = []

    print("=== DAY 26 CUSTOM WAF ENGINE ===")
    print(f"Input fixtures : {args.input}")
    print(f"Requests       : {len(requests)}")

    for request in requests:
        result = detection_engine.inspect(request)
        decision = policy_engine.decide(result)

        decisions.append(decision)

        audit_logger.log_decision(
            decision,
            method=request.method,
            path=request.path,
        )

        print(
            f"{request.request_id} | "
            f"{request.method} {request.path} | "
            f"Detections={result.detection_count} | "
            f"Action={decision.action.value}"
        )

    report = report_writer.build_report(
        tuple(decisions)
    )

    report_writer.write_json(
        report,
        args.json_report,
    )

    report_writer.write_text(
        report,
        args.text_report,
    )

    print()
    print("=== WAF SUMMARY ===")
    print(
        f"Requests processed : "
        f"{report['requests_processed']}"
    )
    print(f"Allowed            : {report['allowed']}")
    print(f"Monitored          : {report['monitored']}")
    print(f"Blocked            : {report['blocked']}")
    print(f"Detections         : {report['detections']}")

    print()
    print("Artifacts:")
    print(f"- {args.log}")
    print(f"- {args.json_report}")
    print(f"- {args.text_report}")

    return 0


def main() -> None:
    raise SystemExit(run())


if __name__ == "__main__":
    main()
