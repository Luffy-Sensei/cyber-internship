from __future__ import annotations

import json
import logging
from pathlib import Path

from .intelligence import analyze_payload
from .sanitizer import sanitize_user_input
from .validation import validate_payload


LOGGER = logging.getLogger("day21")


def load_payloads(path: str | Path) -> list[str]:
    """Load non-empty, non-comment payloads from a text file."""

    payload_file = Path(path)

    if not payload_file.is_file():
        raise FileNotFoundError(f"Payload file not found: {payload_file}")

    payloads: list[str] = []

    for line in payload_file.read_text(encoding="utf-8").splitlines():
        payload = line.strip()

        if not payload or payload.startswith("#"):
            continue

        payloads.append(payload)

    if not payloads:
        raise ValueError("Payload file contains no usable entries.")

    return payloads


def run_validation(
    payload_path: str | Path,
    report_path: str | Path,
) -> dict:
    """Execute adversarial validation and write a JSON evidence report."""

    payloads = load_payloads(payload_path)

    cases: list[dict] = []

    for index, payload in enumerate(payloads, start=1):
        LOGGER.info("Validating case %d", index)

        validation = validate_payload(payload)
        sanitizer_result = validation.sanitized_output

        # Re-run through the sanitizer result to provide contextual
        # intelligence for the evidence record.
        from .sanitizer import sanitize_user_input

        result = sanitize_user_input(payload)
        intelligence = analyze_payload(result)

        case = {
            "case_id": index,
            "payload": payload,
            "passed": validation.passed,
            "detected_tokens": validation.detected_tokens,
            "neutralized": validation.neutralized,
            "sanitized_output": sanitizer_result,
            "severity": intelligence.severity,
            "xss_model": intelligence.xss_model,
            "context": intelligence.context,
            "confidence": intelligence.confidence,
            "reason": validation.reason,
            "rationale": intelligence.rationale,
        }

        cases.append(case)

        LOGGER.info(
            "Case %d result=%s severity=%s tokens=%s",
            index,
            "PASS" if validation.passed else "FAIL",
            intelligence.severity,
            ",".join(validation.detected_tokens) or "NONE",
        )

    passed = sum(1 for case in cases if case["passed"])
    failed = len(cases) - passed

    report = {
        "schema_version": "1.0",
        "tool": "Day 21 XSS Payload Sanitizer",
        "validation_type": "adversarial_payload_validation",
        "payload_count": len(cases),
        "passed": passed,
        "failed": failed,
        "all_passed": failed == 0,
        "cases": cases,
    }

    output = Path(report_path)
    output.parent.mkdir(parents=True, exist_ok=True)

    output.write_text(
        json.dumps(report, indent=2),
        encoding="utf-8",
    )

    LOGGER.info(
        "Validation complete: cases=%d passed=%d failed=%d",
        len(cases),
        passed,
        failed,
    )

    LOGGER.info("Evidence report written to %s", output)

    return report
