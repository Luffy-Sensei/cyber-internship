from __future__ import annotations

from typing import Any


REQUIRED_TOP_LEVEL_FIELDS = {
    "schema_version",
    "scan_id",
    "target",
    "started_at",
    "completed_at",
    "duration_seconds",
    "wordlist_size",
    "requests_sent",
    "findings",
    "summary",
}


def validate_report(report: dict[str, Any]) -> tuple[bool, list[str]]:
    """
    Validate the structural contract of a Day 20 JSON report.

    Returns:
        (True, []) when valid.
        (False, errors) when validation fails.
    """
    errors: list[str] = []

    if not isinstance(report, dict):
        return False, ["Report must be a dictionary."]

    missing = REQUIRED_TOP_LEVEL_FIELDS - report.keys()
    if missing:
        errors.append(
            "Missing required fields: "
            + ", ".join(sorted(missing))
        )

    if "findings" in report and not isinstance(report["findings"], list):
        errors.append("'findings' must be a list.")

    if "summary" in report and not isinstance(report["summary"], dict):
        errors.append("'summary' must be an object.")

    for field in (
        "scan_id",
        "target",
        "started_at",
        "completed_at",
    ):
        if field in report and not isinstance(report[field], str):
            errors.append(f"'{field}' must be a string.")

    for field in (
        "duration_seconds",
        "wordlist_size",
        "requests_sent",
    ):
        if field in report and not isinstance(
            report[field], (int, float)
        ):
            errors.append(f"'{field}' must be numeric.")

    return not errors, errors
