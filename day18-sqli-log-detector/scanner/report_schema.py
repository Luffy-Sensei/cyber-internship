REQUIRED_TOP_LEVEL_FIELDS = {
    "report_version",
    "run_id",
    "generated_at",
    "input_file",
    "statistics",
    "findings",
}


def validate_report(report: dict) -> None:
    """Validate the minimum Day 18 report structure."""

    missing = REQUIRED_TOP_LEVEL_FIELDS - report.keys()

    if missing:
        raise ValueError(
            f"Missing required report fields: "
            f"{sorted(missing)}"
        )

    statistics = report["statistics"]

    required_statistics = {
        "total_entries",
        "detections",
        "critical",
        "high",
        "medium",
        "low",
    }

    missing_statistics = (
        required_statistics - statistics.keys()
    )

    if missing_statistics:
        raise ValueError(
            "Missing required statistics fields: "
            f"{sorted(missing_statistics)}"
        )

    if not isinstance(report["findings"], list):
        raise ValueError(
            "Report findings must be a list."
        )
