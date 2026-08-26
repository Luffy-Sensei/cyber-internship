REQUIRED_TOP_LEVEL_KEYS = {
    "metadata",
    "target",
    "scan_results",
    "service_results",
    "security_findings",
    "risk_summary",
    "topology",
}


def validate_report(report: dict) -> None:
    missing = REQUIRED_TOP_LEVEL_KEYS - report.keys()

    if missing:
        raise ValueError(
            f"Report is missing required fields: "
            f"{sorted(missing)}"
        )

    if not isinstance(report["scan_results"], list):
        raise ValueError(
            "scan_results must be a list"
        )

    if not isinstance(report["service_results"], list):
        raise ValueError(
            "service_results must be a list"
        )

    if not isinstance(report["security_findings"], list):
        raise ValueError(
            "security_findings must be a list"
        )

    if not isinstance(report["topology"], dict):
        raise ValueError(
            "topology must be an object"
        )
