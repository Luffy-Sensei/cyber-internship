import pytest

from scanner.report_schema import validate_report


def test_valid_report():
    report = {
        "metadata": {},
        "target": {},
        "scan_results": [],
        "service_results": [],
        "security_findings": [],
        "risk_summary": {},
        "topology": {},
    }

    validate_report(report)


def test_missing_required_field():
    report = {
        "metadata": {},
        "target": {},
        "scan_results": [],
        "service_results": [],
        "security_findings": [],
        "risk_summary": {},
    }

    with pytest.raises(ValueError):
        validate_report(report)


def test_invalid_scan_results_type():
    report = {
        "metadata": {},
        "target": {},
        "scan_results": {},
        "service_results": [],
        "security_findings": [],
        "risk_summary": {},
        "topology": {},
    }

    with pytest.raises(ValueError):
        validate_report(report)
