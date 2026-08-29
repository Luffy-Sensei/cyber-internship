from pathlib import Path

from scanner.reporting import ScanReporter
from scanner.report_schema import validate_report


def sample_findings():
    return [
        {
            "rule_id": "SENSITIVE_EXPOSURE",
            "severity": "HIGH",
            "path": "/.env",
            "status_code": 200,
            "evidence": "Sensitive file returned HTTP 200.",
            "recommendation": "Remove sensitive files from the web root.",
        },
        {
            "rule_id": "ADMIN_ENDPOINT",
            "severity": "MEDIUM",
            "path": "/admin",
            "status_code": 403,
            "evidence": "Administrative route returned HTTP 403.",
            "recommendation": "Restrict administrative routes with authentication.",
        },
    ]


def test_report_contains_required_metadata():
    reporter = ScanReporter(
        target="http://127.0.0.1:5000",
        wordlist_size=5,
        requests_sent=5,
    )

    report = reporter.build_report(sample_findings())

    assert report["schema_version"] == "1.0"
    assert report["scan_id"]
    assert report["target"] == "http://127.0.0.1:5000"
    assert report["started_at"]
    assert report["completed_at"]
    assert report["duration_seconds"] >= 0
    assert report["wordlist_size"] == 5
    assert report["requests_sent"] == 5


def test_report_summary_counts_severity():
    reporter = ScanReporter(
        target="http://127.0.0.1:5000",
        wordlist_size=5,
        requests_sent=5,
    )

    report = reporter.build_report(sample_findings())

    assert report["summary"]["total_findings"] == 2
    assert report["summary"]["high"] == 1
    assert report["summary"]["medium"] == 1
    assert report["summary"]["critical"] == 0
    assert report["summary"]["low"] == 0


def test_report_schema_accepts_valid_report():
    reporter = ScanReporter(
        target="http://127.0.0.1:5000",
        wordlist_size=5,
        requests_sent=5,
    )

    report = reporter.build_report(sample_findings())

    valid, errors = validate_report(report)

    assert valid is True
    assert errors == []


def test_report_schema_rejects_missing_field():
    reporter = ScanReporter(
        target="http://127.0.0.1:5000",
        wordlist_size=5,
        requests_sent=5,
    )

    report = reporter.build_report(sample_findings())
    del report["scan_id"]

    valid, errors = validate_report(report)

    assert valid is False
    assert "Missing required fields: scan_id" in errors


def test_json_report_is_written(tmp_path: Path):
    reporter = ScanReporter(
        target="http://127.0.0.1:5000",
        wordlist_size=5,
        requests_sent=5,
    )

    report = reporter.build_report(sample_findings())
    output = tmp_path / "reports" / "scan.json"

    reporter.write_json(report, output)

    assert output.exists()
    assert output.stat().st_size > 0


def test_text_report_is_written(tmp_path: Path):
    reporter = ScanReporter(
        target="http://127.0.0.1:5000",
        wordlist_size=5,
        requests_sent=5,
    )

    report = reporter.build_report(sample_findings())
    output = tmp_path / "reports" / "scan.txt"

    reporter.write_text(report, output)

    assert output.exists()
    assert output.stat().st_size > 0

    content = output.read_text(encoding="utf-8")

    assert "DAY 20 - WEB DIRECTORY DISCOVERY SCAN" in content
    assert "SENSITIVE_EXPOSURE" in content
    assert "http://127.0.0.1:5000" in content


def test_empty_findings_generate_clean_report():
    reporter = ScanReporter(
        target="http://127.0.0.1:5000",
        wordlist_size=0,
        requests_sent=0,
    )

    report = reporter.build_report([])

    assert report["findings"] == []
    assert report["summary"]["total_findings"] == 0
    assert report["summary"]["critical"] == 0
    assert report["summary"]["high"] == 0
    assert report["summary"]["medium"] == 0
    assert report["summary"]["low"] == 0
