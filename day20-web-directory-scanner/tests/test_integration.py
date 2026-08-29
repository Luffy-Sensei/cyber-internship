import json

from scanner.detector import SecurityDetector
from scanner.models import PathResult
from scanner.reporting import ScanReporter
from scanner.risk import RiskAnalyzer


def test_full_scan_pipeline_to_json_and_text(tmp_path):
    # ---------------------------------------------------------
    # 1. Simulate a discovered sensitive web path
    # ---------------------------------------------------------
    result = PathResult(
        path=".env",
        url="http://127.0.0.1:5000/.env",
        status_code=200,
        response_length=128,
    )

    # ---------------------------------------------------------
    # 2. Detection
    # ---------------------------------------------------------
    detector = SecurityDetector()
    detections = detector.analyze(result)

    assert detections
    assert any(
        finding.rule_id == "SENSITIVE_EXPOSURE"
        for finding in detections
    )

    # ---------------------------------------------------------
    # 3. Risk analysis
    # ---------------------------------------------------------
    risk_analyzer = RiskAnalyzer()
    findings = []

    for finding in detections:
        risk = risk_analyzer.assess(finding)

        findings.append(
            {
                "rule_id": finding.rule_id,
                "path": finding.path,
                "url": finding.url,
                "status_code": finding.status_code,
                "message": finding.message,
                "evidence": finding.evidence,
                "severity": risk.severity,
                "score": risk.score,
                "classification": risk.classification,
                "recommendation": risk.recommendation,
            }
        )

    sensitive = next(
        finding
        for finding in findings
        if finding["rule_id"] == "SENSITIVE_EXPOSURE"
    )

    assert sensitive["severity"] == "CRITICAL"
    assert sensitive["score"] == 90
    assert sensitive["classification"] == "CRITICAL"
    assert sensitive["recommendation"]

    # ---------------------------------------------------------
    # 4. Reporting
    # ---------------------------------------------------------
    reporter = ScanReporter(
        target="http://127.0.0.1:5000",
        wordlist_size=5,
        requests_sent=5,
    )

    report = reporter.build_report(findings)

    # ---------------------------------------------------------
    # 5. Report metadata
    # ---------------------------------------------------------
    assert report["schema_version"] == "1.0"
    assert report["scan_id"]
    assert report["target"] == "http://127.0.0.1:5000"
    assert report["started_at"]
    assert report["completed_at"]
    assert report["duration_seconds"] >= 0
    assert report["wordlist_size"] == 5
    assert report["requests_sent"] == 5

    # ---------------------------------------------------------
    # 6. Report summary
    # ---------------------------------------------------------
    assert report["summary"]["total_findings"] == len(findings)
    assert report["summary"]["critical"] == 1

    # ---------------------------------------------------------
    # 7. JSON output
    # ---------------------------------------------------------
    json_path = tmp_path / "day20_integration.json"
    reporter.write_json(report, json_path)

    assert json_path.exists()

    loaded_json = json.loads(
        json_path.read_text(encoding="utf-8")
    )

    assert loaded_json["schema_version"] == "1.0"
    assert loaded_json["target"] == "http://127.0.0.1:5000"
    assert loaded_json["summary"]["critical"] == 1
    assert any(
        finding["rule_id"] == "SENSITIVE_EXPOSURE"
        for finding in loaded_json["findings"]
    )

    # ---------------------------------------------------------
    # 8. TXT output
    # ---------------------------------------------------------
    text_path = tmp_path / "day20_integration.txt"
    reporter.write_text(report, text_path)

    assert text_path.exists()

    text_output = text_path.read_text(encoding="utf-8")

    assert "DAY 20 - WEB DIRECTORY DISCOVERY SCAN" in text_output
    assert "SENSITIVE_EXPOSURE" in text_output
    assert "CRITICAL" in text_output
    assert ".env" in text_output
    assert "Remove sensitive files" in text_output
