from pathlib import Path

from scanner.models import (
    PortState,
    RiskLevel,
    ScanResult,
    SecurityFinding,
    ServiceResult,
)

from scanner.reporting import ReportWriter


def build_test_data():
    scan_results = [
        ScanResult(
            host="127.0.0.1",
            port=80,
            protocol="TCP",
            state=PortState.OPEN,
            latency_ms=1.2,
        )
    ]

    service_results = [
        ServiceResult(
            host="127.0.0.1",
            port=80,
            protocol="TCP",
            state=PortState.OPEN,
            service="HTTP",
            category="WEB",
            confidence="HIGH",
            detection_method="HTTP_PROBE",
            latency_ms=1.2,
            evidence="HTTP/1.1 200 OK",
        )
    ]

    findings = [
        SecurityFinding(
            host="127.0.0.1",
            port=80,
            service="HTTP",
            category="WEB",
            risk=RiskLevel.LOW,
            title="Web service exposed",
            description="HTTP is accepting TCP connections.",
            recommendation="Verify exposure is intentional.",
        )
    ]

    return scan_results, service_results, findings


def test_build_report(tmp_path: Path):
    writer = ReportWriter(tmp_path)

    scan_results, service_results, findings = (
        build_test_data()
    )

    report = writer.build_report(
        host="127.0.0.1",
        ports=(80,),
        timeout=1.0,
        scan_results=scan_results,
        service_results=service_results,
        findings=findings,
    )

    assert report["target"]["host"] == "127.0.0.1"
    assert len(report["service_results"]) == 1
    assert report["risk_summary"]["LOW"] == 1


def test_write_json(tmp_path: Path):
    writer = ReportWriter(tmp_path)

    scan_results, service_results, findings = (
        build_test_data()
    )

    report = writer.build_report(
        host="127.0.0.1",
        ports=(80,),
        timeout=1.0,
        scan_results=scan_results,
        service_results=service_results,
        findings=findings,
    )

    path = writer.write_json(report)

    assert path.exists()
    assert path.suffix == ".json"


def test_write_text(tmp_path: Path):
    writer = ReportWriter(tmp_path)

    scan_results, service_results, findings = (
        build_test_data()
    )

    report = writer.build_report(
        host="127.0.0.1",
        ports=(80,),
        timeout=1.0,
        scan_results=scan_results,
        service_results=service_results,
        findings=findings,
    )

    path = writer.write_text(report)

    assert path.exists()
    assert path.suffix == ".txt"

    content = path.read_text(
        encoding="utf-8"
    )

    assert "DAY 17" in content
    assert "127.0.0.1" in content
    assert "HTTP" in content
    assert "LOW" in content
