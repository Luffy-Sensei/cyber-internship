from scanner.detector import SecurityDetector
from scanner.parser import DockerfileParser
from scanner.reporting import ReportWriter


def build_findings(tmp_path):
    dockerfile = tmp_path / "Dockerfile"

    dockerfile.write_text(
        """
FROM python:latest
EXPOSE 22
""",
        encoding="utf-8",
    )

    parser = DockerfileParser()
    document = parser.parse_file(str(dockerfile))

    findings = SecurityDetector().analyze(document)

    return findings


def test_report_contains_required_fields(tmp_path):
    findings = build_findings(tmp_path)

    report = ReportWriter().build_report(
        input_file="Dockerfile",
        findings=findings,
    )

    assert "run_id" in report
    assert "generated_at" in report
    assert "statistics" in report
    assert "findings" in report


def test_report_statistics(tmp_path):
    findings = build_findings(tmp_path)

    report = ReportWriter().build_report(
        input_file="Dockerfile",
        findings=findings,
    )

    assert report["statistics"]["findings"] == 3
    assert report["statistics"]["critical"] == 1
    assert report["statistics"]["high"] == 1
    assert report["statistics"]["medium"] == 1
    assert report["statistics"]["low"] == 0


def test_json_report_written(tmp_path):
    findings = build_findings(tmp_path)

    report = ReportWriter().build_report(
        input_file="Dockerfile",
        findings=findings,
    )

    output = tmp_path / "report.json"

    ReportWriter().write_json(
        report,
        str(output),
    )

    assert output.exists()
    assert output.stat().st_size > 0


def test_text_report_written(tmp_path):
    findings = build_findings(tmp_path)

    report = ReportWriter().build_report(
        input_file="Dockerfile",
        findings=findings,
    )

    output = tmp_path / "report.txt"

    ReportWriter().write_text(
        report,
        str(output),
    )

    assert output.exists()

    content = output.read_text(
        encoding="utf-8"
    )

    assert "DAY 19 - DOCKER SECURITY REPORT" in content
    assert "LATEST_TAG" in content
    assert "SSH_EXPOSED" in content
    assert "MISSING_USER" in content
    assert "Critical     : 1" in content
    assert "High         : 1" in content
    assert "Medium       : 1" in content
    assert "Low          : 0" in content
