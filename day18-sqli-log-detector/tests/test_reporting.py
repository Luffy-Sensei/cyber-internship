from pathlib import Path

from scanner.detector import SQLiDetector
from scanner.parser import LogParser
from scanner.intelligence import SecurityAnalyzer
from scanner.reporting import ReportWriter


def build_findings():
    parser = LogParser()
    analyzer = SecurityAnalyzer()

    findings = []

    with open(
        "input/mock_access.log",
        encoding="utf-8",
    ) as handle:
        lines = handle.readlines()

    for line in lines:
        entry = parser.parse_line(line)
        finding = analyzer.analyze(entry)

        if finding:
            findings.append(finding)

    return len(lines), findings


def test_report_contains_required_fields():
    total, findings = build_findings()

    writer = ReportWriter()

    report = writer.build_report(
        input_file="input/mock_access.log",
        total_entries=total,
        findings=findings,
    )

    assert "run_id" in report
    assert "generated_at" in report
    assert "statistics" in report
    assert "findings" in report


def test_report_statistics():
    total, findings = build_findings()

    writer = ReportWriter()

    report = writer.build_report(
        input_file="input/mock_access.log",
        total_entries=total,
        findings=findings,
    )

    assert report["statistics"]["total_entries"] == 3
    assert report["statistics"]["detections"] == 2
    assert report["statistics"]["critical"] == 1
    assert report["statistics"]["high"] == 1
    assert report["statistics"]["medium"] == 0
    assert report["statistics"]["low"] == 0


def test_json_report_written(tmp_path):
    total, findings = build_findings()

    writer = ReportWriter()

    report = writer.build_report(
        input_file="input/mock_access.log",
        total_entries=total,
        findings=findings,
    )

    output = tmp_path / "report.json"

    writer.write_json(report, str(output))

    assert output.exists()
    assert output.stat().st_size > 0


def test_text_report_written(tmp_path):
    total, findings = build_findings()

    writer = ReportWriter()

    report = writer.build_report(
        input_file="input/mock_access.log",
        total_entries=total,
        findings=findings,
    )

    output = tmp_path / "report.txt"

    writer.write_text(report, str(output))

    assert output.exists()

    content = output.read_text(
        encoding="utf-8"
    )

    assert "SQL INJECTION SECURITY REPORT" in content
    assert "TAUTOLOGY" in content
    assert "UNION_SELECT" in content

    assert "Critical     : 1" in content
    assert "High         : 1" in content
    assert "Medium       : 0" in content
    assert "Low          : 0" in content
