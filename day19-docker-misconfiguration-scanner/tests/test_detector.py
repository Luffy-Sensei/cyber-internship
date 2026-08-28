from scanner.detector import SecurityDetector
from scanner.parser import DockerfileParser


def parse_content(tmp_path, content):
    dockerfile = tmp_path / "Dockerfile"

    dockerfile.write_text(
        content,
        encoding="utf-8",
    )

    parser = DockerfileParser()

    return parser.parse_file(str(dockerfile))


def test_latest_tag_detected(tmp_path):
    document = parse_content(
        tmp_path,
        """
FROM python:latest
USER appuser
""",
    )

    findings = SecurityDetector().analyze(document)

    assert any(
        finding.rule_id == "LATEST_TAG"
        for finding in findings
    )


def test_pinned_image_not_detected(tmp_path):
    document = parse_content(
        tmp_path,
        """
FROM python:3.13-slim
USER appuser
""",
    )

    findings = SecurityDetector().analyze(document)

    assert not any(
        finding.rule_id == "LATEST_TAG"
        for finding in findings
    )


def test_ssh_exposure_detected(tmp_path):
    document = parse_content(
        tmp_path,
        """
FROM python:3.13-slim
USER appuser
EXPOSE 22
""",
    )

    findings = SecurityDetector().analyze(document)

    finding = next(
        finding
        for finding in findings
        if finding.rule_id == "SSH_EXPOSED"
    )

    assert finding.severity == "CRITICAL"
    assert finding.line_number == 4


def test_non_ssh_port_not_detected(tmp_path):
    document = parse_content(
        tmp_path,
        """
FROM python:3.13-slim
USER appuser
EXPOSE 8080
""",
    )

    findings = SecurityDetector().analyze(document)

    assert not any(
        finding.rule_id == "SSH_EXPOSED"
        for finding in findings
    )


def test_missing_user_detected(tmp_path):
    document = parse_content(
        tmp_path,
        """
FROM python:3.13-slim
CMD ["python", "app.py"]
""",
    )

    findings = SecurityDetector().analyze(document)

    finding = next(
        finding
        for finding in findings
        if finding.rule_id == "MISSING_USER"
    )

    assert finding.severity == "HIGH"
    assert finding.line_number is None


def test_explicit_user_suppresses_missing_user(tmp_path):
    document = parse_content(
        tmp_path,
        """
FROM python:3.13-slim
USER appuser
CMD ["python", "app.py"]
""",
    )

    findings = SecurityDetector().analyze(document)

    assert not any(
        finding.rule_id == "MISSING_USER"
        for finding in findings
    )


def test_multiple_findings_detected(tmp_path):
    document = parse_content(
        tmp_path,
        """
FROM python:latest
EXPOSE 22
""",
    )

    findings = SecurityDetector().analyze(document)

    rule_ids = {
        finding.rule_id
        for finding in findings
    }

    assert rule_ids == {
        "LATEST_TAG",
        "SSH_EXPOSED",
        "MISSING_USER",
    }


def test_latest_tag_line_number(tmp_path):
    document = parse_content(
        tmp_path,
        """
# Production image
FROM python:latest
USER appuser
""",
    )

    findings = SecurityDetector().analyze(document)

    finding = next(
        finding
        for finding in findings
        if finding.rule_id == "LATEST_TAG"
    )

    assert finding.line_number == 3
