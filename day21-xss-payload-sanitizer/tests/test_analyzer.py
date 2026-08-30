from scanner.analyzer import XSSAnalyzer
from scanner.sanitizer import sanitize_user_input


def test_analyzer_returns_script_injection_finding():
    result = sanitize_user_input(
        "<script>alert(1)</script>"
    )

    findings = XSSAnalyzer().analyze(result)

    assert findings

    finding = next(
        finding
        for finding in findings
        if finding.rule_id == "SCRIPT_TAG"
    )

    assert finding.severity == "CRITICAL"
    assert finding.classification == "SCRIPT_INJECTION"
    assert finding.recommendation


def test_analyzer_returns_event_handler_finding():
    result = sanitize_user_input(
        '<img src="x" onerror="alert(1)">'
    )

    findings = XSSAnalyzer().analyze(result)

    rule_ids = {
        finding.rule_id
        for finding in findings
    }

    assert "EVENT_HANDLER" in rule_ids


def test_analyzer_returns_javascript_scheme_finding():
    result = sanitize_user_input(
        "javascript:alert(1)"
    )

    findings = XSSAnalyzer().analyze(result)

    finding = next(
        finding
        for finding in findings
        if finding.rule_id == "JAVASCRIPT_SCHEME"
    )

    assert finding.severity == "CRITICAL"
    assert finding.classification == "JAVASCRIPT_URI_INJECTION"


def test_analyzer_returns_multiple_findings():
    result = sanitize_user_input(
        '<object data="javascript:alert(1)">'
    )

    findings = XSSAnalyzer().analyze(result)

    rule_ids = {
        finding.rule_id
        for finding in findings
    }

    assert "OBJECT_TAG" in rule_ids
    assert "JAVASCRIPT_SCHEME" in rule_ids


def test_analyzer_returns_no_findings_for_clean_input():
    result = sanitize_user_input(
        "Hello, this is normal user input."
    )

    findings = XSSAnalyzer().analyze(result)

    assert findings == []
