from scanner.detector import SecurityDetector
from scanner.models import PathResult


def make_result(
    path="admin",
    status_code=200,
    response_length=100,
    location=None,
):
    return PathResult(
        path=path,
        url=f"http://127.0.0.1:5000/{path}",
        status_code=status_code,
        response_length=response_length,
        location=location,
    )


def test_detect_accessible_endpoint():
    findings = SecurityDetector().analyze(
        make_result("admin", 200)
    )

    assert len(findings) == 1
    assert findings[0].rule_id == "DIRECTORY_200"


def test_detect_forbidden_endpoint():
    findings = SecurityDetector().analyze(
        make_result("admin", 403)
    )

    assert len(findings) == 1
    assert findings[0].rule_id == "DIRECTORY_403"


def test_detect_redirect():
    findings = SecurityDetector().analyze(
        make_result(
            "login",
            302,
            location="/signin",
        )
    )

    assert len(findings) == 1
    assert findings[0].rule_id == "DIRECTORY_REDIRECT"


def test_detect_server_error():
    findings = SecurityDetector().analyze(
        make_result("api", 500)
    )

    assert len(findings) == 1
    assert findings[0].rule_id == "DIRECTORY_5XX"


def test_detect_sensitive_exposure():
    findings = SecurityDetector().analyze(
        make_result(".env", 200, 250)
    )

    rule_ids = {finding.rule_id for finding in findings}

    assert "DIRECTORY_200" in rule_ids
    assert "SENSITIVE_EXPOSURE" in rule_ids


def test_sensitive_forbidden_path_is_not_exposure():
    findings = SecurityDetector().analyze(
        make_result(".env", 403)
    )

    rule_ids = {finding.rule_id for finding in findings}

    assert "DIRECTORY_403" in rule_ids
    assert "SENSITIVE_EXPOSURE" not in rule_ids


def test_request_error_produces_no_finding():
    result = PathResult(
        path="admin",
        url="http://127.0.0.1:5000/admin",
        status_code=None,
        error="connection refused",
    )

    findings = SecurityDetector().analyze(result)

    assert findings == []
