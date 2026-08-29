from scanner.analyzer import WebDirectoryAnalyzer
from scanner.models import PathResult


def make_result(
    path: str,
    status_code: int,
    response_length: int = 100,
) -> PathResult:
    return PathResult(
        path=path,
        url=f"http://127.0.0.1:5000{path}",
        status_code=status_code,
        response_length=response_length,
        location=None,
        error=None,
    )


def test_analyzer_generates_risk_enriched_findings():
    analyzer = WebDirectoryAnalyzer(
        target="http://127.0.0.1:5000",
        wordlist=[".env"],
    )

    report = analyzer.analyze(
        [
            make_result(
                "/.env",
                200,
                256,
            )
        ]
    )

    assert report["target"] == "http://127.0.0.1:5000"
    assert report["wordlist_size"] == 1
    assert report["requests_sent"] == 1
    assert report["summary"]["total_findings"] == 2

    rule_ids = {
        finding["rule_id"]
        for finding in report["findings"]
    }

    assert "DIRECTORY_200" in rule_ids
    assert "SENSITIVE_EXPOSURE" in rule_ids


def test_analyzer_assigns_critical_sensitive_exposure():
    analyzer = WebDirectoryAnalyzer(
        target="http://127.0.0.1:5000",
        wordlist=[".env"],
    )

    report = analyzer.analyze(
        [
            make_result("/.env", 200)
        ]
    )

    finding = next(
        finding
        for finding in report["findings"]
        if finding["rule_id"] == "SENSITIVE_EXPOSURE"
    )

    assert finding["severity"] == "CRITICAL"
    assert finding["risk_score"] == 90
    assert finding["classification"] == "CRITICAL"
    assert finding["recommendation"]


def test_analyzer_handles_clean_scan():
    analyzer = WebDirectoryAnalyzer(
        target="http://127.0.0.1:5000",
        wordlist=["missing"],
    )

    report = analyzer.analyze(
        [
            make_result("/missing", 404)
        ]
    )

    assert report["findings"] == []
    assert report["summary"]["total_findings"] == 0


def test_analyzer_handles_forbidden_endpoint():
    analyzer = WebDirectoryAnalyzer(
        target="http://127.0.0.1:5000",
        wordlist=["admin"],
    )

    report = analyzer.analyze(
        [
            make_result("/admin", 403)
        ]
    )

    assert report["summary"]["total_findings"] == 1

    finding = report["findings"][0]

    assert finding["rule_id"] == "DIRECTORY_403"
    assert finding["severity"] == "LOW"
    assert finding["risk_score"] == 5
