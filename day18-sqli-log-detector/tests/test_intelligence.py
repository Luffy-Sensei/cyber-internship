from scanner.detector import SQLiDetector
from scanner.intelligence import SecurityAnalyzer
from scanner.models import HTTPMethod, LogEntry


def make_entry(path: str) -> LogEntry:
    return LogEntry(
        source_ip="10.0.4.12",
        method=HTTPMethod.GET,
        path=path,
        protocol="HTTP/1.1",
        status_code=500,
        raw=f'10.0.4.12 - "GET {path} HTTP/1.1" 500',
    )


def test_security_analyzer_returns_risk():
    analyzer = SecurityAnalyzer(
        detector=SQLiDetector()
    )

    finding = analyzer.analyze(
        make_entry("/search?q=UNION%20SELECT")
    )

    assert finding is not None
    assert finding.risk is not None
    assert finding.risk.severity == "HIGH"
    assert finding.risk.score == 80


def test_security_analyzer_handles_multiple_signatures():
    analyzer = SecurityAnalyzer()

    finding = analyzer.analyze(
        make_entry("/search?q=UNION%20SELECT%20foo--")
    )

    assert finding is not None
    assert finding.risk.severity == "CRITICAL"
    assert finding.risk.score == 100
