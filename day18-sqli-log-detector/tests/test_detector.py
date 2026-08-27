from scanner.detector import SQLiDetector
from scanner.models import HTTPMethod, LogEntry


def make_entry(path: str) -> LogEntry:
    return LogEntry(
        source_ip="10.0.4.12",
        method=HTTPMethod.GET,
        path=path,
        protocol="HTTP/1.1",
        status_code=200,
        raw=f'10.0.4.12 - "GET {path} HTTP/1.1" 200',
    )


def test_union_select_detected():
    detector = SQLiDetector()

    finding = detector.analyze(
        make_entry("/search?q=UNION%20SELECT")
    )

    assert finding is not None
    assert finding.detections[0].signature == "UNION_SELECT"
    assert finding.detections[0].confidence == "HIGH"


def test_tautology_detected():
    detector = SQLiDetector()

    finding = detector.analyze(
        make_entry("/login?user=admin%27%20OR%20%271%27=%271")
    )

    assert finding is not None
    assert any(
        detection.signature == "TAUTOLOGY"
        for detection in finding.detections
    )


def test_sql_comment_detected():
    detector = SQLiDetector()

    finding = detector.analyze(
        make_entry("/search?q=test--")
    )

    assert finding is not None
    assert any(
        detection.signature == "SQL_COMMENT"
        for detection in finding.detections
    )


def test_normal_request_not_detected():
    detector = SQLiDetector()

    finding = detector.analyze(
        make_entry("/profile?id=5")
    )

    assert finding is None


def test_url_encoding_is_normalized():
    detector = SQLiDetector()

    finding = detector.analyze(
        make_entry("/search?q=UNION%20SELECT")
    )

    assert finding is not None
