import pytest

from scanner.models import HTTPMethod
from scanner.parser import LogParser


@pytest.fixture
def parser():
    return LogParser()


def test_parse_get_request(parser):
    entry = parser.parse_line(
        '192.168.1.45 - '
        '"GET /profile?id=5 HTTP/1.1" 200'
    )

    assert entry.source_ip == "192.168.1.45"
    assert entry.method == HTTPMethod.GET
    assert entry.path == "/profile?id=5"
    assert entry.protocol == "HTTP/1.1"
    assert entry.status_code == 200


def test_parse_post_request(parser):
    entry = parser.parse_line(
        '10.0.4.12 - '
        '"POST /auth/login?user=admin HTTP/1.1" 401'
    )

    assert entry.source_ip == "10.0.4.12"
    assert entry.method == HTTPMethod.POST
    assert entry.path == "/auth/login?user=admin"
    assert entry.status_code == 401


def test_original_log_is_preserved(parser):
    raw = (
        '192.168.1.45 - '
        '"GET /profile?id=5 HTTP/1.1" 200'
    )

    entry = parser.parse_line(raw)

    assert entry.raw == raw


def test_invalid_log_entry_rejected(parser):
    with pytest.raises(ValueError):
        parser.parse_line(
            "this is not a valid access log"
        )


def test_empty_log_entry_rejected(parser):
    with pytest.raises(ValueError):
        parser.parse_line("")


def test_unsupported_method_rejected(parser):
    with pytest.raises(ValueError):
        parser.parse_line(
            '192.168.1.45 - '
            '"TRACE /debug HTTP/1.1" 200'
        )
