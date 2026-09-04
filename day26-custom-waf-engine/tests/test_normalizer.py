import pytest

from scanner.models import HTTPRequest
from scanner.normalizer import RequestNormalizer


def test_normalizer_uppercases_method():
    request = HTTPRequest(
        request_id="req-001",
        method=" get ",
        path="/home",
    )

    result = RequestNormalizer().normalize(request)

    assert result.method == "GET"


def test_normalizer_decodes_path():
    request = HTTPRequest(
        request_id="req-002",
        method="GET",
        path="/files/%2e%2e/%2e%2e/secret",
    )

    result = RequestNormalizer().normalize(request)

    assert result.path == "/files/../../secret"


def test_normalizer_decodes_query():
    request = HTTPRequest(
        request_id="req-003",
        method="GET",
        path="/search",
        query="q=%3Cscript%3E",
    )

    result = RequestNormalizer().normalize(request)

    assert result.query == "q=<script>"


def test_normalizer_decodes_body():
    request = HTTPRequest(
        request_id="req-004",
        method="POST",
        path="/submit",
        body="value=%22UNION%20SELECT%22",
    )

    result = RequestNormalizer().normalize(request)

    assert result.body == 'value="UNION SELECT"'


def test_normalizer_canonicalizes_headers():
    request = HTTPRequest(
        request_id="req-005",
        method="GET",
        path="/",
        headers={
            " Host ": " example.local ",
            "Content-Type": " application/json ",
        },
    )

    result = RequestNormalizer().normalize(request)

    assert result.headers == {
        "host": "example.local",
        "content-type": "application/json",
    }


def test_normalizer_preserves_request_id():
    request = HTTPRequest(
        request_id="req-006",
        method="GET",
        path="/",
    )

    result = RequestNormalizer().normalize(request)

    assert result.request_id == "req-006"


def test_normalizer_does_not_modify_original_request():
    request = HTTPRequest(
        request_id="req-007",
        method=" get ",
        path="/search%3Fq%3Dtest",
        headers={" Host ": " example.local "},
    )

    original_method = request.method
    original_path = request.path
    original_headers = request.headers.copy()

    RequestNormalizer().normalize(request)

    assert request.method == original_method
    assert request.path == original_path
    assert request.headers == original_headers


def test_normalizer_rejects_wrong_input_type():
    with pytest.raises(TypeError):
        RequestNormalizer().normalize("not-a-request")  # type: ignore[arg-type]
