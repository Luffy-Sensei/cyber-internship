from scanner.client import HTTPClient
from scanner.models import ScanConfig


def test_scan_path(monkeypatch):
    config = ScanConfig(
        base_url="http://127.0.0.1:5000",
        wordlist_path="input/paths.txt",
    )

    class FakeResponse:
        status_code = 200
        content = b"hello"
        headers = {}

    def fake_get(*args, **kwargs):
        return FakeResponse()

    client = HTTPClient(config)
    monkeypatch.setattr(client.session, "get", fake_get)

    result = client.scan_path("/admin")

    assert result.status_code == 200
    assert result.path == "admin"
    assert result.response_length == 5
