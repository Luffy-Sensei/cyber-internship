from pathlib import Path

import pytest

from scanner.cli import load_requests


def test_load_requests_reads_fixture_file(tmp_path):
    fixture = tmp_path / "requests.json"

    fixture.write_text(
        """
        [
          {
            "request_id": "cli-001",
            "method": "GET",
            "path": "/",
            "query": ""
          }
        ]
        """,
        encoding="utf-8",
    )

    requests = load_requests(fixture)

    assert len(requests) == 1
    assert requests[0].request_id == "cli-001"
    assert requests[0].method == "GET"
    assert requests[0].path == "/"


def test_load_requests_supports_optional_fields(tmp_path):
    fixture = tmp_path / "requests.json"

    fixture.write_text(
        """
        [
          {
            "request_id": "cli-002",
            "method": "POST",
            "path": "/submit"
          }
        ]
        """,
        encoding="utf-8",
    )

    requests = load_requests(fixture)

    assert requests[0].query == ""
    assert requests[0].headers == {}
    assert requests[0].body == ""


def test_load_requests_rejects_missing_file(tmp_path):
    fixture = tmp_path / "missing.json"

    with pytest.raises(FileNotFoundError):
        load_requests(fixture)


def test_load_requests_rejects_non_list_json(tmp_path):
    fixture = tmp_path / "invalid.json"

    fixture.write_text(
        '{"request_id": "invalid"}',
        encoding="utf-8",
    )

    with pytest.raises(ValueError):
        load_requests(fixture)


def test_load_requests_rejects_non_object_entry(tmp_path):
    fixture = tmp_path / "invalid.json"

    fixture.write_text(
        '[1, 2, 3]',
        encoding="utf-8",
    )

    with pytest.raises(ValueError):
        load_requests(fixture)
