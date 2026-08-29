import pytest

from scanner.config import build_config, normalize_base_url


def test_normalize_base_url():
    assert normalize_base_url("http://127.0.0.1:5000/") == \
        "http://127.0.0.1:5000"


def test_rejects_invalid_scheme():
    with pytest.raises(ValueError):
        normalize_base_url("ftp://127.0.0.1")


def test_rejects_missing_hostname():
    with pytest.raises(ValueError):
        normalize_base_url("http://")


def test_build_config():
    config = build_config(
        "http://127.0.0.1:5000/",
        "input/paths.txt",
        timeout=5,
    )

    assert config.base_url == "http://127.0.0.1:5000"
    assert config.wordlist_path == "input/paths.txt"
    assert config.timeout == 5
