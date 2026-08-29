from scanner.rules import is_sensitive_path, normalize_path


def test_normalize_path():
    assert normalize_path("/admin/") == "admin"


def test_sensitive_env():
    assert is_sensitive_path(".env")
    assert is_sensitive_path("/.env/")


def test_sensitive_git():
    assert is_sensitive_path(".git")
    assert is_sensitive_path("/.git/")


def test_normal_path_is_not_sensitive():
    assert not is_sensitive_path("dashboard")
