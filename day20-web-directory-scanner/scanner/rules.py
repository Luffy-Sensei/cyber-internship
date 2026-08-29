SENSITIVE_PATHS = {
    ".env",
    ".git",
    ".git/",
    "backup.sql",
    "backup.zip",
}

RULE_DIRECTORY_200 = "DIRECTORY_200"
RULE_DIRECTORY_403 = "DIRECTORY_403"
RULE_DIRECTORY_REDIRECT = "DIRECTORY_REDIRECT"
RULE_DIRECTORY_5XX = "DIRECTORY_5XX"
RULE_SENSITIVE_EXPOSURE = "SENSITIVE_EXPOSURE"


def normalize_path(path: str) -> str:
    return path.strip().lstrip("/").rstrip("/")


def is_sensitive_path(path: str) -> bool:
    normalized = normalize_path(path)

    return normalized in {
        normalize_path(item)
        for item in SENSITIVE_PATHS
    }
