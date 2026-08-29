from urllib.parse import urlparse

from .models import ScanConfig


def normalize_base_url(url: str) -> str:
    url = url.strip().rstrip("/")

    parsed = urlparse(url)

    if parsed.scheme not in {"http", "https"}:
        raise ValueError("Base URL must use HTTP or HTTPS.")

    if not parsed.netloc:
        raise ValueError("Base URL must include a hostname.")

    return url


def build_config(
    base_url: str,
    wordlist_path: str,
    timeout: float = 3.0,
    follow_redirects: bool = False,
) -> ScanConfig:
    if timeout <= 0:
        raise ValueError("Timeout must be greater than zero.")

    return ScanConfig(
        base_url=normalize_base_url(base_url),
        wordlist_path=wordlist_path,
        timeout=timeout,
        follow_redirects=follow_redirects,
    )
