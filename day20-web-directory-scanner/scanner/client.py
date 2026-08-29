from urllib.parse import quote

import requests

from .models import PathResult, ScanConfig


class HTTPClient:
    def __init__(self, config: ScanConfig):
        self.config = config
        self.session = requests.Session()

    def scan_path(self, path: str) -> PathResult:
        clean_path = path.lstrip("/")
        encoded_path = quote(clean_path, safe="/._-")
        url = f"{self.config.base_url}/{encoded_path}"

        try:
            response = self.session.get(
                url,
                timeout=self.config.timeout,
                allow_redirects=self.config.follow_redirects,
            )

            return PathResult(
                path=clean_path,
                url=url,
                status_code=response.status_code,
                response_length=len(response.content),
                location=response.headers.get("Location"),
            )

        except requests.RequestException as exc:
            return PathResult(
                path=clean_path,
                url=url,
                status_code=None,
                error=str(exc),
            )
