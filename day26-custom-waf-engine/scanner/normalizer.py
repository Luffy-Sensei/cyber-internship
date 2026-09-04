from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import unquote

from scanner.models import HTTPRequest


@dataclass(frozen=True)
class NormalizedRequest:
    request_id: str
    method: str
    path: str
    query: str
    headers: dict[str, str]
    body: str


class RequestNormalizer:
    """Convert an HTTPRequest into a canonical inspection representation."""

    def normalize(self, request: HTTPRequest) -> NormalizedRequest:
        if not isinstance(request, HTTPRequest):
            raise TypeError("request must be an HTTPRequest")

        return NormalizedRequest(
            request_id=request.request_id,
            method=self._normalize_method(request.method),
            path=self._decode(request.path),
            query=self._decode(request.query),
            headers=self._normalize_headers(request.headers),
            body=self._decode(request.body),
        )

    @staticmethod
    def _normalize_method(method: str) -> str:
        return method.strip().upper()

    @staticmethod
    def _decode(value: str) -> str:
        """Decode percent-encoded HTTP input without executing it."""
        return unquote(value)

    @staticmethod
    def _normalize_headers(
        headers: dict[str, str],
    ) -> dict[str, str]:
        normalized: dict[str, str] = {}

        for name, value in headers.items():
            normalized_name = name.strip().lower()
            normalized_value = value.strip()

            normalized[normalized_name] = normalized_value

        return normalized
