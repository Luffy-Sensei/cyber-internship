from dataclasses import dataclass
from enum import Enum


class HTTPMethod(str, Enum):
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    PATCH = "PATCH"
    DELETE = "DELETE"
    HEAD = "HEAD"
    OPTIONS = "OPTIONS"


@dataclass(frozen=True)
class LogEntry:
    """Normalized representation of one HTTP access-log entry."""

    source_ip: str
    method: HTTPMethod
    path: str
    protocol: str
    status_code: int
    raw: str

@dataclass(frozen=True)
class Detection:
    """A security detection generated from a parsed log entry."""

    signature: str
    confidence: str
    description: str
    evidence: str


@dataclass(frozen=True)
class Finding:
    """Security finding associated with one log entry."""

    source_ip: str
    method: HTTPMethod
    path: str
    status_code: int
    detections: tuple[Detection, ...]
    raw: str
    risk: object | None = None    
