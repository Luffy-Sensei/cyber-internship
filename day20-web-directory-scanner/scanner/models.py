from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional


@dataclass(frozen=True)
class ScanConfig:
    base_url: str
    wordlist_path: str
    timeout: float = 3.0
    follow_redirects: bool = False


@dataclass
class PathResult:
    path: str
    url: str
    status_code: Optional[int]
    response_length: int = 0
    location: Optional[str] = None
    error: Optional[str] = None
    scanned_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
