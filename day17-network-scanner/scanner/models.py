from dataclasses import dataclass
from enum import Enum


class PortState(str, Enum):
    OPEN = "OPEN"
    CLOSED = "CLOSED"
    TIMEOUT = "TIMEOUT"
    ERROR = "ERROR"

class RiskLevel(str, Enum):
    NONE = "NONE"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class ScanResult:
    host: str
    port: int
    protocol: str
    state: PortState
    latency_ms: float | None = None
    error: str | None = None


@dataclass
class ServiceResult:
    host: str
    port: int
    protocol: str
    state: PortState
    service: str
    category: str
    confidence: str
    detection_method: str
    latency_ms: float | None = None
    evidence: str | None = None

@dataclass
class SecurityFinding:
    host: str
    port: int
    service: str
    category: str
    risk: RiskLevel
    title: str
    description: str
    recommendation: str
    
@dataclass
class TopologyNode:
    id: str
    type: str
    address: str


@dataclass
class TopologyEdge:
    source: str
    destination: str
    protocol: str
    port: int
    state: str
    service: str
    risk: str        