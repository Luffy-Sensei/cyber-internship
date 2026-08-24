#!/usr/bin/env python3

"""
SE Chain Simulator - Data Models

Shared data structures used across the simulator.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional
from uuid import uuid4


# ---------------------------------------------------------------------------
# Utility
# ---------------------------------------------------------------------------

def utc_now() -> datetime:
    """
    Return the current UTC timestamp.
    """
    return datetime.now(timezone.utc)


def generate_run_id() -> str:
    """
    Generate a unique identifier for a simulator run.
    """
    timestamp = utc_now().strftime("%Y%m%d-%H%M%S")
    short_uuid = uuid4().hex[:8]

    return f"{timestamp}-{short_uuid}"


# ---------------------------------------------------------------------------
# Enumerations / Constants
# ---------------------------------------------------------------------------

class ChainStatus:
    """
    Overall execution states.
    """

    INITIALIZED = "initialized"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    BLOCKED = "blocked"


class EventSeverity:
    """
    Severity levels for simulation events.
    """

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class EventType:
    """
    Types of events generated during a simulation.
    """

    MODULE_STARTED = "module_started"
    MODULE_COMPLETED = "module_completed"

    OSINT_COMPLETED = "osint_completed"
    PROFILE_CREATED = "profile_created"
    PHISH_ANALYSIS = "phish_analysis"
    TEMPLATE_GENERATED = "template_generated"

    DELIVERY_SIMULATED = "delivery_simulated"
    EXPLOIT_SIMULATED = "exploit_simulated"
    PERSISTENCE_SIMULATED = "persistence_simulated"

    ALERT = "alert"
    IR_TRIGGERED = "ir_triggered"


class IRActionType:
    """
    Defensive incident-response action types.
    """

    ACCOUNT_CONTAINMENT = "account_containment"
    SESSION_INVALIDATION = "session_invalidation"
    USER_NOTIFICATION = "user_notification"
    EVIDENCE_PRESERVATION = "evidence_preservation"
    ALERT_GENERATION = "alert_generation"


# ---------------------------------------------------------------------------
# Run Metadata
# ---------------------------------------------------------------------------

@dataclass
class RunMetadata:
    """
    Metadata describing a single simulator execution.
    """

    run_id: str = field(default_factory=generate_run_id)

    target: str = ""
    mode: str = ""

    started_at: datetime = field(default_factory=utc_now)
    completed_at: Optional[datetime] = None

    status: str = ChainStatus.INITIALIZED

    application: str = "SE Chain Simulator"
    version: str = "1.0.0"

    def mark_started(self) -> None:
        """
        Mark the run as started.
        """
        self.started_at = utc_now()
        self.status = ChainStatus.RUNNING

    def mark_completed(self) -> None:
        """
        Mark the run as successfully completed.
        """
        self.completed_at = utc_now()
        self.status = ChainStatus.COMPLETED

    def mark_failed(self) -> None:
        """
        Mark the run as failed.
        """
        self.completed_at = utc_now()
        self.status = ChainStatus.FAILED

    def mark_blocked(self) -> None:
        """
        Mark the run as blocked by the safety layer.
        """
        self.completed_at = utc_now()
        self.status = ChainStatus.BLOCKED


# ---------------------------------------------------------------------------
# Module Result
# ---------------------------------------------------------------------------

@dataclass
class ModuleResult:
    """
    Standardized result returned by every simulator module.
    """

    module: str

    success: bool

    message: str = ""

    status: str = "completed"

    data: dict[str, Any] = field(default_factory=dict)

    warnings: list[str] = field(default_factory=list)

    errors: list[str] = field(default_factory=list)

    started_at: datetime = field(default_factory=utc_now)
    completed_at: Optional[datetime] = None

    def complete(self) -> None:
        """
        Mark module execution as complete.
        """
        self.completed_at = utc_now()

    def fail(self, error: str) -> None:
        """
        Mark module execution as failed.
        """
        self.success = False
        self.status = "failed"
        self.errors.append(error)
        self.completed_at = utc_now()


# ---------------------------------------------------------------------------
# Simulation Event
# ---------------------------------------------------------------------------

@dataclass
class SimulationEvent:
    """
    Represents an event occurring during the simulated attack chain.
    """

    event_type: str

    stage: str

    description: str

    severity: str = EventSeverity.INFO

    timestamp: datetime = field(default_factory=utc_now)

    metadata: dict[str, Any] = field(default_factory=dict)

    simulated: bool = True


# ---------------------------------------------------------------------------
# Incident Response Action
# ---------------------------------------------------------------------------

@dataclass
class IRAction:
    """
    Represents a defensive incident-response action.
    """

    action_type: str

    description: str

    status: str = "simulated"

    timestamp: datetime = field(default_factory=utc_now)

    metadata: dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Chain Context
# ---------------------------------------------------------------------------

@dataclass
class ChainContext:
    """
    Shared state for an entire SE Chain Simulator execution.

    Every module receives the same context and contributes its results
    to this object.
    """

    metadata: RunMetadata

    authorized: bool = False

    target_config: dict[str, Any] = field(
        default_factory=dict
    )

    module_results: dict[str, ModuleResult] = field(
        default_factory=dict
    )

    events: list[SimulationEvent] = field(
        default_factory=list
    )

    ir_actions: list[IRAction] = field(
        default_factory=list
    )

    data: dict[str, Any] = field(
        default_factory=dict
    )

    errors: list[str] = field(
        default_factory=list
    )

    def __post_init__(self) -> None:
        """
        Validate basic context invariants.
        """

        if not isinstance(self.authorized, bool):
            raise TypeError(
                "authorized must be a boolean"
            )

        if not isinstance(self.target_config, dict):
            raise TypeError(
                "target_config must be a dictionary"
            )

        if not isinstance(self.module_results, dict):
            raise TypeError(
                "module_results must be a dictionary"
            )

        if not isinstance(self.events, list):
            raise TypeError(
                "events must be a list"
            )

        if not isinstance(self.ir_actions, list):
            raise TypeError(
                "ir_actions must be a list"
            )

        if not isinstance(self.errors, list):
            raise TypeError(
                "errors must be a list"
            )

    def add_module_result(
        self,
        result: ModuleResult,
    ) -> None:
        """Store a module result."""

        self.module_results[result.module] = result

    def add_event(
        self,
        event: SimulationEvent,
    ) -> None:
        """Add a simulation event."""

        self.events.append(event)

    def add_ir_action(
        self,
        action: IRAction,
    ) -> None:
        """Add an incident-response action."""

        self.ir_actions.append(action)

    def add_error(
        self,
        error: str,
    ) -> None:
        """Record an execution error."""

        if not isinstance(error, str):
            error = str(error)

        self.errors.append(error)