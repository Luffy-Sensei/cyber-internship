from __future__ import annotations

import argparse
import json
import logging
from dataclasses import dataclass, asdict
from logging import FileHandler
from pathlib import Path

from .engine import RateLimitEngine
from .policies import get_policy



LOGGER = logging.getLogger("day22")

def configure_logging(
    verbose: bool = False,
    log_path: str | Path = "output/logs/day22_validation.log",
) -> None:
    """Configure console and persistent validation logging."""

    level = logging.DEBUG if verbose else logging.INFO

    path = Path(log_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    formatter = logging.Formatter(
        "%(asctime)s | %(levelname)s | %(name)s | %(message)s"
    )

    logger = logging.getLogger("day22")
    logger.setLevel(level)
    logger.handlers.clear()
    logger.propagate = False

    console = logging.StreamHandler()
    console.setLevel(level)
    console.setFormatter(formatter)

    file_handler = FileHandler(path, encoding="utf-8")
    file_handler.setLevel(level)
    file_handler.setFormatter(formatter)

    logger.addHandler(console)
    logger.addHandler(file_handler)

@dataclass(frozen=True)
class ValidationEvent:
    """One simulated request decision."""

    sequence: int
    client_id: str
    elapsed_seconds: float
    allowed: bool
    remaining_tokens: float
    retry_after_seconds: float


@dataclass(frozen=True)
class ValidationSummary:
    """Aggregate validation results."""

    total_requests: int
    allowed_requests: int
    denied_requests: int
    denial_rate: float
    clients_tested: int
    refill_verified: bool
    isolation_verified: bool


class ValidationClock:
    """Deterministic clock used by the validation runner."""

    def __init__(self, start: float = 1000.0) -> None:
        self.now = start

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        if seconds < 0:
            raise ValueError("Clock cannot move backwards.")

        self.now += seconds


def run_validation(
    policy_name: str = "default",
    burst_requests: int = 5,
    refill_wait: float = 2.0,
) -> tuple[list[ValidationEvent], ValidationSummary]:
    """
    Execute a deterministic adversarial rate-limit validation.

    The validation demonstrates:
    - initial burst allowance,
    - automatic denial after exhaustion,
    - token refill,
    - per-client isolation.
    """

    if burst_requests < 1:
        raise ValueError("burst_requests must be at least 1.")

    if refill_wait < 0:
        raise ValueError("refill_wait cannot be negative.")

    policy = get_policy(policy_name)
    clock = ValidationClock()
    engine = RateLimitEngine(
        policy=policy,
        clock=clock,
    )

    events: list[ValidationEvent] = []
    sequence = 0

    def record(client_id: str, elapsed: float) -> None:
        nonlocal sequence

        sequence += 1

        decision = engine.process_request(client_id)
        LOGGER.info(
            "Request sequence=%d client=%s decision=%s "
            "remaining_tokens=%.3f retry_after=%.3f",
            sequence,
            client_id,
            "ALLOWED" if decision.allowed else "DENIED",
            decision.remaining_tokens,
            decision.retry_after_seconds,
        )

        events.append(
            ValidationEvent(
                sequence=sequence,
                client_id=client_id,
                elapsed_seconds=elapsed,
                allowed=decision.allowed,
                remaining_tokens=decision.remaining_tokens,
                retry_after_seconds=decision.retry_after_seconds,
            )
        )

    LOGGER.info(
        "Starting validation policy=%s capacity=%s refill_rate=%s",
        policy.name,
        policy.config.capacity,
        policy.config.refill_rate_per_sec,
    )

    # Phase A: rapid burst from client-A.
    for _ in range(burst_requests):
        record("client-A", 0.0)

    # Phase B: wait for refill and retry client-A.
    clock.advance(refill_wait)
    record("client-A", refill_wait)

    # Phase C: prove another client has an independent bucket.
    record("client-B", 0.0)

    summary_data = engine.summary()

    denial_rate = (
        summary_data["denied_requests"]
        / summary_data["total_requests"]
    )

    client_a_events = [
        event for event in events
        if event.client_id == "client-A"
    ]

    client_b_events = [
        event for event in events
        if event.client_id == "client-B"
    ]

    refill_verified = (
        any(not event.allowed for event in client_a_events)
        and client_a_events[-1].allowed
    )

    isolation_verified = bool(
        client_b_events
        and client_b_events[0].allowed
    )

    summary = ValidationSummary(
        total_requests=summary_data["total_requests"],
        allowed_requests=summary_data["allowed_requests"],
        denied_requests=summary_data["denied_requests"],
        denial_rate=denial_rate,
        clients_tested=summary_data["clients_seen"],
        refill_verified=refill_verified,
        isolation_verified=isolation_verified,
    )

    LOGGER.info(
        "Validation complete requests=%d allowed=%d denied=%d",
        summary.total_requests,
        summary.allowed_requests,
        summary.denied_requests,
    )

    return events, summary


def build_report(
    policy_name: str,
    events: list[ValidationEvent],
    summary: ValidationSummary,
) -> dict:
    """Build JSON-serializable validation evidence."""

    policy = get_policy(policy_name)

    return {
        "schema_version": "1.0",
        "tool": "day22-api-rate-limiter",
        "policy": {
            "name": policy.name,
            "capacity": policy.config.capacity,
            "refill_rate_per_sec": policy.config.refill_rate_per_sec,
        },
        "summary": asdict(summary),
        "events": [asdict(event) for event in events],
    }


def write_json(report: dict, output_path: str | Path) -> None:
    """Write validation evidence as formatted JSON."""

    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    with path.open("w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2)

        handle.write("\n")

    LOGGER.info("Validation report written to %s", path)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Day 22 deterministic token-bucket validation runner."
        )
    )

    parser.add_argument(
        "--policy",
        default="default",
        help="Rate-limit policy to validate.",
    )

    parser.add_argument(
        "--burst",
        type=int,
        default=5,
        help="Number of rapid requests from client-A.",
    )

    parser.add_argument(
        "--refill-wait",
        type=float,
        default=2.0,
        help="Simulated refill wait in seconds.",
    )

    parser.add_argument(
        "--json",
        default="output/reports/day22_rate_limit_validation.json",
        help="JSON evidence output path.",
    )

    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose logging.",
    )

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    log_path = "output/logs/day22_validation.log"

    configure_logging(
        verbose=args.verbose,
        log_path=log_path,
    )

    events, summary = run_validation(
        policy_name=args.policy,
        burst_requests=args.burst,
        refill_wait=args.refill_wait,
    )

    report = build_report(
        policy_name=args.policy,
        events=events,
        summary=summary,
    )

    write_json(report, args.json)

    print()
    print("=" * 60)
    print("DAY 22 - API RATE-LIMITING VALIDATION")
    print("=" * 60)
    print()
    print(f"Policy              : {args.policy}")
    print(f"Requests            : {summary.total_requests}")
    print(f"Allowed             : {summary.allowed_requests}")
    print(f"Denied              : {summary.denied_requests}")
    print(f"Denial rate         : {summary.denial_rate:.2%}")
    print(f"Clients tested      : {summary.clients_tested}")
    print(f"Refill verified     : {summary.refill_verified}")
    print(f"Isolation verified  : {summary.isolation_verified}")
    print()
    print("EVIDENCE")
    print("-" * 60)
    print(f"JSON                : {args.json}")
    print(f"LOG                 : {log_path}")
    print()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
