import json

import pytest

from scanner.validation import (
    ValidationClock,
    build_report,
    run_validation,
    write_json,
)


def test_validation_clock_advances_deterministically():
    clock = ValidationClock(start=100.0)

    assert clock() == 100.0

    clock.advance(2.5)

    assert clock() == 102.5


def test_validation_clock_rejects_negative_time():
    clock = ValidationClock()

    with pytest.raises(ValueError):
        clock.advance(-1.0)


def test_validation_produces_denials():
    events, summary = run_validation(
        policy_name="default",
        burst_requests=5,
        refill_wait=2.0,
    )

    assert events
    assert summary.total_requests == len(events)
    assert summary.denied_requests > 0
    assert summary.allowed_requests > 0


def test_validation_verifies_refill():
    _, summary = run_validation(
        policy_name="default",
        burst_requests=5,
        refill_wait=2.0,
    )

    assert summary.refill_verified is True


def test_validation_verifies_client_isolation():
    _, summary = run_validation(
        policy_name="default",
        burst_requests=5,
        refill_wait=2.0,
    )

    assert summary.isolation_verified is True
    assert summary.clients_tested == 2


def test_validation_rejects_invalid_burst():
    with pytest.raises(ValueError):
        run_validation(
            burst_requests=0,
        )


def test_validation_rejects_negative_wait():
    with pytest.raises(ValueError):
        run_validation(
            refill_wait=-1.0,
        )


def test_report_contains_schema_and_events():
    events, summary = run_validation()

    report = build_report(
        policy_name="default",
        events=events,
        summary=summary,
    )

    assert report["schema_version"] == "1.0"
    assert report["tool"] == "day22-api-rate-limiter"
    assert report["policy"]["name"] == "default"
    assert report["summary"]["total_requests"] == len(events)
    assert len(report["events"]) == len(events)


def test_json_report_can_be_written(tmp_path):
    events, summary = run_validation()

    report = build_report(
        policy_name="default",
        events=events,
        summary=summary,
    )

    output = tmp_path / "validation.json"

    write_json(report, output)

    assert output.exists()

    with output.open(encoding="utf-8") as handle:
        loaded = json.load(handle)

    assert loaded["schema_version"] == "1.0"
    assert loaded["summary"]["denied_requests"] > 0
