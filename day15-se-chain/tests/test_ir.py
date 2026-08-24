#!/usr/bin/env python3

"""
Tests for the SE Chain defensive incident-response module.
"""

from se_chain.models import (
    ChainContext,
    RunMetadata,
    ModuleResult,
)
from se_chain.modules.ir import IRModule


def make_context() -> ChainContext:
    """
    Create a minimal authorized lab context.
    """

    metadata = RunMetadata(
        target="127.0.0.1",
        mode="lab",
    )

    return ChainContext(
        metadata=metadata,
        authorized=True,
    )


def make_phish_result(
    score: int = 40,
    level: str = "MEDIUM",
    indicator_count: int = 1,
) -> ModuleResult:
    """
    Create a simulated phishing result for integration testing.
    """

    return ModuleResult(
        module="phish",
        success=True,
        message="Phishing risk analysis completed",
        data={
            "risk_assessment": {
                "score": score,
                "level": level,
                "indicator_count": indicator_count,
            },
            "indicators": [
                {
                    "type": "raw_ip_address",
                    "severity": "high",
                    "points": score,
                }
            ],
        },
    )


def test_ir_success_without_phish_result():
    """
    IR should still run when no phishing result exists.
    """

    context = make_context()

    result = IRModule().run(context)

    assert result.success is True
    assert result.status == "completed"
    assert result.errors == []

    assert result.data["response"]["risk_score"] == 0
    assert result.data["response"]["risk_level"] == "UNKNOWN"

    assert len(context.ir_actions) == 5
    assert len(context.events) == 1


def test_ir_consumes_phish_result():
    """
    IR should consume phishing risk information from ChainContext.
    """

    context = make_context()

    phish_result = make_phish_result(
        score=40,
        level="MEDIUM",
        indicator_count=1,
    )

    context.add_module_result(phish_result)

    result = IRModule().run(context)

    assert result.success is True
    assert result.status == "completed"

    response = result.data["response"]

    assert response["risk_score"] == 40
    assert response["risk_level"] == "MEDIUM"
    assert response["indicator_count"] == 1

    assert len(context.ir_actions) == 5


def test_ir_actions_are_simulated():
    """
    Every generated IR action must remain simulated.
    """

    context = make_context()

    context.add_module_result(
        make_phish_result()
    )

    result = IRModule().run(context)

    assert result.success is True

    for action in context.ir_actions:
        assert action.status == "simulated"
        assert action.metadata["simulated"] is True


def test_ir_event_created():
    """
    IR should create a structured IR_TRIGGERED event.
    """

    context = make_context()

    context.add_module_result(
        make_phish_result(
            score=80,
            level="HIGH",
            indicator_count=2,
        )
    )

    result = IRModule().run(context)

    assert result.success is True
    assert len(context.events) == 1

    event = context.events[0]

    assert event.event_type == "ir_triggered"
    assert event.stage == "incident_response"
    assert event.severity == "high"
    assert event.simulated is True


def test_ir_requires_authorization():
    """
    Unauthorized IR simulation must fail safely.
    """

    context = make_context()
    context.authorized = False

    result = IRModule().run(context)

    assert result.success is False
    assert result.status == "failed"
    assert result.errors

    assert context.ir_actions == []
    assert context.events == []


def test_ir_requires_target():
    """
    IR must fail cleanly when the target is missing.
    """

    context = make_context()
    context.metadata.target = ""

    result = IRModule().run(context)

    assert result.success is False
    assert result.status == "failed"
    assert result.errors
