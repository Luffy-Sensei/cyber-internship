#!/usr/bin/env python3

"""
Tests for the Phase 3 attack-chain engine.
"""

import pytest

from se_chain.engine import ChainEngine
from se_chain.exceptions import ChainExecutionError
from se_chain.models import ChainContext, RunMetadata


def make_context(
    target: str = "127.0.0.1",
    authorized: bool = True,
) -> ChainContext:

    return ChainContext(
        metadata=RunMetadata(
            target=target,
            mode="lab",
        ),
        authorized=authorized,
    )


def test_engine_pipeline(monkeypatch):
    """Engine should orchestrate all Phase 2 modules."""

    engine = ChainEngine()

    calls = []

    class FakeResult:
        def __init__(self, module, data=None):
            self.module = module
            self.success = True
            self.status = "completed"
            self.message = "ok"
            self.data = data or {}
            self.warnings = []
            self.errors = []

    def fake_osint(context):
        calls.append("osint")
        return FakeResult("osint")

    def fake_profile(context):
        calls.append("profile")
        return FakeResult("profile")

    def fake_phish(context):
        calls.append("phish")

        return FakeResult(
            "phish",
            {
                "risk_assessment": {
                    "score": 40,
                    "level": "MEDIUM",
                    "indicator_count": 1,
                }
            },
        )

    def fake_template(context):
        calls.append("template")
        return FakeResult("template")

    def fake_ir(context):
        calls.append("ir")
        return FakeResult(
            "ir",
            {
                "response": {
                    "action_count": 5,
                }
            },
        )

    monkeypatch.setattr(engine.osint, "run", fake_osint)
    monkeypatch.setattr(engine.profile, "run", fake_profile)
    monkeypatch.setattr(engine.phish, "run", fake_phish)
    monkeypatch.setattr(engine.template, "run", fake_template)
    monkeypatch.setattr(engine.ir, "run", fake_ir)

    context = engine.run(make_context())

    assert calls == [
        "osint",
        "profile",
        "phish",
        "template",
        "ir",
    ]

    assert context.metadata.status == "completed"

    assert list(context.module_results.keys()) == [
        "osint",
        "profile",
        "phish",
        "template",
        "ir",
    ]


def test_engine_generates_detection_event(monkeypatch):
    """Phishing risk should produce a detection event."""

    engine = ChainEngine()

    class FakeResult:
        def __init__(self, module, data=None):
            self.module = module
            self.success = True
            self.status = "completed"
            self.message = "ok"
            self.data = data or {}
            self.warnings = []
            self.errors = []

    monkeypatch.setattr(
        engine.osint,
        "run",
        lambda context: FakeResult("osint"),
    )

    monkeypatch.setattr(
        engine.profile,
        "run",
        lambda context: FakeResult("profile"),
    )

    monkeypatch.setattr(
        engine.phish,
        "run",
        lambda context: FakeResult(
            "phish",
            {
                "risk_assessment": {
                    "score": 40,
                    "level": "MEDIUM",
                    "indicator_count": 1,
                }
            },
        ),
    )

    monkeypatch.setattr(
        engine.template,
        "run",
        lambda context: FakeResult("template"),
    )

    monkeypatch.setattr(
        engine.ir,
        "run",
        lambda context: FakeResult("ir"),
    )

    context = engine.run(make_context())

    alerts = [
        event
        for event in context.events
        if event.event_type == "alert"
    ]

    assert len(alerts) == 1

    assert alerts[0].severity == "medium"

    assert alerts[0].metadata["risk_score"] == 40


def test_engine_triggers_ir(monkeypatch):
    """Detected phishing risk should trigger IR."""

    engine = ChainEngine()

    class FakeResult:
        def __init__(self, module, data=None):
            self.module = module
            self.success = True
            self.status = "completed"
            self.message = "ok"
            self.data = data or {}
            self.warnings = []
            self.errors = []

    ir_called = []

    monkeypatch.setattr(
        engine.osint,
        "run",
        lambda context: FakeResult("osint"),
    )

    monkeypatch.setattr(
        engine.profile,
        "run",
        lambda context: FakeResult("profile"),
    )

    monkeypatch.setattr(
        engine.phish,
        "run",
        lambda context: FakeResult(
            "phish",
            {
                "risk_assessment": {
                    "score": 40,
                    "level": "MEDIUM",
                    "indicator_count": 1,
                }
            },
        ),
    )

    monkeypatch.setattr(
        engine.template,
        "run",
        lambda context: FakeResult("template"),
    )

    def fake_ir(context):
        ir_called.append(True)
        return FakeResult("ir")

    monkeypatch.setattr(
        engine.ir,
        "run",
        fake_ir,
    )

    context = engine.run(make_context())

    assert ir_called == [True]

    assert any(
        event.event_type == "ir_triggered"
        for event in context.events
    )


def test_engine_blocks_unauthorized_context():
    """Unauthorized execution must never enter the pipeline."""

    engine = ChainEngine()

    context = make_context(
        authorized=False,
    )

    with pytest.raises(ChainExecutionError):
        engine.run(context)

    assert context.metadata.status == "blocked"

    assert context.module_results == {}


def test_engine_fails_when_phish_fails(monkeypatch):
    """A failed phishing stage should stop the chain."""

    engine = ChainEngine()

    class FakeResult:
        def __init__(self, module, success=True):
            self.module = module
            self.success = success
            self.status = (
                "completed"
                if success
                else "failed"
            )
            self.message = "test"
            self.data = {}
            self.warnings = []
            self.errors = []

    monkeypatch.setattr(
        engine.osint,
        "run",
        lambda context: FakeResult("osint"),
    )

    monkeypatch.setattr(
        engine.profile,
        "run",
        lambda context: FakeResult("profile"),
    )

    monkeypatch.setattr(
        engine.phish,
        "run",
        lambda context: FakeResult(
            "phish",
            success=False,
        ),
    )

    context = make_context()

    with pytest.raises(ChainExecutionError):
        engine.run(context)

    assert context.metadata.status == "failed"

    assert list(context.module_results.keys()) == [
        "osint",
        "profile",
        "phish",
    ]