#!/usr/bin/env python3

from se_chain.models import ChainContext, RunMetadata
from se_chain.modules.profile import ProfileModule


def make_context(
    authorized: bool = True,
) -> ChainContext:
    target = {
        "target": "127.0.0.1",
        "target_type": "localhost",
        "environment": "lab",
        "authorized": authorized,
        "owner": "Cybersecurity Internship Lab",
        "purpose": (
            "Authorized social engineering attack-chain simulation"
        ),
    }

    return ChainContext(
        metadata=RunMetadata(
            target="127.0.0.1",
            mode="lab",
        ),
        authorized=authorized,
        target_config=target,
    )


def test_profile_success():
    context = make_context()

    result = ProfileModule().run(context)

    assert result.success is True
    assert result.status == "completed"
    assert result.module == "profile"


def test_profile_creates_synthetic_profile():
    context = make_context()

    result = ProfileModule().run(context)

    profile = result.data["profile"]

    assert profile["profile_type"] == "synthetic_lab_profile"
    assert profile["target"] == "127.0.0.1"
    assert profile["environment"] == "lab"
    assert profile["authorized"] is True
    assert profile["simulated"] is True


def test_profile_does_not_use_real_person_data():
    context = make_context()

    result = ProfileModule().run(context)

    profile = result.data["profile"]

    assert profile["real_person_data"] is False
    assert profile["external_targeting"] is False


def test_profile_creates_event():
    context = make_context()

    ProfileModule().run(context)

    assert len(context.events) == 1

    event = context.events[0]

    assert event.event_type == "profile_created"
    assert event.stage == "profile"
    assert event.simulated is True


def test_profile_requires_authorization():
    context = make_context(authorized=False)

    result = ProfileModule().run(context)

    assert result.success is False
    assert result.status == "failed"
    assert result.errors


def test_profile_requires_target():
    context = make_context()
    context.metadata.target = ""

    result = ProfileModule().run(context)

    assert result.success is False
    assert result.status == "failed"
    assert result.errors
