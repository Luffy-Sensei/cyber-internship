#!/usr/bin/env python3

"""
SE Chain Simulator - Profile Module

Creates a safe, synthetic target profile from the authorized
laboratory configuration.

This module does NOT:
- collect personal information
- perform social-media harvesting
- identify real individuals
- contact targets
- perform victim profiling
- make authorization decisions

It only converts authorized lab metadata into a structured
simulation profile.
"""

from __future__ import annotations

from typing import Any

from se_chain.exceptions import ProfileError
from se_chain.models import (
    ChainContext,
    EventSeverity,
    EventType,
    ModuleResult,
    SimulationEvent,
)


class ProfileModule:
    """
    Generate a synthetic profile for the authorized lab target.
    """

    name = "profile"

    def run(self, context: ChainContext) -> ModuleResult:
        """
        Generate a safe simulation profile from lab metadata.
        """

        result = ModuleResult(
            module=self.name,
            success=False,
            message="Profile simulation started",
        )

        try:
            self._validate_context(context)

            profile = self._build_profile(context)

            context.data["profile"] = profile

            result.data = {
                "profile": profile,
                "mode": "synthetic_lab_profile",
                "simulated": True,
            }

            context.add_event(
                SimulationEvent(
                    event_type=EventType.PROFILE_CREATED,
                    stage="profile",
                    description=(
                        "Synthetic laboratory target profile "
                        "created for simulation."
                    ),
                    severity=EventSeverity.INFO,
                    metadata={
                        "profile_type": "synthetic_lab_profile",
                        "target": context.metadata.target,
                        "simulated": True,
                    },
                    simulated=True,
                )
            )

            result.success = True
            result.message = (
                "Synthetic laboratory target profile created"
            )

            result.complete()

            return result

        except ProfileError as exc:
            result.fail(str(exc))
            return result

        except Exception as exc:
            result.fail(
                f"Unexpected profile failure: {exc}"
            )
            return result

    # ==================================================================
    # Validation
    # ==================================================================

    @staticmethod
    def _validate_context(context: ChainContext) -> None:
        """
        Validate the chain context before profile generation.
        """

        if context is None:
            raise ProfileError(
                "Profile context is missing"
            )

        if context.metadata is None:
            raise ProfileError(
                "Profile run metadata is missing"
            )

        if not context.metadata.target:
            raise ProfileError(
                "Profile target is missing from chain context"
            )

        if not context.authorized:
            raise ProfileError(
                "Profile simulation requires an authorized lab context"
            )

        if not context.target_config:
            raise ProfileError(
                "Profile target configuration is missing"
            )

    # ==================================================================
    # Profile generation
    # ==================================================================

    @staticmethod
    def _build_profile(
        context: ChainContext,
    ) -> dict[str, Any]:
        """
        Build a synthetic profile using only authorized lab metadata.
        """

        target = context.target_config

        return {
            "profile_type": "synthetic_lab_profile",
            "target": target.get(
                "target",
                context.metadata.target,
            ),
            "target_type": target.get(
                "target_type",
                "unknown",
            ),
            "environment": target.get(
                "environment",
                "unknown",
            ),
            "authorized": target.get(
                "authorized",
                False,
            ),
            "owner": target.get(
                "owner",
                "unknown",
            ),
            "purpose": target.get(
                "purpose",
                "unknown",
            ),
            "simulation_scope": [
                "authorized_lab_metadata",
                "synthetic_profile_generation",
                "security_awareness_simulation",
            ],
            "real_person_data": False,
            "external_targeting": False,
            "simulated": True,
        }
