#!/usr/bin/env python3

"""
SE Chain Simulator - Incident Response Module

Defensive incident-response simulation.

This module does NOT perform real containment, account changes,
session invalidation, notifications, or evidence collection.

It generates structured simulated IR actions for the attack-chain
engine and reporting layer.
"""

from __future__ import annotations

from typing import Any

from se_chain.exceptions import IRError
from se_chain.models import (
    ChainContext,
    EventSeverity,
    EventType,
    IRAction,
    IRActionType,
    ModuleResult,
    SimulationEvent,
)


class IRModule:
    """
    Execute defensive incident-response simulation.
    """

    name = "ir"

    def run(self, context: ChainContext) -> ModuleResult:
        """
        Generate simulated defensive response actions.
        """

        result = ModuleResult(
            module=self.name,
            success=False,
            message="Incident-response simulation started",
        )

        try:
            self._validate_context(context)

            phish_result = context.module_results.get("phish")

            risk_score = 0
            risk_level = "UNKNOWN"
            indicator_count = 0

            if phish_result is not None:
                risk_assessment = phish_result.data.get(
                    "risk_assessment",
                    {},
                )

                risk_score = risk_assessment.get(
                    "score",
                    0,
                )

                risk_level = risk_assessment.get(
                    "level",
                    "UNKNOWN",
                )

                indicator_count = risk_assessment.get(
                    "indicator_count",
                    0,
                )

            actions = self._build_actions(
                context=context,
                risk_score=risk_score,
                risk_level=risk_level,
                indicator_count=indicator_count,
            )

            for action in actions:
                context.add_ir_action(action)

            self._add_ir_event(
                context=context,
                risk_score=risk_score,
                risk_level=risk_level,
                action_count=len(actions),
            )

            result.data = {
                "response": {
                    "mode": "defensive_simulation",
                    "target": context.metadata.target,
                    "risk_score": risk_score,
                    "risk_level": risk_level,
                    "indicator_count": indicator_count,
                    "action_count": len(actions),
                },
                "actions": [
                    {
                        "action_type": action.action_type,
                        "description": action.description,
                        "status": action.status,
                        "timestamp": action.timestamp.isoformat(),
                        "metadata": action.metadata,
                    }
                    for action in actions
                ],
                "source": {
                    "module": "phish",
                    "available": phish_result is not None,
                },
            }

            result.success = True
            result.message = (
                "Defensive incident-response simulation completed"
            )

            result.complete()

            return result

        except IRError as exc:
            result.fail(str(exc))
            return result

        except Exception as exc:
            result.fail(
                f"Unexpected incident-response failure: {exc}"
            )
            return result

    # ==================================================================
    # Validation
    # ==================================================================

    @staticmethod
    def _validate_context(context: ChainContext) -> None:
        """
        Validate the chain context before performing simulation.
        """

        if context is None:
            raise IRError("IR context is missing")

        if context.metadata is None:
            raise IRError("IR run metadata is missing")

        if not context.metadata.target:
            raise IRError(
                "IR target is missing from chain context"
            )

        if not context.authorized:
            raise IRError(
                "IR simulation requires an authorized lab context"
            )

    # ==================================================================
    # Action generation
    # ==================================================================

    @staticmethod
    def _build_actions(
        context: ChainContext,
        risk_score: int,
        risk_level: str,
        indicator_count: int,
    ) -> list[IRAction]:
        """
        Build defensive simulated response actions.
        """

        target = context.metadata.target

        common_metadata: dict[str, Any] = {
            "target": target,
            "risk_score": risk_score,
            "risk_level": risk_level,
            "indicator_count": indicator_count,
            "simulated": True,
        }

        return [
            IRAction(
                action_type=IRActionType.ACCOUNT_CONTAINMENT,
                description=(
                    "Simulated containment of accounts potentially "
                    "associated with the suspicious activity."
                ),
                status="simulated",
                metadata={
                    **common_metadata,
                    "action_scope": "account",
                },
            ),
            IRAction(
                action_type=IRActionType.SESSION_INVALIDATION,
                description=(
                    "Simulated invalidation of active sessions "
                    "associated with the affected account."
                ),
                status="simulated",
                metadata={
                    **common_metadata,
                    "action_scope": "session",
                },
            ),
            IRAction(
                action_type=IRActionType.USER_NOTIFICATION,
                description=(
                    "Simulated security notification advising the "
                    "user to verify the suspicious activity."
                ),
                status="simulated",
                metadata={
                    **common_metadata,
                    "action_scope": "user",
                },
            ),
            IRAction(
                action_type=IRActionType.EVIDENCE_PRESERVATION,
                description=(
                    "Simulated preservation of relevant phishing "
                    "analysis and chain-event evidence."
                ),
                status="simulated",
                metadata={
                    **common_metadata,
                    "action_scope": "evidence",
                },
            ),
            IRAction(
                action_type=IRActionType.ALERT_GENERATION,
                description=(
                    "Simulated generation of a security alert for "
                    "the detected social-engineering activity."
                ),
                status="simulated",
                metadata={
                    **common_metadata,
                    "action_scope": "alert",
                },
            ),
        ]

    # ==================================================================
    # Simulation event
    # ==================================================================

    @staticmethod
    def _add_ir_event(
        context: ChainContext,
        risk_score: int,
        risk_level: str,
        action_count: int,
    ) -> None:
        """
        Record the defensive IR simulation event.
        """

        severity = EventSeverity.MEDIUM

        if risk_level == "HIGH":
            severity = EventSeverity.HIGH
        elif risk_level == "CRITICAL":
            severity = EventSeverity.CRITICAL

        context.add_event(
            SimulationEvent(
                event_type=EventType.IR_TRIGGERED,
                stage="incident_response",
                description=(
                    "Defensive incident-response actions were "
                    "simulated for the social-engineering scenario."
                ),
                severity=severity,
                metadata={
                    "risk_score": risk_score,
                    "risk_level": risk_level,
                    "action_count": action_count,
                },
                simulated=True,
            )
        )
