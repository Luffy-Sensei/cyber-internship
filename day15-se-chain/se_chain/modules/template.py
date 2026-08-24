#!/usr/bin/env python3

"""
SE Chain Simulator - Training Template Module

Defensive security-awareness template generation.

This module does NOT send messages or perform phishing delivery.
It generates simulated training material from the phishing-analysis
stage of the SE Chain.
"""

from __future__ import annotations

from se_chain.exceptions import AuthorizationError, TemplateError
from se_chain.models import (
    ChainContext,
    EventSeverity,
    EventType,
    ModuleResult,
    SimulationEvent,
)


class TemplateModule:
    """Generate defensive security-awareness training material."""

    name = "template"

    def run(self, context: ChainContext) -> ModuleResult:
        """Generate a simulated training template."""

        result = ModuleResult(
            module=self.name,
            success=False,
            status="running",
        )

        try:
            # Safety boundary: template generation requires authorization.
            if not context.authorized:
                raise AuthorizationError(
                    "Training template generation requires authorization"
                )

            # Read the phishing-analysis result if available.
            phish_result = context.module_results.get("phish")

            if phish_result is None:
                result.warnings.append(
                    "Phishing analysis result was not available; "
                    "template generated with limited context."
                )
                phish_data = {}
            else:
                phish_data = phish_result.data

            risk_assessment = phish_data.get(
                "risk_assessment",
                {},
            )

            risk_score = risk_assessment.get("score", 0)
            risk_level = risk_assessment.get("level", "UNKNOWN")

            indicators = phish_data.get("indicators", [])

            indicator_types = [
                indicator.get("type", "unknown")
                for indicator in indicators
            ]

            target = context.metadata.target

            training_template = {
                "purpose": "security_awareness_training",
                "delivery": "simulated_only",
                "target": target,
                "risk_score": risk_score,
                "risk_level": risk_level,
                "indicator_types": indicator_types,
                "learning_objectives": [
                    "Identify suspicious URL characteristics",
                    "Recognize phishing risk indicators",
                    "Verify links before authentication",
                    "Report suspicious messages through approved channels",
                ],
                "defensive_message": (
                    "Training simulation: inspect the destination URL, "
                    "verify the domain, and avoid entering credentials "
                    "when the destination appears suspicious."
                ),
            }

            result.data = {
                "template": training_template,
                "source": {
                    "module": "phish",
                    "risk_score": risk_score,
                    "risk_level": risk_level,
                    "indicator_count": len(indicators),
                },
            }

            result.message = (
                "Security-awareness training template generated"
            )

            result.success = True
            result.status = "completed"

            context.add_event(
                SimulationEvent(
                    event_type=EventType.TEMPLATE_GENERATED,
                    stage="template",
                    description=(
                        "Generated defensive security-awareness "
                        "training material from phishing analysis."
                    ),
                    severity=EventSeverity.INFO,
                    metadata={
                        "risk_score": risk_score,
                        "risk_level": risk_level,
                        "indicator_count": len(indicators),
                    },
                    simulated=True,
                )
            )

            result.complete()
            return result

        except AuthorizationError:
            result.fail(
                "Training template generation requires authorization"
            )
            raise

        except Exception as exc:
            result.fail(str(exc))
            raise TemplateError(
                f"Training template generation failed: {exc}"
            ) from exc
