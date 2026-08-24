#!/usr/bin/env python3

"""
SE Chain Simulator - JSON Reporting

Serializes a completed ChainContext into a structured JSON report.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from se_chain.exceptions import ReportingError
from se_chain.models import ChainContext


class JSONReporter:
    """Generate JSON reports from ChainContext."""

    name = "json"

    def generate(
        self,
        context: ChainContext,
        output_path: Path,
    ) -> Path:
        """
        Generate a JSON report.

        Args:
            context: Completed simulation context.
            output_path: Destination JSON file.

        Returns:
            Path to the generated report.
        """

        if context is None:
            raise ReportingError("Cannot generate report from missing context")

        try:
            output_path.parent.mkdir(
                parents=True,
                exist_ok=True,
            )

            report = self._build_report(context)

            with output_path.open(
                "w",
                encoding="utf-8",
            ) as file:
                json.dump(
                    report,
                    file,
                    indent=2,
                    ensure_ascii=False,
                )

            return output_path

        except ReportingError:
            raise

        except Exception as exc:
            raise ReportingError(
                f"JSON report generation failed: {exc}"
            ) from exc

    @staticmethod
    def _build_report(
        context: ChainContext,
    ) -> dict[str, Any]:
        """Build the serializable report structure."""

        return {
            "application": context.metadata.application,
            "version": context.metadata.version,

            "run": {
                "run_id": context.metadata.run_id,
                "target": context.metadata.target,
                "mode": context.metadata.mode,
                "status": context.metadata.status,
                "started_at": context.metadata.started_at.isoformat(),
                "completed_at": (
                    context.metadata.completed_at.isoformat()
                    if context.metadata.completed_at
                    else None
                ),
            },

            "authorization": {
                "authorized": context.authorized,
            },

            "modules": {
                name: {
                    "module": result.module,
                    "success": result.success,
                    "message": result.message,
                    "status": result.status,
                    "data": result.data,
                    "warnings": result.warnings,
                    "errors": result.errors,
                    "started_at": result.started_at.isoformat(),
                    "completed_at": (
                        result.completed_at.isoformat()
                        if result.completed_at
                        else None
                    ),
                }
                for name, result in context.module_results.items()
            },

            "events": [
                {
                    "event_type": event.event_type,
                    "stage": event.stage,
                    "description": event.description,
                    "severity": event.severity,
                    "timestamp": event.timestamp.isoformat(),
                    "metadata": event.metadata,
                    "simulated": event.simulated,
                }
                for event in context.events
            ],

            "ir_actions": [
                {
                    "action_type": action.action_type,
                    "description": action.description,
                    "status": action.status,
                    "timestamp": action.timestamp.isoformat(),
                    "metadata": action.metadata,
                }
                for action in context.ir_actions
            ],

            "errors": context.errors,
        }
