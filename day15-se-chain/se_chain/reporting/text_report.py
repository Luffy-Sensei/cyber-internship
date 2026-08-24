#!/usr/bin/env python3

"""
SE Chain Simulator - Text Reporting
"""

from __future__ import annotations

from pathlib import Path

from se_chain.exceptions import ReportingError
from se_chain.models import ChainContext


class TextReporter:
    """Generate human-readable text reports."""

    name = "text"

    def generate(
        self,
        context: ChainContext,
        output_path: Path,
    ) -> Path:
        """Generate a text report."""

        if context is None:
            raise ReportingError("Cannot generate report from missing context")

        try:
            output_path.parent.mkdir(
                parents=True,
                exist_ok=True,
            )

            report = self._build_report(context)

            output_path.write_text(
                report,
                encoding="utf-8",
            )

            return output_path

        except ReportingError:
            raise

        except Exception as exc:
            raise ReportingError(
                f"Text report generation failed: {exc}"
            ) from exc

    @staticmethod
    def _build_report(context: ChainContext) -> str:
        """Build the human-readable report."""

        lines: list[str] = []

        lines.append("=" * 70)
        lines.append("SE CHAIN SIMULATOR - RUN REPORT")
        lines.append("=" * 70)
        lines.append("")

        lines.append("RUN")
        lines.append("-" * 70)
        lines.append(f"Run ID : {context.metadata.run_id}")
        lines.append(f"Target : {context.metadata.target}")
        lines.append(f"Mode   : {context.metadata.mode}")
        lines.append(f"Status : {context.metadata.status}")
        lines.append("")

        lines.append("AUTHORIZATION")
        lines.append("-" * 70)
        lines.append(f"Authorized : {context.authorized}")
        lines.append("")

        lines.append("MODULES")
        lines.append("-" * 70)

        for name, result in context.module_results.items():
            lines.append(
                f"{name}: "
                f"{'SUCCESS' if result.success else 'FAILED'}"
            )
            lines.append(f"  Status  : {result.status}")
            lines.append(f"  Message : {result.message}")

            if result.warnings:
                lines.append("  Warnings:")
                for warning in result.warnings:
                    lines.append(f"    - {warning}")

            if result.errors:
                lines.append("  Errors:")
                for error in result.errors:
                    lines.append(f"    - {error}")

            lines.append("")

        lines.append("EVENTS")
        lines.append("-" * 70)

        for event in context.events:
            lines.append(
                f"[{event.severity.upper()}] "
                f"{event.event_type} "
                f"({event.stage})"
            )
            lines.append(f"  {event.description}")

        lines.append("")

        lines.append("INCIDENT RESPONSE ACTIONS")
        lines.append("-" * 70)

        for action in context.ir_actions:
            lines.append(
                f"- {action.action_type}: {action.status}"
            )
            lines.append(f"  {action.description}")

        lines.append("")

        lines.append("SUMMARY")
        lines.append("-" * 70)
        lines.append(f"Events generated : {len(context.events)}")
        lines.append(f"IR actions       : {len(context.ir_actions)}")

        phish_result = context.module_results.get("phish")

        if phish_result:
            risk = phish_result.data.get(
                "risk_assessment",
                {},
            )

            lines.append(
                f"Risk score       : {risk.get('score', 0)}"
            )
            lines.append(
                f"Risk level       : {risk.get('level', 'UNKNOWN')}"
            )

        lines.append("")
        lines.append("=" * 70)

        return "\n".join(lines) + "\n"
