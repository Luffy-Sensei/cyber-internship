#!/usr/bin/env python3

"""
SE Chain Simulator - Attack Chain Engine

Phase 5:
- Pipeline orchestration
- Simulation events
- Detection events
- Defensive IR triggering
- Structured error recovery
- Centralized logging

The engine coordinates simulation modules. It does not implement
offensive actions itself.
"""

from __future__ import annotations

from typing import Any

from se_chain.exceptions import ChainExecutionError
from se_chain.logger import LoggerManager
from se_chain.models import (
    ChainContext,
    ChainStatus,
    EventSeverity,
    EventType,
    SimulationEvent,
)
from se_chain.modules.osint import OSINTModule
from se_chain.modules.phish import PhishModule
from se_chain.modules.profile import ProfileModule
from se_chain.modules.template import TemplateModule
from se_chain.modules.ir import IRModule


class ChainEngine:
    """
    Orchestrates the authorized SE Chain simulation.

    Pipeline:

        OSINT
          ↓
        PROFILE
          ↓
        PHISH
          ↓
        TEMPLATE
          ↓
        DETECTION
          ↓
        IR

    All activity remains simulated and defensive.
    """

    name = "chain-engine"

    def __init__(
        self,
        osint_module: OSINTModule | None = None,
        profile_module: ProfileModule | None = None,
        phish_module: PhishModule | None = None,
        template_module: TemplateModule | None = None,
        ir_module: IRModule | None = None,
    ) -> None:

        self.osint = osint_module or OSINTModule()
        self.profile = profile_module or ProfileModule()
        self.phish = phish_module or PhishModule()
        self.template = template_module or TemplateModule()
        self.ir = ir_module or IRModule()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def run(self, context: ChainContext) -> ChainContext:
        """
        Execute the complete authorized simulation pipeline.

        Raises:
            ChainExecutionError:
                If the simulation cannot continue safely.
        """

        if context is None:
            raise ChainExecutionError("Chain context is missing")

        logger = LoggerManager(
            log_directory=self._get_log_directory(context),
            run_id=context.metadata.run_id,
        ).get_logger()

        logger.info("Chain execution requested")

        # --------------------------------------------------------------
        # Authorization gate
        # --------------------------------------------------------------

        if not context.authorized:
            context.metadata.mark_blocked()

            context.add_error(
                "Simulation blocked: target is not authorized"
            )

            logger.warning(
                "Simulation blocked: target is not authorized"
            )

            context.add_event(
                SimulationEvent(
                    event_type=EventType.MODULE_COMPLETED,
                    stage="safety",
                    description=(
                        "Simulation blocked by authorization policy"
                    ),
                    severity=EventSeverity.HIGH,
                    metadata={
                        "authorized": False,
                        "status": ChainStatus.BLOCKED,
                    },
                    simulated=True,
                )
            )

            raise ChainExecutionError(
                "Simulation blocked: target is not authorized"
            )

        # --------------------------------------------------------------
        # Start execution
        # --------------------------------------------------------------

        context.metadata.mark_started()

        logger.info(
            "Chain execution started for target=%s",
            context.metadata.target,
        )

        try:
            self._run_osint(context)
            self._run_profile(context)
            self._run_phish(context)
            self._run_template(context)

            self._detect_phishing(context)
            self._trigger_ir(context)

            context.metadata.mark_completed()

            logger.info("Chain execution completed successfully")

            return context

        except ChainExecutionError:
            context.metadata.mark_failed()

            logger.error(
                "Chain execution failed: %s",
                context.errors[-1] if context.errors else "unknown error",
            )

            raise

        except Exception as exc:
            context.add_error(str(exc))
            context.metadata.mark_failed()

            logger.exception(
                "Unexpected chain execution failure"
            )

            raise ChainExecutionError(
                f"Attack-chain simulation failed: {exc}"
            ) from exc

    # ------------------------------------------------------------------
    # Pipeline stages
    # ------------------------------------------------------------------

    def _run_osint(self, context: ChainContext) -> None:
        """Execute passive OSINT."""

        self._run_module(
            context=context,
            module_name="osint",
            module=self.osint,
            failure_message="OSINT stage failed",
        )

    def _run_profile(self, context: ChainContext) -> None:
        """Execute synthetic laboratory profile generation."""

        self._run_module(
            context=context,
            module_name="profile",
            module=self.profile,
            failure_message="Profile stage failed",
        )

    def _run_phish(self, context: ChainContext) -> None:
        """Execute phishing-risk analysis."""

        self._run_module(
            context=context,
            module_name="phish",
            module=self.phish,
            failure_message="Phishing analysis stage failed",
        )

    def _run_template(self, context: ChainContext) -> None:
        """Generate the defensive training template."""

        self._run_module(
            context=context,
            module_name="template",
            module=self.template,
            failure_message="Training-template stage failed",
        )

    # ------------------------------------------------------------------
    # Generic module runner
    # ------------------------------------------------------------------

    def _run_module(
        self,
        context: ChainContext,
        module_name: str,
        module: Any,
        failure_message: str,
    ) -> None:
        """
        Execute a module using a standardized error-handling path.
        """

        logger = LoggerManager(
            log_directory=self._get_log_directory(context),
            run_id=context.metadata.run_id,
        ).get_logger()

        logger.info(
            "Starting module: %s",
            module_name,
        )

        try:
            result = module.run(context)

        except Exception as exc:
            context.add_error(
                f"{module_name}: {exc}"
            )

            context.add_event(
                SimulationEvent(
                    event_type=EventType.MODULE_COMPLETED,
                    stage=module_name,
                    description=(
                        f"{module_name.upper()} module failed"
                    ),
                    severity=EventSeverity.HIGH,
                    metadata={
                        "module": module_name,
                        "success": False,
                        "error": str(exc),
                    },
                    simulated=True,
                )
            )

            logger.exception(
                "Module failed: %s",
                module_name,
            )

            raise ChainExecutionError(
                failure_message
            ) from exc

        context.add_module_result(result)

        self._record_module_event(
            context=context,
            module=module_name,
            result=result,
        )

        if result.warnings:
            logger.warning(
                "%s completed with %d warning(s)",
                module_name,
                len(result.warnings),
            )

        if not result.success:
            error_message = (
                result.errors[-1]
                if result.errors
                else failure_message
            )

            context.add_error(
                f"{module_name}: {error_message}"
            )

            logger.error(
                "%s reported failure: %s",
                module_name,
                error_message,
            )

            raise ChainExecutionError(
                failure_message
            )

        logger.info(
            "Module completed successfully: %s",
            module_name,
        )

    # ------------------------------------------------------------------
    # Detection
    # ------------------------------------------------------------------

    def _detect_phishing(self, context: ChainContext) -> None:
        """
        Convert phishing-analysis results into a detection event.
        """

        logger = LoggerManager(
            log_directory=self._get_log_directory(context),
            run_id=context.metadata.run_id,
        ).get_logger()

        result = context.module_results.get("phish")

        if result is None:
            raise ChainExecutionError(
                "Cannot perform detection: phishing result missing"
            )

        risk = result.data.get(
            "risk_assessment",
            {},
        )

        score = risk.get("score", 0)
        level = risk.get("level", "UNKNOWN")
        indicator_count = risk.get(
            "indicator_count",
            0,
        )

        if score <= 0:
            logger.info(
                "No phishing detection threshold reached"
            )
            return

        severity = self._risk_to_severity(level)

        context.add_event(
            SimulationEvent(
                event_type=EventType.ALERT,
                stage="detection",
                description=(
                    "Phishing risk detected from analyzed URL"
                ),
                severity=severity,
                metadata={
                    "risk_score": score,
                    "risk_level": level,
                    "indicator_count": indicator_count,
                },
                simulated=True,
            )
        )

        logger.warning(
            "Phishing risk detected: score=%s level=%s",
            score,
            level,
        )

    # ------------------------------------------------------------------
    # Incident Response
    # ------------------------------------------------------------------

    def _trigger_ir(self, context: ChainContext) -> None:
        """
        Trigger defensive incident response when phishing risk
        reaches a meaningful detection threshold.
        """

        logger = LoggerManager(
            log_directory=self._get_log_directory(context),
            run_id=context.metadata.run_id,
        ).get_logger()

        result = context.module_results.get("phish")

        if result is None:
            raise ChainExecutionError(
                "Cannot trigger IR: phishing result missing"
            )

        risk = result.data.get(
            "risk_assessment",
            {},
        )

        score = risk.get("score", 0)
        level = risk.get("level", "UNKNOWN")

        if score <= 0:
            logger.info(
                "IR not triggered: phishing score is zero"
            )
            return

        severity = self._risk_to_severity(level)

        context.add_event(
            SimulationEvent(
                event_type=EventType.IR_TRIGGERED,
                stage="incident_response",
                description=(
                    "Defensive incident response triggered "
                    "by phishing-risk detection"
                ),
                severity=severity,
                metadata={
                    "risk_score": score,
                    "risk_level": level,
                    "trigger": "phishing_detection",
                },
                simulated=True,
            )
        )

        logger.warning(
            "Defensive IR triggered: risk_score=%s level=%s",
            score,
            level,
        )

        try:
            result = self.ir.run(context)

        except Exception as exc:
            context.add_error(
                f"ir: {exc}"
            )

            logger.exception(
                "Incident-response module failed"
            )

            raise ChainExecutionError(
                "Incident-response stage failed"
            ) from exc

        context.add_module_result(result)

        self._record_module_event(
            context=context,
            module="ir",
            result=result,
        )

        if not result.success:
            error_message = (
                result.errors[-1]
                if result.errors
                else "Incident-response stage failed"
            )

            context.add_error(
                f"ir: {error_message}"
            )

            logger.error(
                "Incident-response module reported failure: %s",
                error_message,
            )

            raise ChainExecutionError(
                "Incident-response stage failed"
            )

        logger.info(
            "Incident-response simulation completed"
        )

    # ------------------------------------------------------------------
    # Event helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _record_module_event(
        context: ChainContext,
        module: str,
        result: Any,
    ) -> None:
        """Record standardized module completion event."""

        context.add_event(
            SimulationEvent(
                event_type=EventType.MODULE_COMPLETED,
                stage=module,
                description=(
                    f"{module.upper()} module completed"
                ),
                severity=(
                    EventSeverity.INFO
                    if result.success
                    else EventSeverity.HIGH
                ),
                metadata={
                    "module": module,
                    "success": result.success,
                    "status": result.status,
                    "warnings": len(result.warnings),
                    "errors": len(result.errors),
                },
                simulated=True,
            )
        )

    # ------------------------------------------------------------------
    # Utility
    # ------------------------------------------------------------------

    @staticmethod
    def _risk_to_severity(level: str) -> str:
        """Map phishing risk levels to event severity."""

        mapping = {
            "LOW": EventSeverity.LOW,
            "MEDIUM": EventSeverity.MEDIUM,
            "HIGH": EventSeverity.HIGH,
            "CRITICAL": EventSeverity.CRITICAL,
        }

        return mapping.get(
            str(level).upper(),
            EventSeverity.INFO,
        )

    @staticmethod
    def _get_log_directory(context: ChainContext):
        """
        Resolve the application log directory.

        Kept isolated so logging-path configuration does not leak
        throughout the engine.
        """

        from se_chain.config import OUTPUT_DIR

        return OUTPUT_DIR / "logs"