from __future__ import annotations

import json
import logging
from collections.abc import Iterable
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from .models import (
    FirewallAction,
    FirewallExecution,
    ThreatFeed,
)


class ThreatIntelReportWriter:
    """Build and persist auditable Day 24 pipeline evidence."""

    def __init__(
        self,
        *,
        report_directory: str | Path = "output/reports",
        log_directory: str | Path = "output/logs",
    ) -> None:
        self.report_directory = Path(report_directory)
        self.log_directory = Path(log_directory)

    def build_report(
        self,
        feed: ThreatFeed,
        executions: Iterable[FirewallExecution],
        *,
        rejected: int = 0,
        pipeline_id: str | None = None,
        validation_status: str = "VALIDATED",
        execution_mode: str = "DRY-RUN",
        policy: str | None = None,
    ) -> dict:
        """Build a JSON-serializable audit report."""

        execution_list = tuple(executions)

        decisions = [
            self._serialize_execution(execution)
            for execution in execution_list
        ]

        blocks_proposed = sum(
            execution.action is FirewallAction.BLOCK
            and execution.status.value == "PROPOSED"
            for execution in execution_list
        )

        monitored = sum(
            execution.action is FirewallAction.MONITOR
            for execution in execution_list
        )

        ignored = sum(
            execution.action is FirewallAction.IGNORE
            for execution in execution_list
        )

        return {
            "pipeline_id": pipeline_id or str(uuid4()),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "feed_id": feed.feed_id,
            "feed_source": feed.source,
            "indicators_received": (
                len(feed.indicators) + rejected
            ),
            "indicators_valid": len(feed.indicators),
            "blocks_proposed": blocks_proposed,
            "monitored": monitored,
            "ignored": ignored,
            "rejected": rejected,
            "policy": policy or self._resolve_policy(execution_list),
            "execution_mode": execution_mode,
            "validation_status": validation_status,
            "firewall_modification": False,
            "decisions": decisions,
        }

    def write_json(
        self,
        report: dict,
        filename: str = "day24_threat_intel.json",
    ) -> Path:
        """Write structured JSON evidence."""

        self.report_directory.mkdir(
            parents=True,
            exist_ok=True,
        )

        output_path = self.report_directory / filename

        with output_path.open("w", encoding="utf-8") as handle:
            json.dump(
                report,
                handle,
                indent=2,
                sort_keys=True,
            )
            handle.write("\n")

        return output_path

    def write_text(
        self,
        report: dict,
        filename: str = "day24_threat_intel.txt",
    ) -> Path:
        """Write human-readable audit evidence."""

        self.report_directory.mkdir(
            parents=True,
            exist_ok=True,
        )

        output_path = self.report_directory / filename

        lines = [
            "DAY 24 - THREAT INTELLIGENCE PIPELINE REPORT",
            "=" * 62,
            f"Pipeline ID          : {report['pipeline_id']}",
            f"Timestamp            : {report['timestamp']}",
            f"Feed ID              : {report['feed_id']}",
            f"Feed Source          : {report['feed_source']}",
            f"Indicators Received  : {report['indicators_received']}",
            f"Indicators Valid     : {report['indicators_valid']}",
            f"Blocks Proposed      : {report['blocks_proposed']}",
            f"Monitored            : {report['monitored']}",
            f"Ignored              : {report['ignored']}",
            f"Rejected             : {report['rejected']}",
            f"Policy               : {report['policy']}",
            f"Execution Mode       : {report['execution_mode']}",
            f"Validation Status    : {report['validation_status']}",
            f"Firewall Modification: {report['firewall_modification']}",
            "",
            "DECISIONS",
            "-" * 62,
        ]

        for decision in report["decisions"]:
            lines.extend(
                [
                    f"IP       : {decision['ip']}",
                    f"Indicator: {decision['indicator']}",
                    f"Risk     : {decision['risk_score']}",
                    f"Action   : {decision['action']}",
                    f"Status   : {decision['status']}",
                    f"Reason   : {decision['reason']}",
                    f"Policy   : {decision['policy']}",
                    f"Mode     : {decision['mode']}",
                    "",
                ]
            )

        lines.extend(
            [
                "AUDIT RESULT",
                "-" * 62,
                "Firewall modification : NONE",
                f"Validation status     : {report['validation_status']}",
            ]
        )

        output_path.write_text(
            "\n".join(lines) + "\n",
            encoding="utf-8",
        )

        return output_path

    def configure_logging(
        self,
        filename: str = "day24_threat_intel.log",
    ) -> Path:
        """Configure a file logger for pipeline audit events."""

        self.log_directory.mkdir(
            parents=True,
            exist_ok=True,
        )

        log_path = self.log_directory / filename

        logger = logging.getLogger("day24.threat_intel")

        if not logger.handlers:
            handler = logging.FileHandler(
                log_path,
                encoding="utf-8",
            )
            handler.setFormatter(
                logging.Formatter(
                    "%(asctime)s %(levelname)s %(message)s"
                )
            )
            logger.addHandler(handler)
            logger.setLevel(logging.INFO)
            logger.propagate = False

        return log_path

    def log_report(
        self,
        report: dict,
        *,
        log_path: str | Path | None = None,
    ) -> Path:
        """Write high-level pipeline events to the audit log."""

        if log_path is None:
            log_path = self.configure_logging()

        logger = logging.getLogger("day24.threat_intel")

        logger.info(
            "pipeline_id=%s feed_id=%s source=%s "
            "indicators_received=%d indicators_valid=%d "
            "blocks_proposed=%d monitored=%d ignored=%d "
            "rejected=%d mode=%s validation=%s",
            report["pipeline_id"],
            report["feed_id"],
            report["feed_source"],
            report["indicators_received"],
            report["indicators_valid"],
            report["blocks_proposed"],
            report["monitored"],
            report["ignored"],
            report["rejected"],
            report["execution_mode"],
            report["validation_status"],
        )

        for decision in report["decisions"]:
            logger.info(
                "decision ip=%s indicator=%s risk=%d "
                "action=%s status=%s",
                decision["ip"],
                decision["indicator"],
                decision["risk_score"],
                decision["action"],
                decision["status"],
            )

        logger.info(
            "firewall_modification=%s",
            report["firewall_modification"],
        )

        return Path(log_path)

    @staticmethod
    def _serialize_execution(
        execution: FirewallExecution,
    ) -> dict:
        """Convert an execution record into JSON-safe data."""

        return {
            "ip": execution.ip,
            "indicator": execution.indicator,
            "risk_score": execution.risk_score,
            "action": execution.action.value,
            "status": execution.status.value,
            "reason": execution.reason,
            "policy": execution.policy,
            "mode": execution.mode.value,
            "rule": (
                {
                    "ip": execution.rule.ip,
                    "reason": execution.rule.reason,
                    "source": execution.rule.source,
                    "enabled": execution.rule.enabled,
                }
                if execution.rule is not None
                else None
            ),
        }

    @staticmethod
    def _resolve_policy(
        executions: tuple[FirewallExecution, ...],
    ) -> str:
        """Resolve the policy name from execution records."""

        if not executions:
            return "unknown"

        return executions[0].policy
