from __future__ import annotations

from .models import (
    BlockRule,
    FirewallAction,
    FirewallDecision,
    FirewallExecution,
    FirewallMode,
    RuleStatus,
)


class FirewallAdapter:
    """Translate policy decisions into safe firewall execution records.

    The adapter intentionally does not invoke iptables, nftables,
    firewalld, or another host firewall command.

    DRY_RUN is the only operational mode used by this lab.
    """

    def __init__(self, mode: FirewallMode = FirewallMode.DRY_RUN):
        self.mode = mode

    def process(
        self,
        decision: FirewallDecision,
        *,
        source: str,
    ) -> FirewallExecution:
        """Process one firewall decision without modifying the host."""

        if not source.strip():
            raise ValueError("source must not be empty")

        if decision.action is not FirewallAction.BLOCK:
            return FirewallExecution(
                ip=decision.ip,
                indicator=decision.indicator,
                action=decision.action,
                mode=self.mode,
                status=RuleStatus.SKIPPED,
                reason=(
                    f"No firewall block rule generated for "
                    f"{decision.action.value} decision."
                ),
                risk_score=decision.risk_score,
                policy=decision.policy,
            )

        rule = BlockRule(
            ip=decision.ip,
            indicator=decision.indicator,
            reason=decision.reason,
            source=source,
            enabled=True,
        )

        return FirewallExecution(
            ip=decision.ip,
            indicator=decision.indicator,
            action=decision.action,
            mode=self.mode,
            status=RuleStatus.PROPOSED,
            reason=decision.reason,
            risk_score=decision.risk_score,
            policy=decision.policy,
            rule=rule,
        )

    def process_many(
        self,
        decisions: tuple[FirewallDecision, ...],
        *,
        source: str,
    ) -> tuple[FirewallExecution, ...]:
        """Process multiple decisions deterministically."""

        return tuple(
            self.process(
                decision,
                source=source,
            )
            for decision in decisions
        )
