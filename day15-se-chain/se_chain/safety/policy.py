#!/usr/bin/env python3

"""
SE Chain Simulator - Safety Policy

Defines the simulator's hard safety boundaries.
"""

from dataclasses import dataclass
import ipaddress

from se_chain.exceptions import SafetyPolicyError


@dataclass(frozen=True)
class PolicyDecision:
    """
    Result of a safety-policy evaluation.
    """

    allowed: bool
    reason: str


class SafetyPolicy:
    """
    Enforce hard safety constraints for simulation targets.
    """

    ALLOWED_ENVIRONMENT = "lab"

    def evaluate(self, target: dict) -> PolicyDecision:
        """
        Evaluate whether a target is permitted.

        The initial implementation only permits explicitly configured
        localhost targets inside the lab environment.
        """

        environment = target.get("environment")
        target_value = target.get("target")
        target_type = target.get("target_type")

        if environment != self.ALLOWED_ENVIRONMENT:
            raise SafetyPolicyError(
                "Target environment is not permitted"
            )

        if target_type != "localhost":
            raise SafetyPolicyError(
                "Only localhost targets are permitted"
            )

        if not self._is_localhost(target_value):
            raise SafetyPolicyError(
                "Target must resolve to localhost"
            )

        return PolicyDecision(
            allowed=True,
            reason="Target satisfies lab safety policy",
        )

    @staticmethod
    def _is_localhost(value: str) -> bool:
        """
        Return True only for loopback IP addresses.
        """

        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            return value.lower() == "localhost"

        return address.is_loopback
