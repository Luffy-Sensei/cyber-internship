#!/usr/bin/env python3

"""
SE Chain Simulator - Authorization

Validates whether a simulation target has explicit authorization.
"""

from dataclasses import dataclass

from se_chain.exceptions import (
    AuthorizationError,
    ValidationError,
)


@dataclass(frozen=True)
class AuthorizationDecision:
    """
    Result of an authorization check.
    """

    authorized: bool
    reason: str


class AuthorizationValidator:
    """
    Validate explicit target authorization.
    """

    REQUIRED_FIELDS = (
        "target",
        "target_type",
        "environment",
        "authorized",
        "owner",
        "purpose",
    )

    def validate(self, target: dict) -> AuthorizationDecision:
        """
        Validate authorization metadata.

        Raises:
            ValidationError:
                If required authorization metadata is missing.

            AuthorizationError:
                If the target is explicitly unauthorized.
        """

        if not isinstance(target, dict):
            raise ValidationError(
                "Lab target configuration must be an object"
            )

        missing = [
            field
            for field in self.REQUIRED_FIELDS
            if field not in target
        ]

        if missing:
            raise ValidationError(
                "Missing required authorization fields: "
                + ", ".join(missing)
            )

        if target["authorized"] is not True:
            raise AuthorizationError(
                "Target is not explicitly authorized"
            )

        return AuthorizationDecision(
            authorized=True,
            reason="Explicit authorization confirmed",
        )
