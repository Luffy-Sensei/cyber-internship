#!/usr/bin/env python3

"""
SE Chain Simulator - Exception Hierarchy

Application-specific exceptions used to provide predictable and
controlled error handling.
"""


class SEChainError(Exception):
    """
    Base exception for all SE Chain Simulator errors.
    """

    default_message = "SE Chain Simulator error"

    def __init__(self, message: str | None = None) -> None:
        super().__init__(message or self.default_message)


# ---------------------------------------------------------------------------
# Configuration Errors
# ---------------------------------------------------------------------------

class ConfigurationError(SEChainError):
    """
    Raised when application configuration is invalid or unavailable.
    """

    default_message = "Invalid application configuration"


# ---------------------------------------------------------------------------
# Validation Errors
# ---------------------------------------------------------------------------

class ValidationError(SEChainError):
    """
    Raised when input data fails validation.
    """

    default_message = "Input validation failed"


# ---------------------------------------------------------------------------
# Safety / Authorization Errors
# ---------------------------------------------------------------------------

class AuthorizationError(SEChainError):
    """
    Raised when the requested operation is not authorized.
    """

    default_message = "Operation is not authorized"


class SafetyPolicyError(SEChainError):
    """
    Raised when an operation violates a simulator safety policy.
    """

    default_message = "Safety policy violation"


# ---------------------------------------------------------------------------
# Module Errors
# ---------------------------------------------------------------------------

class ModuleError(SEChainError):
    """
    Base exception for module-level failures.
    """

    default_message = "Simulator module execution failed"


class OSINTError(ModuleError):
    """
    Raised when the OSINT module encounters an operational failure.
    """

    default_message = "OSINT module failed"


class ProfileError(ModuleError):
    """
    Raised when profile generation fails.
    """

    default_message = "Profile module failed"


class PhishError(ModuleError):
    """
    Raised when phishing analysis fails.
    """

    default_message = "Phishing analysis module failed"


class TemplateError(ModuleError):
    """
    Raised when training-template generation fails.
    """

    default_message = "Template module failed"


class IRError(ModuleError):
    """
    Raised when incident-response processing fails.
    """

    default_message = "Incident-response module failed"


# ---------------------------------------------------------------------------
# Reporting Errors
# ---------------------------------------------------------------------------

class ReportingError(SEChainError):
    """
    Raised when report generation fails.
    """

    default_message = "Report generation failed"


# ---------------------------------------------------------------------------
# Engine Errors
# ---------------------------------------------------------------------------

class ChainExecutionError(SEChainError):
    """
    Raised when the attack-chain simulation cannot continue.
    """

    default_message = "SE chain execution failed"
