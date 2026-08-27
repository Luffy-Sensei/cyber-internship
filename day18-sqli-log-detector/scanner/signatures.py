from dataclasses import dataclass
import re


@dataclass(frozen=True)
class Signature:
    """A SQL injection detection signature."""

    name: str
    pattern: re.Pattern[str]
    confidence: str
    description: str


SIGNATURES = (
    Signature(
        name="UNION_SELECT",
        pattern=re.compile(r"\bUNION\s+SELECT\b", re.IGNORECASE),
        confidence="HIGH",
        description="SQL UNION SELECT syntax detected.",
    ),
    Signature(
        name="TAUTOLOGY",
        pattern=re.compile(
            r"\bOR\s+(?:['\"]?\d+['\"]?)\s*=\s*(?:['\"]?\d+['\"]?)",
            re.IGNORECASE,
        ),
        confidence="HIGH",
        description="OR-based tautological SQL condition detected.",
    ),
    Signature(
        name="SQL_COMMENT",
        pattern=re.compile(r"(?:--|#)", re.IGNORECASE),
        confidence="MEDIUM",
        description="SQL comment syntax detected.",
    ),
)
