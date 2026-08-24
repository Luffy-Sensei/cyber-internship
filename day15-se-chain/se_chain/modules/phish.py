#!/usr/bin/env python3

"""
SE Chain Simulator - Phishing Analysis Module

Defensive phishing URL risk analysis for authorized security
simulation environments.

Responsibilities:
- Validate and normalize URLs
- Detect raw IP address hosts
- Parse registered domains
- Detect suspicious TLDs
- Detect brand typosquatting
- Detect Punycode / Unicode hostname indicators
- Detect suspicious authentication keywords
- Produce a normalized ModuleResult

This module does not:
- send phishing messages
- collect credentials
- submit credentials
- perform exploitation
- make authorization decisions
"""

from __future__ import annotations

import ipaddress
import math
import re
from datetime import datetime, timezone
from urllib.parse import urlparse

from se_chain.exceptions import PhishError
from se_chain.models import ChainContext, ModuleResult


# ---------------------------------------------------------------------------
# Detection configuration
# ---------------------------------------------------------------------------

COMMON_MULTI_PART_TLDS = {
    "co.uk",
    "gov.uk",
    "org.uk",
    "ac.uk",
    "com.pk",
    "gov.pk",
    "edu.pk",
    "net.pk",
    "com.au",
    "edu.au",
    "gov.au",
    "co.jp",
    "ne.jp",
    "com.br",
    "co.in",
}

KNOWN_BRANDS = {
    "paypal": {"paypal.com", "paypal.co.uk"},
    "github": {"github.com"},
    "microsoft": {
        "microsoft.com",
        "live.com",
        "office.com",
        "azure.com",
    },
    "google": {
        "google.com",
        "accounts.google.com",
    },
    "apple": {
        "apple.com",
        "icloud.com",
    },
    "amazon": {
        "amazon.com",
        "aws.amazon.com",
    },
}

SUSPICIOUS_TLDS = {
    ".tk": 10,
    ".ml": 10,
    ".ga": 10,
    ".cf": 10,
    ".xyz": 8,
    ".top": 8,
    ".club": 5,
    ".work": 10,
    ".date": 10,
    ".review": 10,
}

SUSPICIOUS_KEYWORDS = {
    "login": 15,
    "signin": 15,
    "verify": 15,
    "secure": 10,
    "update": 15,
    "account": 15,
    "bank": 20,
    "wallet": 20,
    "credential": 20,
    "authenticate": 15,
    "confirm": 10,
}


# ---------------------------------------------------------------------------
# URL validation
# ---------------------------------------------------------------------------

def validate_url(url: str) -> str:
    """
    Validate and normalize a URL.

    Supports:
    - Plain hostnames
    - HTTP/HTTPS URLs
    - Markdown links
    - Escaped Markdown syntax
    """

    if not isinstance(url, str):
        raise PhishError(
            "Phishing analysis target must be a string"
        )

    url = url.strip()

    if not url:
        raise PhishError(
            "Phishing analysis target is empty"
        )

    # Normalize escaped Markdown punctuation.
    url = (
        url.replace(r"\(", "(")
           .replace(r"\)", ")")
           .replace(r"\:", ":")
    )

    # Extract destination from Markdown:
    #
    # [Click](example.com)
    # [Click](https://example.com)
    #
    markdown_match = re.fullmatch(
        r"\s*\[.*?\]\(([^)\s]+)\)\s*",
        url,
    )

    if markdown_match:
        url = markdown_match.group(1).strip()

    # Normalize malformed scheme separators:
    #
    # http//example.com  -> example.com
    # https//example.com -> example.com
    url = re.sub(
        r"^https?//",
        "",
        url,
        flags=re.IGNORECASE,
    )

    # Add HTTPS when no scheme is present.
    if not re.match(
        r"^https?://",
        url,
        re.IGNORECASE,
    ):
        url = "https://" + url

    parsed = urlparse(url)

    if not parsed.hostname:
        raise PhishError(
            f"Invalid URL: no hostname found in '{url}'"
        )

    return url


# ---------------------------------------------------------------------------
# Host analysis
# ---------------------------------------------------------------------------

def is_ip_address(hostname: str) -> bool:
    """Return True when hostname is an IPv4 or IPv6 literal."""

    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False


def parse_domain_components(
    hostname: str,
) -> tuple[str, str, str]:
    """
    Return:

        subdomain
        registered_domain
        tld

    Example:

        login.example.com

    becomes:

        login
        example.com
        com
    """

    hostname = hostname.lower().rstrip(".")

    if is_ip_address(hostname):
        return "", hostname, "IP"

    labels = [label for label in hostname.split(".") if label]

    if len(labels) < 2:
        return "", hostname, ""

    possible_tld = ".".join(labels[-2:])

    if (
        possible_tld in COMMON_MULTI_PART_TLDS
        and len(labels) >= 3
    ):
        registered_domain = ".".join(labels[-3:])
        subdomain = ".".join(labels[:-3])
        tld = possible_tld

    else:
        registered_domain = ".".join(labels[-2:])
        subdomain = ".".join(labels[:-2])
        tld = labels[-1]

    return subdomain, registered_domain, tld


# ---------------------------------------------------------------------------
# Risk calculations
# ---------------------------------------------------------------------------

def calculate_shannon_entropy(text: str) -> float:
    """Calculate Shannon entropy for a string."""

    clean_text = text.replace(".", "").replace("-", "")

    if not clean_text:
        return 0.0

    length = len(clean_text)
    entropy = 0.0

    for char in set(clean_text):
        probability = clean_text.count(char) / length
        entropy -= probability * math.log2(probability)

    return round(entropy, 3)


def levenshtein_distance(
    first: str,
    second: str,
) -> int:
    """Calculate Levenshtein edit distance."""

    if len(first) < len(second):
        return levenshtein_distance(second, first)

    if not second:
        return len(first)

    previous_row = list(range(len(second) + 1))

    for i, char_first in enumerate(first):
        current_row = [i + 1]

        for j, char_second in enumerate(second):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = (
                previous_row[j] +
                (char_first != char_second)
            )

            current_row.append(
                min(insertions, deletions, substitutions)
            )

        previous_row = current_row

    return previous_row[-1]


# ---------------------------------------------------------------------------
# Indicator detection
# ---------------------------------------------------------------------------

def analyze_tld_risk(
    tld: str,
    indicators: list[dict],
) -> int:
    """Detect suspicious TLD reputation indicators."""

    if tld == "IP":
        return 0

    normalized = (
        tld if tld.startswith(".") else f".{tld}"
    )

    points = SUSPICIOUS_TLDS.get(normalized)

    if points is None:
        return 0

    indicators.append(
        {
            "type": "suspicious_tld",
            "severity": "medium",
            "points": points,
            "reason": (
                f"TLD '{normalized}' has elevated "
                "phishing-risk reputation."
            ),
        }
    )

    return points


def detect_typosquatting(
    registered_domain: str,
    indicators: list[dict],
) -> int:
    """Detect close variations of known brands."""

    if not registered_domain:
        return 0

    domain_name = registered_domain.split(".")[0]
    score = 0

    for brand in KNOWN_BRANDS:
        distance = levenshtein_distance(
            domain_name,
            brand,
        )

        if (
            1 <= distance <= 2
            and domain_name != brand
        ):
            indicators.append(
                {
                    "type": "typosquatting",
                    "severity": "high",
                    "points": 40,
                    "value": domain_name,
                    "reason": (
                        f"Domain '{domain_name}' resembles "
                        f"known brand '{brand}' "
                        f"(edit distance: {distance})."
                    ),
                }
            )

            score += 40

    return score


def detect_hostname_obfuscation(
    hostname: str,
    indicators: list[dict],
) -> int:
    """Detect Punycode and non-ASCII hostname indicators."""

    if not hostname or is_ip_address(hostname):
        return 0

    score = 0

    if "xn--" in hostname.lower():
        indicators.append(
            {
                "type": "punycode_homograph",
                "severity": "high",
                "points": 35,
                "reason": (
                    f"Punycode hostname detected: '{hostname}'."
                ),
            }
        )

        score += 35

    if any(ord(char) > 127 for char in hostname):
        indicators.append(
            {
                "type": "unicode_confusables",
                "severity": "high",
                "points": 30,
                "reason": (
                    "Hostname contains non-ASCII Unicode "
                    "characters."
                ),
            }
        )

        score += 30

    return score


def analyze_subdomain_entropy(
    subdomain: str,
    indicators: list[dict],
) -> int:
    """Detect unusually high-entropy subdomains."""

    if not subdomain:
        return 0

    entropy = calculate_shannon_entropy(subdomain)

    if entropy <= 3.5:
        return 0

    points = 25 if entropy > 4.0 else 15
    severity = "high" if entropy > 4.0 else "medium"

    indicators.append(
        {
            "type": "high_subdomain_entropy",
            "severity": severity,
            "points": points,
            "value": entropy,
            "reason": (
                f"Subdomain entropy is elevated "
                f"({entropy})."
            ),
        }
    )

    return points


# ---------------------------------------------------------------------------
# Main analyzer
# ---------------------------------------------------------------------------

def analyze_url(url: str) -> dict:
    """
    Analyze a URL and return structured phishing-risk data.
    """

    validated_url = validate_url(url)

    parsed = urlparse(validated_url)

    hostname = (
        parsed.hostname.lower().rstrip(".")
        if parsed.hostname
        else ""
    )

    if not hostname:
        raise PhishError(
            "Validated URL does not contain a hostname"
        )

    subdomain, registered_domain, tld = (
        parse_domain_components(hostname)
    )

    indicators: list[dict] = []
    score = 0

    # 1. Raw IP
    if is_ip_address(hostname):
        indicators.append(
            {
                "type": "raw_ip_address",
                "severity": "high",
                "points": 40,
                "reason": (
                    "URL uses a raw IP address instead "
                    "of a registered domain."
                ),
            }
        )

        score += 40

    # 2. Transport
    if parsed.scheme.lower() != "https":
        indicators.append(
            {
                "type": "transport",
                "severity": "medium",
                "points": 25,
                "reason": (
                    "URL uses unencrypted HTTP."
                ),
            }
        )

        score += 25

    # 3. Brand abuse in subdomain
    if subdomain:
        for brand, trusted_domains in KNOWN_BRANDS.items():
            if (
                brand in subdomain.lower()
                and registered_domain
                not in trusted_domains
            ):
                indicators.append(
                    {
                        "type": "subdomain_brand_abuse",
                        "severity": "high",
                        "points": 40,
                        "reason": (
                            f"Brand '{brand}' appears in "
                            f"subdomain while registered "
                            f"domain is '{registered_domain}'."
                        ),
                    }
                )

                score += 40

    # 4. Entropy
    score += analyze_subdomain_entropy(
        subdomain,
        indicators,
    )

    # 5. TLD
    score += analyze_tld_risk(
        tld,
        indicators,
    )

    # 6. Typosquatting
    score += detect_typosquatting(
        registered_domain,
        indicators,
    )

    # 7. Punycode / Unicode
    score += detect_hostname_obfuscation(
        hostname,
        indicators,
    )

    # 8. Suspicious path keywords
    full_path = (
        parsed.path + " " + parsed.query
    ).lower()

    for keyword, points in SUSPICIOUS_KEYWORDS.items():
        if keyword in full_path:
            indicators.append(
                {
                    "type": "path_keyword",
                    "severity": "low",
                    "points": points,
                    "value": keyword,
                    "reason": (
                        f"Authentication-related keyword "
                        f"'{keyword}' found in URL."
                    ),
                }
            )

            score += points

    final_score = min(score, 100)

    if final_score >= 70:
        risk_level = "HIGH"
    elif final_score >= 40:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    return {
        "url": validated_url,
        "domain_breakdown": {
            "subdomain": subdomain,
            "registered_domain": registered_domain,
            "tld": tld,
        },
        "risk_assessment": {
            "score": final_score,
            "level": risk_level,
            "indicator_count": len(indicators),
        },
        "indicators": indicators,
    }


# ---------------------------------------------------------------------------
# Chain module
# ---------------------------------------------------------------------------

class PhishModule:
    """Defensive phishing analysis module."""

    name = "phish"

    def run(
        self,
        context: ChainContext,
    ) -> ModuleResult:
        """
        Execute phishing analysis for the current chain context.
        """

        result = ModuleResult(
            module=self.name,
            success=False,
            message="Phishing analysis started",
        )

        result.started_at = datetime.now(timezone.utc)

        try:
            target = self._get_target(context)

            analysis = analyze_url(target)

            result.data = analysis
            result.success = True
            result.message = (
                "Phishing risk analysis completed"
            )

            result.complete()

            return result

        except PhishError as exc:
            result.fail(str(exc))
            return result

        except Exception as exc:
            result.fail(
                f"Unexpected phishing analysis failure: {exc}"
            )
            return result

    @staticmethod
    def _get_target(
        context: ChainContext,
    ) -> str:
        """Extract the analysis target from chain context."""

        target = context.metadata.target

        if not target:
            raise PhishError(
                "Phishing analysis target is missing "
                "from chain context"
            )

        return target
