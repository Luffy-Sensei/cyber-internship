#!/usr/bin/env python3
"""
Day 03 — Advanced Phishing Page Anatomy & URL Risk Detector
Sqrock Cybersecurity Internship - Phase 1

Defensive security analyzer incorporating:
1. Markdown URL normalization & string validation.
2. IP address literal detection (bypassing PSL domain splits).
3. Multi-part Public Suffix List (PSL) domain parsing.
4. Homograph & Typosquatting (Levenshtein distance) detection.
5. Normalized Shannon Entropy calculation for DGA detection.
6. High-risk TLD reputation scoring.
7. Passive HTML DOM inspection (external forms, urgency triggers, unencrypted passwords).
8. Categorized risk reporting and colorized CLI output.
"""

import argparse
import ipaddress
import json
import math
import re
import sys
import unicodedata
import urllib.request
from datetime import datetime, timezone
from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse

# Optional colorama import for CLI presentation
try:
    from colorama import Fore, Style, init
    init(autoreset=True)
    COLOR_ENABLED = True
except ImportError:
    COLOR_ENABLED = False


# ---------------------------------------------------------------------------
# Configuration & Risk Taxonomies
# ---------------------------------------------------------------------------

COMMON_MULTI_PART_TLDS = {
    "co.uk", "gov.uk", "org.uk", "ac.uk",
    "com.pk", "gov.pk", "edu.pk", "net.pk",
    "com.au", "edu.au", "gov.au",
    "co.jp", "ne.jp", "com.br", "co.in"
}

KNOWN_BRANDS = {
    "paypal": {"paypal.com", "paypal.co.uk"},
    "github": {"github.com"},
    "microsoft": {"microsoft.com", "live.com", "office.com", "azure.com"},
    "google": {"google.com", "accounts.google.com"},
    "apple": {"apple.com", "icloud.com"},
    "amazon": {"amazon.com", "aws.amazon.com"},
}

SUSPICIOUS_TLDS = {
    ".tk": 10, ".ml": 10, ".ga": 10, ".cf": 10,  # Legacy free domain TLDs
    ".xyz": 8, ".top": 8, ".club": 5,             # Low-cost gTLDs
    ".work": 10, ".date": 10, ".review": 10       # High phishing prevalence
}

SUSPICIOUS_KEYWORDS = {
    "login": 15, "signin": 15, "verify": 15, "secure": 10,
    "update": 15, "account": 15, "bank": 20, "wallet": 20,
    "credential": 20, "authenticate": 15, "confirm": 10
}

URGENCY_KEYWORDS = [
    "suspended", "24 hours", "unauthorized access", "action required",
    "immediate action", "account locked", "verify immediately"
]


# ---------------------------------------------------------------------------
# Input Validation & Domain/IP Component Extraction
# ---------------------------------------------------------------------------

def is_ip_address(hostname: str) -> bool:
    """Check if hostname is a valid IPv4 or IPv6 address literal."""
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False


def validate_url(url: str) -> str:
    """Validate, unwrap Markdown links, and normalize URL string."""
    url = url.strip()
    if not url:
        raise ValueError("URL cannot be empty")
    
    # Extract actual URL if wrapped in Markdown link format [text](url)
    md_match = re.search(r'\[.*?\]\((https?://[^\s\)]+)\)', url)
    if md_match:
        url = md_match.group(1)
    else:
        # Strip outer brackets if present
        url = url.strip("[]()")

    if not url.startswith(("http://", "https://")):
        url = "https://" + url
        
    parsed = urlparse(url)
    if not parsed.hostname:
        raise ValueError(f"Invalid URL structure: no hostname found in '{url}'")
        
    return url


def parse_domain_components(hostname: str) -> tuple[str, str, str]:
    """
    Extract (subdomain, registered_domain, tld) handling multi-part TLDs.
    Returns ('', hostname, 'IP') if host is a raw IP literal.
    """
    hostname = hostname.lower().rstrip(".")
    
    # Handle IPv4 / IPv6 literals directly
    if is_ip_address(hostname):
        return "", hostname, "IP"

    labels = [l for l in hostname.split(".") if l]
    if len(labels) < 2:
        return "", hostname, ""
    
    possible_tld = ".".join(labels[-2:])
    if possible_tld in COMMON_MULTI_PART_TLDS and len(labels) >= 3:
        registered_domain = ".".join(labels[-3:])
        subdomain = ".".join(labels[:-3])
        tld = possible_tld
    else:
        registered_domain = ".".join(labels[-2:])
        subdomain = ".".join(labels[:-2])
        tld = labels[-1]
        
    return subdomain, registered_domain, tld


# ---------------------------------------------------------------------------
# Advanced Risk Assessment Functions
# ---------------------------------------------------------------------------

def calculate_shannon_entropy(text: str) -> float:
    """Calculate Shannon Entropy on clean text strings."""
    clean_text = text.replace(".", "").replace("-", "")
    if not clean_text:
        return 0.0
        
    entropy = 0.0
    length = len(clean_text)
    for char in set(clean_text):
        p_x = clean_text.count(char) / length
        entropy -= p_x * math.log2(p_x)
        
    return round(entropy, 3)


def analyze_subdomain_entropy(subdomain: str, indicators: list[dict]) -> int:
    """Analyze subdomain randomness with context to spot DGA patterns."""
    if not subdomain:
        return 0
        
    entropy = calculate_shannon_entropy(subdomain)
    labels = subdomain.split(".")
    score = 0
    
    has_meaningful_words = any(
        any(c.isalpha() for c in label) for label in labels
    )
    
    if entropy > 3.5:
        if not has_meaningful_words or entropy > 4.0:
            pts = 25 if entropy > 4.0 else 15
            indicators.append({
                "type": "high_subdomain_entropy",
                "severity": "high" if entropy > 4.0 else "medium",
                "points": pts,
                "reason": (
                    f"Subdomain shows signs of random generation (entropy: {entropy}). "
                    f"{'No meaningful words detected.' if not has_meaningful_words else ''}"
                ).strip()
            })
            score += pts
            
    return score


def analyze_tld_risk(tld: str, indicators: list[dict]) -> int:
    """Check if TLD is commonly associated with phishing infrastructure."""
    if tld == "IP":
        return 0  # Handled separately in host inspection
        
    tld_lower = f".{tld}" if not tld.startswith(".") else tld
    
    if tld_lower in SUSPICIOUS_TLDS:
        points = SUSPICIOUS_TLDS[tld_lower]
        indicators.append({
            "type": "suspicious_tld",
            "severity": "medium",
            "points": points,
            "reason": f"Top-level domain '{tld_lower}' is commonly associated with phishing/malware campaigns."
        })
        return points
    return 0


def levenshtein_distance(s1: str, s2: str) -> int:
    """Compute edit distance to detect brand typosquatting."""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)
    
    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
        
    return previous_row[-1]


def detect_homographs_and_typos(hostname: str, registered_domain: str, indicators: list[dict]) -> int:
    """Analyze hostname for IDN/Punycode homographs and visual typosquatting."""
    score = 0
    decoded_hostname = hostname

    if is_ip_address(hostname):
        return 0

    if "xn--" in hostname:
        try:
            decoded_hostname = hostname.encode("ascii").decode("idna")
            indicators.append({
                "type": "punycode_homograph",
                "severity": "high",
                "points": 35,
                "reason": f"Punycode host detected: '{hostname}' decodes to Unicode '{decoded_hostname}'."
            })
            score += 35
        except UnicodeError:
            pass

    if any(ord(char) > 127 for char in decoded_hostname):
        indicators.append({
            "type": "unicode_confusables",
            "severity": "high",
            "points": 30,
            "reason": f"Hostname '{decoded_hostname}' contains non-ASCII Unicode characters."
        })
        score += 30

    reg_name = registered_domain.split(".")[0]
    for brand in KNOWN_BRANDS:
        dist = levenshtein_distance(reg_name, brand)
        if 1 <= dist <= 2 and reg_name != brand:
            indicators.append({
                "type": "typosquatting",
                "severity": "high",
                "points": 40,
                "value": reg_name,
                "reason": f"Registered domain '{reg_name}' is a typo variation of brand '{brand}' (Distance: {dist})."
            })
            score += 40

    return score


# ---------------------------------------------------------------------------
# HTML DOM Inspection Engine
# ---------------------------------------------------------------------------

class PhishingHTMLParser(HTMLParser):
    """HTML parser extracting form targets and password fields."""
    def __init__(self, base_url: str):
        super().__init__()
        self.base_url = base_url
        self.forms = []
        self.has_password_field = False
        self.text_content = []

    def handle_starttag(self, tag, attrs):
        attrs_dict = dict(attrs)
        if tag == "form":
            action = attrs_dict.get("action", "")
            self.forms.append(urljoin(self.base_url, action))
        elif tag == "input":
            if attrs_dict.get("type", "").lower() == "password":
                self.has_password_field = True

    def handle_data(self, data):
        clean_text = data.strip().lower()
        if clean_text:
            self.text_content.append(clean_text)


def inspect_page_anatomy(url: str, indicators: list[dict]) -> int:
    """Fetch and parse HTML DOM for phishing indicators."""
    score = 0
    try:
        req = urllib.request.Request(
            url, 
            headers={"User-Agent": "Mozilla/5.0 (Defensive-Phishing-Scanner/1.0)"}
        )
        with urllib.request.urlopen(req, timeout=5) as response:
            content_type = response.headers.get("Content-Type", "")
            if "text/html" not in content_type:
                return 0
            html_code = response.read().decode("utf-8", errors="ignore")
            
        parser = PhishingHTMLParser(url)
        parser.feed(html_code)
        
        parsed_url = urlparse(url)
        base_domain = parse_domain_components(parsed_url.hostname)[1]

        # Check for external form submission targets
        for form_action in parser.forms:
            action_domain = parse_domain_components(urlparse(form_action).hostname)[1]
            if action_domain and action_domain != base_domain:
                indicators.append({
                    "type": "external_form_action",
                    "severity": "high",
                    "points": 45,
                    "reason": f"Form submits credentials to external domain: '{action_domain}'."
                })
                score += 45
                break

        # Check for password field over unencrypted HTTP
        if parser.has_password_field and parsed_url.scheme != "https":
            indicators.append({
                "type": "insecure_password_form",
                "severity": "critical",
                "points": 50,
                "reason": "Password field present over insecure HTTP connection."
            })
            score += 50

        # Check for urgency triggers in page body
        full_text = " ".join(parser.text_content)
        found_triggers = [kw for kw in URGENCY_KEYWORDS if kw in full_text]
        if found_triggers:
            indicators.append({
                "type": "urgency_triggers",
                "severity": "medium",
                "points": 20,
                "value": found_triggers,
                "reason": f"Page contains urgency triggers: {', '.join(found_triggers)}."
            })
            score += 20

    except Exception as e:
        indicators.append({
            "type": "inspection_failed",
            "severity": "info",
            "points": 0,
            "reason": f"Could not inspect dynamic page content: {str(e)}"
        })

    return score


# ---------------------------------------------------------------------------
# Structured Risk Reporting
# ---------------------------------------------------------------------------

def generate_risk_categories(indicators: list[dict]) -> dict:
    """Categorize indicators into tactical security domains for SIEM ingestion."""
    categories = {
        "domain_deception": [],  # Homographs, typosquatting
        "brand_abuse": [],       # Subdomain brand spoofing
        "technical_risks": [],   # Plaintext transport, insecure forms
        "content_risks": [],     # Urgency language, auth keywords
        "infrastructure": []     # Raw IP usage, TLD reputation, DGA/Entropy
    }
    
    category_mapping = {
        "punycode_homograph": "domain_deception",
        "unicode_confusables": "domain_deception",
        "typosquatting": "domain_deception",
        "subdomain_brand_abuse": "brand_abuse",
        "transport": "technical_risks",
        "insecure_password_form": "technical_risks",
        "external_form_action": "technical_risks",
        "urgency_triggers": "content_risks",
        "path_keyword": "content_risks",
        "high_subdomain_entropy": "infrastructure",
        "suspicious_tld": "infrastructure",
        "raw_ip_address": "infrastructure"
    }
    
    for indicator in indicators:
        category = category_mapping.get(indicator["type"], "other")
        if category in categories:
            categories[category].append(indicator)
            
    return categories


# ---------------------------------------------------------------------------
# Core Analysis Engine & Execution
# ---------------------------------------------------------------------------

def analyze_url(raw_url: str, inspect_dom: bool = False) -> dict:
    """Analyze validated URL and optional HTML DOM context."""
    validated_url = validate_url(raw_url)
    parsed = urlparse(validated_url)
    hostname = parsed.hostname.lower().rstrip(".") if parsed.hostname else ""
    
    subdomain, registered_domain, tld = parse_domain_components(hostname)

    indicators = []
    score = 0

    # 1. Raw IP Address Host Indicator
    if is_ip_address(hostname):
        indicators.append({
            "type": "raw_ip_address",
            "severity": "high",
            "points": 40,
            "reason": f"URL uses a raw IP address ({hostname}) instead of a registered domain name."
        })
        score += 40

    # 2. Transport Encryption Check
    if parsed.scheme.lower() != "https":
        indicators.append({
            "type": "transport", "severity": "medium", "points": 25,
            "reason": "URL connection is unencrypted (HTTP)."
        })
        score += 25

    # 3. Subdomain Brand Spoofing Check
    if subdomain:
        for brand, trusted_domains in KNOWN_BRANDS.items():
            if brand in subdomain and registered_domain not in trusted_domains:
                indicators.append({
                    "type": "subdomain_brand_abuse",
                    "severity": "high",
                    "points": 40,
                    "reason": f"Known brand '{brand}' used in subdomain, but registered domain is '{registered_domain}'."
                })
                score += 40

    # 4. Enhanced Entropy / DGA Analysis
    score += analyze_subdomain_entropy(subdomain, indicators)

    # 5. Suspicious TLD Reputation Check
    score += analyze_tld_risk(tld, indicators)

    # 6. Homographs & Typosquatting Analysis
    score += detect_homographs_and_typos(hostname, registered_domain, indicators)

    # 7. Auth Keyword Inspection in Path
    full_path = (parsed.path + " " + parsed.query).lower()
    for kw, points in SUSPICIOUS_KEYWORDS.items():
        if kw in full_path:
            indicators.append({
                "type": "path_keyword", "severity": "low", "points": points,
                "reason": f"Authentication keyword '{kw}' found in URL path."
            })
            score += points

    # 8. Optional DOM Inspection Engine
    if inspect_dom:
        score += inspect_page_anatomy(validated_url, indicators)

    final_score = min(score, 100)
    risk_lvl = "HIGH" if final_score >= 70 else ("MEDIUM" if final_score >= 40 else "LOW")

    return {
        "url": validated_url,
        "domain_breakdown": {
            "subdomain": subdomain,
            "registered_domain": registered_domain,
            "tld": tld
        },
        "risk_assessment": {
            "score": final_score,
            "level": risk_lvl,
            "indicator_count": len(indicators)
        },
        "risk_categories": generate_risk_categories(indicators),
        "indicators": indicators
    }


def print_colored_result(result: dict) -> None:
    """Print analyst-friendly colorized terminal results."""
    risk_level = result['risk_assessment']['level']
    score = result['risk_assessment']['score']
    
    if COLOR_ENABLED:
        color = {'HIGH': Fore.RED, 'MEDIUM': Fore.YELLOW, 'LOW': Fore.GREEN}.get(risk_level, Fore.WHITE)
        print(f"\n{Style.BRIGHT}🔍 Target: {result['url']}{Style.RESET_ALL}")
        print(f"    ├── Domain: {result['domain_breakdown']['registered_domain']}")
        print(f"    ├── Risk Score: {color}{score}/100 ({risk_level}){Style.RESET_ALL}")
        print(f"    └── Indicators Triggered: {result['risk_assessment']['indicator_count']}")
        
        for ind in result['indicators']:
            sev_color = {
                'critical': Fore.RED + Style.BRIGHT,
                'high': Fore.RED,
                'medium': Fore.YELLOW,
                'low': Fore.WHITE,
                'info': Fore.CYAN
            }.get(ind['severity'], Fore.WHITE)
            print(f"        └── {sev_color}+{ind['points']} pts{Style.RESET_ALL}: {ind['reason']}")
    else:
        print(f"\n[+] Target: {result['url']}")
        print(f"    ├── Domain: {result['domain_breakdown']['registered_domain']}")
        print(f"    ├── Risk Score: {score}/100 ({risk_level})")
        print(f"    └── Indicators Triggered: {result['risk_assessment']['indicator_count']}")
        for ind in result['indicators']:
            print(f"        └── +{ind['points']} pts: {ind['reason']}")


# ---------------------------------------------------------------------------
# CLI Entry Point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description="Advanced Phishing URL & Page Anatomy Detector.")
    parser.add_argument("urls", nargs="+", help="URL(s) to analyze.")
    parser.add_argument("--inspect-dom", action="store_true", help="Fetch and inspect page HTML for forms and urgency triggers.")
    parser.add_argument("-o", "--output", default="output/phishing_scan.json", help="Output JSON report path.")
    args = parser.parse_args()

    results = []
    print("[+] Day 03: Advanced Phishing Page Anatomy & Detection Engine")
    print(f"[+] DOM Inspection Mode: {'ENABLED' if args.inspect_dom else 'DISABLED'}")

    for raw_url in args.urls:
        try:
            res = analyze_url(raw_url, inspect_dom=args.inspect_dom)
            results.append(res)
            print_colored_result(res)
        except ValueError as err:
            print(f"\n[-] Error analyzing '{raw_url}': {err}")

    report = {
        "scan_metadata": {
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "urls_analyzed": len(results)
        },
        "results": results
    }

    # Ensure output directory exists before writing
    import os
    os.makedirs(os.path.dirname(args.output) if os.path.dirname(args.output) else ".", exist_ok=True)

    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=4)
    print(f"\n[+] Scan complete. Full structured report saved to {args.output}")

if __name__ == "__main__":
    main()
