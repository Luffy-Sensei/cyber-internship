#!/usr/bin/env python3

"""
Day 05 — OSINT + Social Engineering
GitHub Target Profile Aggregator

Aggregates publicly available GitHub profile, repository, and gist metadata
into a structured target-profile report.

This tool is intended for authorized security research,
exposure assessment, and security-awareness training.
"""

import json
import logging
import os
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

BASE_URL = "https://api.github.com"
REQUEST_TIMEOUT = 10
MAX_REPOSITORIES = 100

OUTPUT_DIR = Path("output")
JSON_OUTPUT = OUTPUT_DIR / "target_profile.json"
TEXT_OUTPUT = OUTPUT_DIR / "target_profile.txt"

USER_AGENT = "CyberInternship-Day05-GitHubProfiler/1.0"
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# HTTP Helpers
# ---------------------------------------------------------------------------

def create_session() -> requests.Session:
    """Create a configured HTTP session with optional authentication."""
    session = requests.Session()

    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": USER_AGENT,
        "X-GitHub-Api-Version": "2022-11-28",
    }

    if GITHUB_TOKEN:
        headers["Authorization"] = f"Bearer {GITHUB_TOKEN}"
        logger.info("Authenticated session active via GITHUB_TOKEN.")
    else:
        logger.warning(
            "Unauthenticated session: Subject to GitHub 60 req/hr rate limit."
        )

    session.headers.update(headers)
    return session


def github_get(session: requests.Session, endpoint: str) -> Any:
    """
    Perform a GET request against the GitHub API.

    Returns decoded JSON on success.
    Raises RuntimeError on API/network failures.
    """
    url = f"{BASE_URL}{endpoint}"

    try:
        response = session.get(
            url,
            timeout=REQUEST_TIMEOUT,
        )
    except requests.RequestException as exc:
        raise RuntimeError(
            f"Network error while requesting {endpoint}: {exc}"
        ) from exc

    if response.status_code == 404:
        raise RuntimeError(f"GitHub resource not found: {endpoint}")

    if response.status_code in (403, 429):
        raise RuntimeError(
            "GitHub API request was rate limited or forbidden (403/429). "
            "Consider exporting GITHUB_TOKEN."
        )

    if response.status_code >= 500:
        raise RuntimeError(
            f"GitHub API server error: {response.status_code}"
        )

    if not response.ok:
        raise RuntimeError(
            f"GitHub API request failed: {response.status_code} {response.reason}"
        )

    try:
        return response.json()
    except ValueError as exc:
        raise RuntimeError(
            f"GitHub returned invalid JSON for {endpoint}"
        ) from exc


# ---------------------------------------------------------------------------
# Data Collection
# ---------------------------------------------------------------------------

def collect_profile(session: requests.Session, username: str) -> Dict[str, Any]:
    """Collect public GitHub profile information."""
    logger.info("Collecting GitHub profile: %s", username)
    return github_get(session, f"/users/{username}")


def collect_repositories(
    session: requests.Session, username: str, limit: int = MAX_REPOSITORIES
) -> List[Dict[str, Any]]:
    """
    Collect public repositories with pagination.
    """
    logger.info("Collecting public repositories for: %s", username)
    repositories: List[Dict[str, Any]] = []
    page = 1
    per_page = 50

    while len(repositories) < limit:
        endpoint = (
            f"/users/{username}/repos"
            f"?per_page={per_page}&page={page}&sort=updated&direction=desc"
        )
        page_repos = github_get(session, endpoint)

        if not isinstance(page_repos, list) or not page_repos:
            break

        repositories.extend(page_repos)

        if len(page_repos) < per_page:
            break  # Reached last page

        page += 1

    return repositories[:limit]


def collect_gists(session: requests.Session, username: str) -> List[Dict[str, Any]]:
    """Collect public gists for the target."""
    logger.info("Collecting public gists for: %s", username)
    gists = github_get(session, f"/users/{username}/gists?per_page=30")
    return gists if isinstance(gists, list) else []


# ---------------------------------------------------------------------------
# Analysis
# ---------------------------------------------------------------------------

def analyze_languages(repositories: List[Dict[str, Any]]) -> Dict[str, int]:
    """Count primary repository languages."""
    languages: Counter[str] = Counter()

    for repository in repositories:
        language = repository.get("language")
        if language:
            languages[language] += 1

    return dict(languages.most_common())


def analyze_repository_exposure(
    repositories: List[Dict[str, Any]]
) -> List[Dict[str, Any]]:
    """Extract public repository metadata."""
    results = []

    for repository in repositories:
        results.append(
            {
                "name": repository.get("name"),
                "description": repository.get("description"),
                "language": repository.get("language"),
                "stars": repository.get("stargazers_count"),
                "forks": repository.get("forks_count"),
                "is_fork": repository.get("fork"),
                "archived": repository.get("archived"),
                "visibility": repository.get("visibility"),
                "updated_at": repository.get("updated_at"),
                "html_url": repository.get("html_url"),
            }
        )

    return results


def build_exposure_indicators(
    profile: Dict[str, Any],
    repositories: List[Dict[str, Any]],
    gists: List[Dict[str, Any]],
    languages: Dict[str, int],
) -> List[Dict[str, str]]:
    """Generate defensive exposure observations."""
    indicators = []

    if profile.get("name"):
        indicators.append(
            {
                "type": "public_identity",
                "severity": "low",
                "reason": "A public display name is available.",
            }
        )

    if profile.get("company"):
        indicators.append(
            {
                "type": "organizational_affiliation",
                "severity": "medium",
                "reason": "A public company/organization field is available.",
            }
        )

    if profile.get("location"):
        indicators.append(
            {
                "type": "location_exposure",
                "severity": "medium",
                "reason": "A public location field is available.",
            }
        )

    if repositories:
        indicators.append(
            {
                "type": "repository_exposure",
                "severity": "medium",
                "reason": f"{len(repositories)} public repositories were observable.",
            }
        )

    if gists:
        indicators.append(
            {
                "type": "gist_exposure",
                "severity": "medium",
                "reason": f"{len(gists)} public code gists were discovered.",
            }
        )

    if languages:
        indicators.append(
            {
                "type": "technology_exposure",
                "severity": "medium",
                "reason": "Repository metadata exposes primary programming languages.",
            }
        )

    return indicators


# ---------------------------------------------------------------------------
# Profile Construction
# ---------------------------------------------------------------------------

def build_target_profile(
    username: str,
    profile: Dict[str, Any],
    repositories: List[Dict[str, Any]],
    gists: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """Build the final structured target profile."""
    languages = analyze_languages(repositories)
    repository_data = analyze_repository_exposure(repositories)
    exposure_indicators = build_exposure_indicators(
        profile, repositories, gists, languages
    )

    return {
        "scan_metadata": {
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "tool": "Day 05 GitHub Target Profile Aggregator",
            "tool_version": "1.1",
            "target_username": username,
            "repositories_analyzed": len(repositories),
            "gists_found": len(gists),
        },
        "target_profile": {
            "username": username,
            "name": profile.get("name"),
            "company": profile.get("company"),
            "location": profile.get("location"),
            "bio": profile.get("bio"),
            "public_repositories": profile.get("public_repos"),
            "public_gists": profile.get("public_gists"),
            "followers": profile.get("followers"),
            "following": profile.get("following"),
            "account_created": profile.get("created_at"),
            "profile_url": profile.get("html_url"),
        },
        "technology_profile": {
            "primary_languages": languages,
            "language_count": len(languages),
        },
        "repository_exposure": repository_data,
        "exposure_assessment": {
            "indicator_count": len(exposure_indicators),
            "indicators": exposure_indicators,
        },
        "defensive_guidance": [
            "Review publicly visible profile information.",
            "Remove unnecessary organizational or location details.",
            "Review public repositories and gists for accidental sensitive leaks.",
            "Avoid publishing credentials, tokens, private keys, or secrets.",
            "Review repository descriptions and metadata for unnecessary exposure.",
            "Use secret-scanning tools (e.g., Trufflehog, GitGuardian) on commit history.",
        ],
    }


# ---------------------------------------------------------------------------
# Report Generation
# ---------------------------------------------------------------------------

def save_json_report(report: Dict[str, Any]) -> None:
    """Save structured JSON output."""
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    with JSON_OUTPUT.open("w", encoding="utf-8") as file:
        json.dump(report, file, indent=2, ensure_ascii=False)

    logger.info("JSON report saved to: %s", JSON_OUTPUT.resolve())


def save_text_report(report: Dict[str, Any]) -> None:
    """Save a human-readable report."""
    profile = report["target_profile"]
    technology = report["technology_profile"]
    exposure = report["exposure_assessment"]

    lines = [
        "=" * 70,
        "DAY 05 — GITHUB OSINT TARGET PROFILE",
        "=" * 70,
        "",
        f"Username: {profile['username']}",
        f"Name: {profile['name']}",
        f"Company: {profile['company']}",
        f"Location: {profile['location']}",
        f"Public repositories: {profile['public_repositories']}",
        f"Public gists: {profile['public_gists']}",
        f"Followers: {profile['followers']}",
        f"Following: {profile['following']}",
        "",
        "BIO",
        "-" * 70,
        profile["bio"] or "No public bio.",
        "",
        "TECHNOLOGY PROFILE",
        "-" * 70,
    ]

    if technology["primary_languages"]:
        for language, count in technology["primary_languages"].items():
            lines.append(f"- {language}: {count} repositories")
    else:
        lines.append("- No primary language data observed.")

    lines.extend(["", "EXPOSURE INDICATORS", "-" * 70])

    for indicator in exposure["indicators"]:
        lines.append(
            f"- [{indicator['severity'].upper()}] "
            f"{indicator['type']}: "
            f"{indicator['reason']}"
        )

    lines.extend(["", "DEFENSIVE GUIDANCE", "-" * 70])

    for item in report["defensive_guidance"]:
        lines.append(f"- {item}")

    lines.extend(["", "=" * 70, "END OF REPORT", "=" * 70])

    with TEXT_OUTPUT.open("w", encoding="utf-8") as file:
        file.write("\n".join(lines) + "\n")

    logger.info("Text report saved to: %s", TEXT_OUTPUT.resolve())


# ---------------------------------------------------------------------------
# Console Summary
# ---------------------------------------------------------------------------

def print_summary(report: Dict[str, Any]) -> None:
    """Print a concise console summary."""
    metadata = report["scan_metadata"]
    profile = report["target_profile"]
    technology = report["technology_profile"]
    exposure = report["exposure_assessment"]

    print("\n" + "=" * 70)
    print("🔎 DAY 05: GITHUB OSINT TARGET PROFILE ENGINE")
    print("=" * 70)

    print("\n[+] Collection Complete")
    print(f"├── Target: {profile['username']}")
    print(f"├── Repositories Analyzed: {metadata['repositories_analyzed']}")
    print(f"├── Public Gists Found: {metadata['gists_found']}")
    print(f"└── Exposure Indicators: {exposure['indicator_count']}")

    print("\n📊 TECHNOLOGY PROFILE")
    if technology["primary_languages"]:
        for language, count in technology["primary_languages"].items():
            print(f"├── {language}: {count} repositories")
    else:
        print("└── No language data observed.")

    print("\n👤 TARGET PROFILE")
    print(f"├── Name: {profile['name']}")
    print(f"├── Company: {profile['company']}")
    print(f"├── Location: {profile['location']}")
    print(f"└── Bio: {profile['bio']}")

    print("\n🛡️ EXPOSURE ASSESSMENT")
    for indicator in exposure["indicators"]:
        print(f"├── [{indicator['severity'].upper()}] {indicator['type']}")

    print("\n[+] JSON report:")
    print(f"    {JSON_OUTPUT.resolve()}")
    print("[+] Text report:")
    print(f"    {TEXT_OUTPUT.resolve()}")
    print("\n✅ Scan complete.")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    if len(sys.argv) != 2:
        script_name = Path(sys.argv[0]).name
        print(f"Usage: python3 {script_name} <github_username>\n")
        print("Example:")
        print(f"  python3 {script_name} torvalds")
        sys.exit(1)

    username = sys.argv[1].strip()

    if not username:
        print("Error: GitHub username cannot be empty.")
        sys.exit(1)

    with create_session() as session:
        try:
            profile = collect_profile(session, username)
            repositories = collect_repositories(session, username)
            gists = collect_gists(session, username)

            report = build_target_profile(username, profile, repositories, gists)

            save_json_report(report)
            save_text_report(report)
            print_summary(report)

        except RuntimeError as exc:
            logger.error("%s", exc)
            sys.exit(1)


if __name__ == "__main__":
    main()
