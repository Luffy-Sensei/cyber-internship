# Day 05 — OSINT + Social Engineering: Target Profile

## Overview

Day 05 combines OSINT concepts with social-engineering awareness by building a Python-based GitHub target-profile aggregator.

The tool collects publicly available GitHub profile and repository metadata and converts the information into a structured target profile.

The exercise demonstrates how publicly exposed information can reveal:

- Public identity information
- Organizational affiliation
- Location information
- Public repositories
- Programming languages
- Repository metadata
- Technology exposure

The defensive objective is to understand what information is publicly observable and how unnecessary exposure can be reduced.

---

## Objectives

- Understand how OSINT can be used to construct a public target profile.
- Query the GitHub public API.
- Collect public GitHub profile information.
- Collect public repository metadata.
- Identify observable programming languages.
- Analyze publicly exposed information.
- Generate structured JSON output.
- Generate a human-readable text report.
- Produce defensive exposure indicators.

---

## Directory Structure

```text
day05-osint-target-profile/
├── github_target_profiler.py
├── input/
├── output/
│   ├── target_profile.json
│   └── target_profile.txt
├── report/
│   └── day05-report.md
├── screenshots/
│   ├── json-report.png
│   ├── scanner-execution.png
│   ├── target-profile.png
│   └── technology-profile.png
├── README.md
└── requirements.txt
Technology
Python 3
Requests
GitHub REST API
JSON
Linux / Parrot OS
Installation

Create and activate a virtual environment:

python3 -m venv .venv
source .venv/bin/activate

Install dependencies:

pip install -r requirements.txt
Usage

Run the profiler with a GitHub username:

python3 github_target_profiler.py torvalds

Replace torvalds with the GitHub username being assessed.

The tool collects publicly available GitHub information and generates two reports.

Output
JSON Report
output/target_profile.json

The JSON report contains structured information including:

Scan metadata
GitHub username
Public name
Company
Location
Bio
Public repository count
Followers
Following
Account creation date
Profile URL
Repository metadata
Primary repository languages
Technology exposure
Defensive guidance
Text Report
output/target_profile.txt

The text report provides a human-readable summary of the collected information.

Analysis Performed
1. Public Profile Metadata

The profiler collects publicly available fields such as:

Name
Company
Location
Bio
Public repositories
Followers
Following
Account creation date
Profile URL
2. Repository Analysis

The tool analyzes public repositories and extracts metadata including:

Repository name
Description
Primary language
Stars
Forks
Fork status
Archived status
Visibility
Last update time
Repository URL
3. Technology Profile

The primary programming language reported by each analyzed repository is counted.

Example:

Python: 8 repositories
C: 5 repositories
Shell: 3 repositories

This provides a high-level view of the technologies observable from public repository metadata.

4. Exposure Assessment

The tool identifies observable exposure indicators such as:

Public identity
Organizational affiliation
Location exposure
Repository exposure
Technology exposure

These are observations about publicly available metadata and are not conclusions about the individual.

API Handling

The tool uses a configured HTTP session with:

GitHub JSON API headers
Custom User-Agent
Request timeout
HTTP error handling
JSON validation
404 handling
403/rate-limit handling
429 handling
Server-error handling
Network exception handling

Unauthenticated GitHub API requests are subject to GitHub's rate limits.

Defensive Guidance

The generated report provides defensive recommendations including:

Review publicly visible profile information.
Remove unnecessary organizational or location details.
Review public repositories for accidental sensitive information.
Never publish credentials, tokens, private keys, or secrets.
Review repository descriptions and metadata.
Use secret-scanning and repository security controls where appropriate.
Validation

The implementation was validated using Python compilation and JSON validation.

Python syntax check:

python3 -m py_compile github_target_profiler.py

JSON validation:

jq empty output/target_profile.json

Git whitespace validation:

git diff --check
Evidence

Screenshots documenting the implementation and results are stored under:

screenshots/

Evidence includes:

Scanner execution
Target profile output
Technology profile
JSON report
Key Learning Outcomes

This exercise demonstrated how several individually low-risk pieces of public information can be aggregated into a more useful technical profile.

The main security lesson is that defenders should consider the combined exposure created by public profile information, repositories, technology choices, organizational information, and other metadata.

Public information should therefore be reviewed as part of an organization's broader security-awareness and digital-footprint strategy.

Scope

This project uses publicly available GitHub information through the GitHub API.

No authentication bypass, private-data access, credential collection, or exploitation is performed.

The project is intended for cybersecurity education, OSINT exposure assessment, and security-awareness training.
