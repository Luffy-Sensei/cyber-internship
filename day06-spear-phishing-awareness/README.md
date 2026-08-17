# Day 06 — Spear Phishing Awareness Engine

A Python-based security-awareness tool that generates a personalized spear-phishing training scenario and analyzes the social-engineering techniques used in the message.

## Objective

Build an awareness-training engine that demonstrates how publicly available target information can be incorporated into a spear-phishing scenario.

The generated scenario is analyzed rather than delivered. The engine identifies:

- Psychological manipulation techniques
- Phishing red flags
- Defensive responses
- Email authentication controls

## Features

- Personalized awareness-email generation
- Target profile integration
- Psychological trigger analysis
- Phishing red-flag detection
- Defensive guidance generation
- SPF, DKIM, and DMARC awareness section
- JSON output for structured analysis
- Human-readable text report
- Timestamped scan metadata
- Console summary and logging
- Input validation and API-independent report generation

## Project Structure

```text
day06-spear-phishing-awareness/
├── output/
│   ├── awareness_email.txt
│   └── awareness_scenarios.json
├── report/
│   └── day06-report.md
├── screenshots/
│   ├── generator-execution.png
│   ├── json-report.png
│   ├── awareness-email.png
│   └── defensive-analysis.png
├── README.md
├── requirements.txt
└── spear_phishing_generator.py
Requirements
Python 3.10+
No external network connection is required by the generator
Python dependencies listed in requirements.txt
Installation

Create and activate a virtual environment:

python3 -m venv .venv
source .venv/bin/activate

Install dependencies:

pip install -r requirements.txt
Usage

Run the generator:

python3 spear_phishing_generator.py

The generator creates:

output/awareness_scenarios.json
output/awareness_email.txt
Validate the JSON Output
jq empty output/awareness_scenarios.json && echo "JSON VALID"

Inspect the complete JSON report:

jq . output/awareness_scenarios.json

Inspect the statistics:

jq '.statistics' output/awareness_scenarios.json
Generated Scenario

The generated scenario contains:

Target Profile
Name
Email
Company
Location
Email Scenario
Sender
Recipient
Subject
Message body
Psychological Triggers

The engine identifies manipulation techniques including:

Authority
Urgency
Fear
Personalization
Red Flags

The analysis identifies indicators such as:

Sender impersonation
Unexpected security notifications
Urgency
Threats of consequences
Verification requests
Personalized hooks
Defensive Guidance

The generated guidance covers:

Independent verification
Sender identity verification
Avoiding unexpected links
Following established security procedures
Reporting suspicious messages
Email Authentication

The report explains the defensive purpose of:

SPF
DKIM
DMARC

These controls improve email authentication and domain protection but do not eliminate phishing entirely.

Output Example

The JSON report follows a structured format:

scan_metadata
├── timestamp_utc
├── tool
├── tool_version
├── scenario_type
└── delivery


target_profile
├── name
├── email
├── company
└── location


email_scenario
├── from
├── to
├── subject
└── body


psychological_triggers
red_flags
defensive_guidance
email_authentication
statistics
Testing

Run Python syntax validation:

python3 -m py_compile spear_phishing_generator.py

Validate JSON:

jq empty output/awareness_scenarios.json && echo "JSON VALID"

Check Git whitespace errors:

git diff --check
Security Awareness Focus

The project demonstrates how personalization can increase the credibility of a phishing message and how defenders can identify the same characteristics during analysis.

The important defensive signals are:

Unexpected security notifications
Requests to verify an account through a supplied path
Artificial deadlines
Threats of account suspension
Familiar-looking sender identities
Personal information used to establish credibility
Defensive Controls

Organizations can reduce spear-phishing risk through:

SPF
DKIM
DMARC
Security-awareness training
Phishing-reporting procedures
Independent verification procedures
Strong authentication
Secure password practices
Regular review of publicly exposed organizational information

Ethical Scope

The project is designed for security-awareness training and authorized security research. Generated scenarios remain local artifacts and are not delivered to real recipients.
