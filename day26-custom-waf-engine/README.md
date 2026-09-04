# Day 26 — Custom Web Application Firewall (WAF) Engine

A lightweight, rule-based Web Application Firewall (WAF) engine implemented in Python for controlled cybersecurity training and defensive security research.

The project demonstrates how a WAF can normalize incoming HTTP requests, inspect request components against configurable security rules, generate detections, apply enforcement policies, and produce structured audit logs and security reports.

> **Security Notice:** This project is designed for authorized defensive testing, controlled lab environments, and educational use. The included fixtures are mock HTTP requests. Do not use the engine to inspect or interfere with traffic belonging to systems you do not own or have explicit authorization to test.

---

## Overview

Modern web applications are exposed to a wide range of application-layer attacks. A Web Application Firewall provides an additional defensive layer by inspecting HTTP traffic before requests reach application backends.

This Day 26 project implements a simplified WAF processing pipeline:

```text
                 ┌──────────────────┐
                 │      Client      │
                 └────────┬─────────┘
                          │
                          ▼
                 ┌──────────────────┐
                 │   HTTP Request   │
                 └────────┬─────────┘
                          │
                          ▼
              ┌─────────────────────────┐
              │     WAF ENGINE          │
              │                         │
              │  1. Normalize Request  │
              │  2. Inspect Rules      │
              │  3. Generate Findings  │
              │  4. Apply Policy       │
              │  5. Record Decision    │
              └───────────┬─────────────┘
                          │
              ┌───────────┼────────────┐
              │           │            │
              ▼           ▼            ▼
           ALLOW       MONITOR       BLOCK
              │           │            │
              ▼           ▼            ▼
           Backend     Backend       Drop
```

The implementation focuses on three representative web attack categories:

* SQL Injection (SQLi)
* Cross-Site Scripting (XSS)
* Path Traversal

The engine is intentionally modular so that additional rules, policies, logging mechanisms, and integrations can be added later.

---

## Objectives

The objectives of Day 26 are to:

* Build a custom WAF inspection engine in Python.
* Normalize HTTP request data before security inspection.
* Detect common malicious request indicators.
* Support configurable security rules.
* Assign severity and confidence to detections.
* Convert detections into enforcement decisions.
* Support `ALLOW`, `MONITOR`, and `BLOCK` actions.
* Produce structured JSONL audit logs.
* Generate JSON and human-readable TXT reports.
* Provide a repeatable CLI workflow.
* Validate the implementation using automated tests.
* Demonstrate secure defensive processing using controlled mock traffic.

---

## Features

### Request Normalization

Incoming request data is converted into a canonical inspection representation.

The normalizer handles:

* HTTP method normalization.
* URL decoding.
* Header-name normalization.
* Whitespace normalization.
* Query-string normalization.
* Request-body normalization.

This is important because security indicators may be encoded or represented differently in incoming HTTP traffic.

Example:

```text
%3Cscript%3E
```

is normalized to:

```text
<script>
```

before rule evaluation.

---

### Rule-Based Detection

The WAF currently includes rules for:

| Rule ID         | Category       | Severity | Purpose                                         |
| --------------- | -------------- | -------- | ----------------------------------------------- |
| `SQLI-001`      | SQLI           | HIGH     | Detects `UNION SELECT` SQL injection indicators |
| `XSS-001`       | XSS            | HIGH     | Detects script-tag XSS indicators               |
| `TRAVERSAL-001` | PATH_TRAVERSAL | HIGH     | Detects directory traversal indicators          |

Rules are compiled as regular expressions and can be extended through the WAF configuration.

---

### Multi-Field Inspection

The engine can inspect:

* Request path
* Query parameters
* HTTP headers
* Request body

This prevents the implementation from relying on a single request component.

---

### Severity-Based Policy Enforcement

The policy engine converts detections into enforcement decisions.

The default policy is:

```text
No detection  → ALLOW
LOW           → ALLOW
MEDIUM        → MONITOR
HIGH          → BLOCK
CRITICAL      → BLOCK
```

Confidence thresholds are also supported.

This separation between **detection** and **policy enforcement** allows organizations to tune the WAF without rewriting the underlying detection engine.

---

### Structured Audit Logging

Every WAF decision can be recorded as JSON Lines (`JSONL`).

Example structure:

```json
{
  "action": "BLOCK",
  "detection_count": 1,
  "method": "GET",
  "path": "/search",
  "request_id": "req-002",
  "rules_triggered": [
    "XSS-001"
  ]
}
```

The logging layer intentionally avoids recording unnecessary full request bodies.

---

### Security Reports

The reporting system produces:

* JSON reports for machine-readable processing.
* TXT reports for human review.

Reports include:

* Run ID
* Timestamp
* Requests processed
* Allowed requests
* Monitored requests
* Blocked requests
* Detection count
* Triggered rules
* Individual WAF decisions

---

## Project Structure

```text
day26-custom-waf-engine/
├── authorized-target-guide.md
├── input/
│   └── mock_requests.json
├── output/
│   ├── logs/
│   │   └── waf-audit.jsonl
│   └── reports/
│       ├── day26-report.json
│       └── day26-report.txt
├── README.md
├── report/
│   └── day26-report.md
├── requirements.txt
├── scanner/
│   ├── __init__.py
│   ├── cli.py
│   ├── config.py
│   ├── engine.py
│   ├── logging.py
│   ├── models.py
│   ├── normalizer.py
│   ├── policies.py
│   ├── reporting.py
│   └── rules.py
└── tests/
    ├── test_cli.py
    ├── test_config.py
    ├── test_engine.py
    ├── test_logging.py
    ├── test_models.py
    ├── test_normalizer.py
    ├── test_policies.py
    ├── test_reporting.py
    ├── test_rules.py
    └── test_security_boundary.py
```

---

# Requirements

## Operating System

Recommended:

* Linux
* Parrot OS
* Kali Linux
* Ubuntu/Debian-based distributions

The project should also work on other systems capable of running Python 3.11+.

---

## Python

Recommended Python version:

```text
Python 3.11+
```

The development environment for this project uses:

```text
Python 3.13.5
```

Check your Python version:

```bash
python3 --version
```

---

## Dependencies

The project is intentionally lightweight.

Install the project dependencies with:

```bash
pip install -r requirements.txt
```

For the development environment, a Python virtual environment is strongly recommended.

---

# Installation

## Option 1 — Clone from GitHub

Clone the repository containing the internship project:

```bash
git clone https://github.com/Luffy-Sensei/cyber-internship.git
```

Enter the repository:

```bash
cd cyber-internship-FINAL
```

Navigate to Day 26:

```bash
cd day26-custom-waf-engine
```

---

## Option 2 — Download from GitHub

If you do not want to use Git, open the project repository on GitHub and use:

```text
Code → Download ZIP
```

Extract the downloaded archive and navigate into:

```text
day26-custom-waf-engine/
```

---

# Recommended Virtual Environment

Create a dedicated Python virtual environment:

```bash
python3 -m venv .venv
```

Activate it:

### Linux / Parrot OS / Kali

```bash
source .venv/bin/activate
```

### Windows

```powershell
.venv\Scripts\activate
```

Upgrade pip:

```bash
python -m pip install --upgrade pip
```

Install dependencies:

```bash
pip install -r requirements.txt
```

---

# Input Fixtures

The WAF processes controlled JSON request fixtures.

The default fixture file is:

```text
input/mock_requests.json
```

Example:

```json
[
  {
    "request_id": "req-001",
    "method": "GET",
    "path": "/products",
    "query": "category=books"
  },
  {
    "request_id": "req-002",
    "method": "GET",
    "path": "/search",
    "query": "q=%3Cscript%3E"
  }
]
```

The first request represents normal traffic.

The second request contains a controlled, URL-encoded XSS indicator for detection testing.

These fixtures are intentionally harmless and exist only to validate the WAF's detection pipeline.

---

# Usage

## Run the WAF CLI

From the `day26-custom-waf-engine` directory:

```bash
python3 -m scanner.cli
```

The CLI will:

1. Load the mock HTTP requests.
2. Normalize request data.
3. Evaluate configured WAF rules.
4. Generate detections.
5. Apply the configured policy.
6. Record audit events.
7. Generate JSON and TXT reports.
8. Print a runtime summary.

Example:

```text
=== DAY 26 CUSTOM WAF ENGINE ===
Input fixtures : .../input/mock_requests.json
Requests       : 2

req-001 | GET /products | Detections=0 | Action=ALLOW
req-002 | GET /search | Detections=1 | Action=BLOCK

=== WAF SUMMARY ===
Requests processed : 2
Allowed            : 1
Monitored          : 0
Blocked            : 1
Detections         : 1
```

---

# Output Artifacts

After execution, the WAF generates:

```text
output/
├── logs/
│   └── waf-audit.jsonl
└── reports/
    ├── day26-report.json
    └── day26-report.txt
```

## JSONL Audit Log

View the audit log:

```bash
cat output/logs/waf-audit.jsonl
```

This contains one structured event per processed request.

---

## JSON Security Report

View the machine-readable report:

```bash
cat output/reports/day26-report.json
```

The report contains aggregate WAF statistics and individual enforcement decisions.

---

## Text Security Report

View the human-readable report:

```bash
cat output/reports/day26-report.txt
```

---

# Testing

The project uses `pytest`.

Run the complete test suite:

```bash
python3 -m pytest -q
```

The test suite covers:

* Data models
* Configuration validation
* Request normalization
* WAF rules
* Detection engine
* Policy enforcement
* Structured logging
* Report generation
* CLI fixture loading
* Security-boundary behavior
* False-positive handling

The project should be considered ready for use only when the complete test suite passes successfully.

---

# Security Boundary Testing

The project includes dedicated security-boundary tests covering:

### Detection

* SQL injection indicators
* XSS indicators
* Path traversal indicators
* Multiple simultaneous indicators
* URL-encoded indicators

### Safety

* Invalid request structures
* Empty request identifiers
* Invalid paths
* Disabled rules
* Confidence thresholds

### False-Positive Resistance

The tests verify that benign strings such as:

```text
scriptwriting
union membership
parent-directory
```

are not incorrectly classified as attacks by the current rules.

This is important because a production WAF must balance detection coverage with false-positive management.

---

# WAF Processing Model

The implementation separates the WAF into distinct responsibilities.

```text
HTTP Request
     │
     ▼
┌─────────────────────┐
│ Request Normalizer  │
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│   Rule Engine       │
│                     │
│ SQLi / XSS /        │
│ Path Traversal      │
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│ Detection Engine    │
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│ Policy Engine       │
│                     │
│ ALLOW / MONITOR /   │
│ BLOCK               │
└──────────┬──────────┘
           │
           ├──────────────► Audit Log
           │
           ├──────────────► JSON Report
           │
           └──────────────► TXT Report
```

This modular architecture makes individual components easier to test, maintain, and extend.

---

# Inline WAF vs Reverse-Proxy WAF

A WAF can be deployed in different architectural positions.

## Inline / Middleware WAF

```text
Client
  │
  ▼
Application
  │
  ▼
WAF Middleware
  │
  ▼
Protected Logic
```

An inline middleware WAF operates within or immediately around an application.

### Advantages

* Simple integration with an application.
* Direct access to request context.
* Easy to implement for application-specific controls.
* Useful for development and internal services.

### Limitations

* Security processing is closely coupled to the application.
* A compromised application environment may reduce confidence in the control.
* Scaling and centralized policy management can become more difficult.

---

## Reverse-Proxy WAF

```text
Client
  │
  ▼
┌──────────────┐
│ Reverse Proxy│
│     + WAF    │
└──────┬───────┘
       │
       ▼
┌──────────────┐
│   Backend    │
│ Application  │
└──────────────┘
```

A reverse-proxy WAF sits at the edge of an application environment.

### Advantages

* Centralized enforcement.
* Multiple applications can share WAF policies.
* Backend applications receive filtered traffic.
* Easier integration with load-balancing architectures.
* Better separation between security controls and application code.

### Limitations

* More infrastructure to deploy and maintain.
* Requires careful proxy configuration.
* Incorrect rules can block legitimate traffic.
* TLS termination and header forwarding require careful design.

---

# Configuration

Default WAF behavior is defined in:

```text
scanner/config.py
```

The configuration defines:

* WAF policy thresholds.
* Default action.
* Minimum confidence.
* Request fields to inspect.
* Default detection rules.

Current inspection areas include:

```text
Path
Query
Headers
Body
```

Rules can be extended by creating additional `WAFRule` definitions.

---

# Security Design Principles

This project follows several defensive engineering principles.

## 1. Detection and Enforcement Are Separate

The rule engine identifies suspicious indicators.

The policy engine determines what should happen.

This prevents detection logic from being tightly coupled to enforcement behavior.

---

## 2. Normalize Before Inspection

Encoded request data can bypass simplistic pattern matching.

The project therefore normalizes request data before applying security rules.

---

## 3. Evidence Is Bounded

Detection evidence is intentionally limited in size.

This reduces unnecessary data exposure in reports and logs.

---

## 4. Structured Logging

JSONL provides machine-readable audit records suitable for future SIEM or monitoring integrations.

---

## 5. Configurable Policies

Different environments may require different enforcement thresholds.

The policy engine therefore supports configurable severity and confidence thresholds.

---

## 6. Defense in Depth

A WAF should not be treated as the only application security control.

Secure coding, input validation, parameterized database queries, output encoding, authentication, authorization, logging, monitoring, and secure deployment practices remain essential.

---

# Recommendations

For educational and development environments:

* Use Python 3.11 or newer.
* Use a dedicated virtual environment.
* Run the test suite before and after changes.
* Keep mock fixtures separate from production traffic.
* Review WAF rules for false positives.
* Keep security rules under version control.
* Review audit logs for unexpected behavior.
* Keep evidence bounded and avoid unnecessary sensitive data.
* Use explicit authorization before testing real systems.
* Prefer staging or isolated environments for WAF experimentation.
* Add regression tests whenever a rule is modified.
* Do not assume that a regex-based WAF can identify every attack variant.

For production deployments, additional controls would be required, including:

* TLS termination strategy.
* Rate limiting.
* Centralized logging.
* SIEM integration.
* Rule versioning.
* Alerting.
* Metrics and observability.
* Operational dashboards.
* Authentication and authorization controls.
* Secure secret management.
* Load testing.
* WAF bypass testing within an authorized environment.
* Formal change management.
* Incident-response integration.

---

# Limitations

This implementation is an educational WAF engine rather than a production-grade commercial WAF.

Current limitations include:

* Regex-based detection is inherently incomplete.
* The rule set is intentionally small.
* There is no machine-learning detection layer.
* There is no distributed deployment model.
* There is no TLS termination.
* There is no live reverse-proxy integration.
* There is no rate-limiting subsystem.
* There is no external SIEM integration.
* There is no persistent database.
* Detection rules require careful tuning to avoid false positives.
* The engine does not guarantee that malicious requests will always be detected.

A real production WAF requires substantially broader coverage, operational controls, continuous tuning, and integration with the surrounding application-security architecture.

---

# Responsible Use

This project is intended for:

* Cybersecurity education.
* Defensive security research.
* Authorized application testing.
* Local development.
* Security engineering experimentation.
* Controlled lab environments.

Do **not** use this tool to inspect, modify, block, intercept, or interfere with traffic on systems without explicit authorization.

All demonstrations in this project should use systems and traffic that you own or are explicitly authorized to test.

---

# GitHub

The complete internship project is maintained in GitHub.

Repository:

```text
https://github.com/Luffy-Sensei/cyber-internship.git
```

Clone the project:

```bash
git clone https://github.com/Luffy-Sensei/cyber-internship.git
```

Then:

```bash
cd cyber-internship-FINAL/day26-custom-waf-engine
```

Alternatively, download the repository as a ZIP from GitHub:

```text
GitHub → Code → Download ZIP
```

The Day 26 implementation is located in:

```text
day26-custom-waf-engine/
```

---

# Quick Start

For users who already have Python installed:

```bash
git clone https://github.com/Luffy-Sensei/cyber-internship.git
cd cyber-internship-FINAL/day26-custom-waf-engine

python3 -m venv .venv
source .venv/bin/activate

pip install -r requirements.txt

python3 -m pytest -q
python3 -m scanner.cli
```

Review generated artifacts:

```bash
cat output/logs/waf-audit.jsonl
cat output/reports/day26-report.json
cat output/reports/day26-report.txt
```

---

# Development Workflow

Recommended workflow when modifying the WAF:

```text
Modify Code
    │
    ▼
Run Focused Tests
    │
    ▼
Run Full Test Suite
    │
    ▼
Run CLI Validation
    │
    ▼
Review Logs / Reports
    │
    ▼
Run git diff --check
    │
    ▼
Commit Changes
```

Useful commands:

```bash
python3 -m pytest -q
```

```bash
python3 -m scanner.cli
```

```bash
git diff --check
```

```bash
git status
```

---

# Project Status

**Day 26 — Custom Web Application Firewall Engine**

Status:

```text
COMPLETE
```

Validated capabilities:

* [x] Request models
* [x] WAF configuration
* [x] Request normalization
* [x] Rule compilation
* [x] SQLi detection
* [x] XSS detection
* [x] Path traversal detection
* [x] Multi-detection aggregation
* [x] Policy enforcement
* [x] ALLOW / MONITOR / BLOCK actions
* [x] Confidence filtering
* [x] Structured JSONL logging
* [x] JSON reporting
* [x] TXT reporting
* [x] CLI integration
* [x] Controlled mock-request testing
* [x] Security-boundary testing
* [x] False-positive regression tests

---

# License

If this project is published publicly, add the license selected for the overall internship repository here.

For example:

```text
MIT License
```

Ensure the license is consistent with the license used by the parent repository.