# Authorized Target Guide — Day 26 Custom WAF Engine

## Purpose

This guide explains how to use the Day 26 Custom Web Application Firewall (WAF) Engine with:

1. The default controlled `localhost` environment.
2. Another explicitly authorized application or target.
3. A future staging or test environment.

It also identifies which files should be changed when adapting the project to another authorized environment and provides recommendations for evolving the educational implementation toward a more professional WAF architecture.

> **Important:** Only inspect, filter, or intercept HTTP traffic for systems you own or systems for which you have explicit authorization. Changing the target does not grant authorization.

---

# 1. Default Operating Model

The Day 26 implementation is intentionally designed around **controlled request fixtures** rather than automatically intercepting live network traffic.

The default workflow is:

```text
mock_requests.json
        │
        ▼
   scanner.cli
        │
        ▼
Request Normalization
        │
        ▼
    Rule Engine
        │
        ▼
 Detection Engine
        │
        ▼
   Policy Engine
        │
        ├── ALLOW
        ├── MONITOR
        └── BLOCK
        │
        ▼
 Logs + Reports
```

The default input is:

```text
input/mock_requests.json
```

The CLI loads these requests and processes them locally.

---

# 2. What Is the Default Target?

The current project does **not** hard-code `127.0.0.1` or a live HTTP destination as its WAF target.

Instead, the current CLI operates on structured request fixtures.

Default input:

```text
input/mock_requests.json
```

Therefore, changing from localhost to another authorized environment is **not currently a matter of changing one IP address**.

The request data must represent the authorized environment's traffic or application behavior.

This distinction is important:

```text
Current implementation:
Fixture → WAF → Decision

Not:
Client → Network → WAF → Live Server
```

The current implementation is therefore safe for controlled demonstrations and testing.

---

# 3. Using the Default Local Environment

The simplest workflow is to use the supplied mock requests.

Navigate to:

```bash
cd ~/cyber-internship/cyber-internship-FINAL/day26-custom-waf-engine
```

Activate the virtual environment:

```bash
source .venv/bin/activate
```

Run the test suite:

```bash
python3 -m pytest -q
```

Run the WAF:

```bash
python3 -m scanner.cli
```

The default CLI reads:

```text
input/mock_requests.json
```

and generates:

```text
output/logs/waf-audit.jsonl
output/reports/day26-report.json
output/reports/day26-report.txt
```

---

# 4. Using Another Authorized Target

If you have an authorized staging application, test server, or local application, the recommended approach is **not** to immediately modify the core WAF engine.

Instead, preserve the security engine and change the input/integration layer.

The architecture should remain:

```text
Authorized Application
        │
        ▼
 Request Adapter
        │
        ▼
 HTTPRequest
        │
        ▼
 WAF Engine
```

This keeps the detection and policy logic independent from the target environment.

---

# 5. Which Files Should Be Changed?

When adapting the project to another authorized environment, the files fall into three categories.

## Category A — Usually Change

These files contain environment-specific behavior or input data.

### 1. `input/mock_requests.json`

Current purpose:

```text
Controlled HTTP request fixtures
```

If you want to represent another authorized application, this is the first file to update for a fixture-based test.

Example:

```json
[
  {
    "request_id": "staging-001",
    "method": "GET",
    "path": "/products",
    "query": "category=books"
  },
  {
    "request_id": "staging-002",
    "method": "POST",
    "path": "/search",
    "query": "q=test",
    "headers": {
      "content-type": "application/x-www-form-urlencoded"
    },
    "body": "search=test"
  }
]
```

The fixture should represent the authorized application's normal request structure.

Do not place credentials, session tokens, API keys, or unnecessary personal information in the fixture.

---

### 2. `scanner/cli.py`

The CLI is the correct place to introduce integration-specific behavior.

For example, a future professional implementation could support:

```text
--input
--target
--listen
--upstream
--config
--rules
--log
--json-report
--text-report
```

However, **do not simply add a target URL and make the current CLI send arbitrary requests to it**.

A live target adapter should be explicitly designed and authorized.

---

### 3. `scanner/config.py`

Change this file when the authorized environment requires different:

* Security rules.
* Severity thresholds.
* Confidence thresholds.
* Inspection fields.
* Enforcement policy.

For example:

```text
Development:
MEDIUM → MONITOR

Staging:
MEDIUM → MONITOR
HIGH   → BLOCK

Production:
HIGH     → BLOCK
CRITICAL → BLOCK
```

Avoid putting environment-specific secrets into this file.

---

# 6. Files That Should Usually NOT Be Changed

Changing the target should not require modifying the core security pipeline.

The following should remain reusable:

```text
scanner/models.py
scanner/normalizer.py
scanner/rules.py
scanner/engine.py
scanner/policies.py
scanner/logging.py
scanner/reporting.py
```

These components represent the WAF's core functionality.

A clean architecture should allow:

```text
Target A ─┐
Target B ─┼──► Same WAF Engine
Target C ─┘
```

rather than creating a different WAF implementation for every target.

---

# 7. Tests Must Be Updated When Fixtures Change

If you modify:

```text
input/mock_requests.json
```

you should not assume the existing tests automatically validate the new behavior.

Add or modify regression tests under:

```text
tests/
```

For example:

```text
tests/test_engine.py
tests/test_rules.py
tests/test_policies.py
tests/test_security_boundary.py
```

Every new security rule should have:

```text
Positive test
Negative test
False-positive test
Encoding test where applicable
```

Example test strategy:

```text
Malicious indicator
       ↓
Expected detection

Benign equivalent
       ↓
Expected no detection
```

This is particularly important for WAF rules because overly broad signatures can create availability problems.

---

# 8. Example: Authorized Staging Environment

Suppose an organization owns:

```text
https://staging.example.internal
```

and has explicitly authorized WAF testing against it.

The current Day 26 engine should **not** simply replace a string such as:

```text
127.0.0.1
```

with:

```text
staging.example.internal
```

because the current engine is fixture-driven.

Instead:

```text
Staging Application
        │
        ▼
Authorized Integration / Adapter
        │
        ▼
HTTPRequest
        │
        ▼
WAFDetectionEngine
        │
        ▼
WAFPolicyEngine
        │
        ▼
Decision
```

This preserves the core WAF implementation.

---

# 9. Recommended Professional Integration

For a higher-level implementation, introduce a dedicated adapter layer.

Recommended structure:

```text
scanner/
├── adapters/
│   ├── __init__.py
│   ├── fixture.py
│   ├── middleware.py
│   └── reverse_proxy.py
├── models.py
├── config.py
├── normalizer.py
├── rules.py
├── engine.py
├── policies.py
├── logging.py
├── reporting.py
└── cli.py
```

The adapter should convert an environment-specific request into the existing:

```python
HTTPRequest
```

model.

This creates a clean boundary:

```text
Integration Layer
       │
       ▼
 HTTPRequest
       │
       ▼
 Core WAF
```

---

# 10. Professional-Level Recommendation #1 — Separate Configuration from Code

The current educational configuration is Python-based:

```text
scanner/config.py
```

For a professional implementation, move environment configuration into a dedicated configuration file.

For example:

```text
config/
├── development.yaml
├── staging.yaml
└── production.yaml
```

Potential configuration:

```yaml
policy:
  block_severity: HIGH
  monitor_severity: MEDIUM
  minimum_confidence: MEDIUM

inspection:
  path: true
  query: true
  headers: true
  body: true
```

Advantages:

* Environment-specific configuration.
* Easier deployment.
* No code changes for policy adjustments.
* Better configuration management.
* Easier CI/CD integration.

---

# 11. Professional-Level Recommendation #2 — Introduce a Rule Registry

Instead of keeping all rules directly inside:

```text
scanner/config.py
```

consider a dedicated rules directory:

```text
rules/
├── sqli.yaml
├── xss.yaml
└── traversal.yaml
```

A rule registry could load:

```text
Rule ID
Category
Pattern
Severity
Confidence
Description
Enabled/Disabled
```

This makes rule management easier.

It also allows security teams to version rules independently from application code.

---

# 12. Professional-Level Recommendation #3 — Add Rule Versioning

Each rule should eventually contain metadata such as:

```text
rule_id
version
category
severity
confidence
description
created_at
updated_at
enabled
```

Example:

```text
XSS-001
Version: 1.2
Category: XSS
Severity: HIGH
Confidence: HIGH
Status: ENABLED
```

Rule versioning makes security incidents easier to investigate because analysts can determine exactly which rule set was active when a request was blocked.

---

# 13. Professional-Level Recommendation #4 — Improve Detection Evidence

The current implementation intentionally bounds evidence.

That is a good security practice.

A professional implementation could additionally record:

```text
matched field
rule ID
rule version
match position
normalized representation
request correlation ID
confidence
```

However, sensitive request data should not automatically be logged.

Avoid storing:

```text
Passwords
Session cookies
Authorization headers
API keys
Personal data
Full request bodies
```

unless there is a documented operational requirement and appropriate protection.

---

# 14. Professional-Level Recommendation #5 — Add Sensitive-Data Redaction

A production-oriented logging layer should support redaction.

Example:

```text
Authorization: [REDACTED]
Cookie: [REDACTED]
password: [REDACTED]
api_key: [REDACTED]
token: [REDACTED]
```

The redaction layer should execute before audit data is persisted.

Recommended architecture:

```text
Detection
    │
    ▼
Redaction
    │
    ▼
Audit Logger
```

---

# 15. Professional-Level Recommendation #6 — Add Rate Limiting

A real WAF should consider request volume in addition to individual payload signatures.

For example:

```text
Normal request
        ↓
Signature inspection

Repeated suspicious requests
        ↓
Behavioral detection
        ↓
Rate-limit / block policy
```

A future module could provide:

```text
scanner/rate_limit.py
```

with configurable controls for:

* Requests per second.
* Requests per minute.
* Per-client thresholds.
* Burst handling.
* Temporary blocking.
* Allowlisted clients.

---

# 16. Professional-Level Recommendation #7 — Add Behavioral Detection

Signature matching alone is insufficient.

A professional WAF should combine:

```text
Signature Detection
        +
Behavioral Detection
        +
Request Anomaly Detection
```

Potential behavioral signals include:

* Excessive request rates.
* Repeated rule violations.
* Unusual HTTP methods.
* Abnormal parameter counts.
* Oversized requests.
* Unexpected content types.
* Repeated failed authentication requests.
* Suspicious request sequences.

---

# 17. Professional-Level Recommendation #8 — Add Request Size Limits

Before performing expensive inspection, establish limits for:

```text
Maximum URL length
Maximum header size
Maximum body size
Maximum parameter count
Maximum header count
```

This reduces resource-exhaustion risk.

The architecture could become:

```text
Request
  │
  ▼
Size Validation
  │
  ├── Reject
  │
  ▼
Normalization
  │
  ▼
Inspection
```

---

# 18. Professional-Level Recommendation #9 — Add Timeouts and Resource Controls

When integrating with live applications or reverse proxies, every network operation should have explicit resource limits.

Recommended controls include:

* Connection timeout.
* Read timeout.
* Request-size limit.
* Processing deadline.
* Maximum regex evaluation complexity.
* Worker limits.
* Queue limits.

Never allow a security inspection layer to become an availability vulnerability itself.

---

# 19. Professional-Level Recommendation #10 — Protect Against Regex Problems

The current engine uses Python regular expressions.

This is acceptable for the educational implementation, but production rule design must consider regex performance.

Poorly designed patterns can cause excessive CPU consumption.

Recommendations:

* Keep patterns simple.
* Avoid catastrophic backtracking.
* Benchmark expensive rules.
* Establish execution limits where possible.
* Review every new rule before deployment.
* Prefer specialized parsers when structured parsing is more appropriate.

---

# 20. Professional-Level Recommendation #11 — Add Metrics

A production WAF should expose operational metrics.

Recommended metrics:

```text
requests_processed_total
requests_allowed_total
requests_monitored_total
requests_blocked_total
detections_total
rule_matches_total
false_positive_reports_total
inspection_latency
request_size
```

Example:

```text
WAF Requests:      125,430
Allowed:           119,210
Monitored:           4,980
Blocked:             1,240
Detections:          1,785
```

These metrics make the WAF observable rather than treating it as a black box.

---

# 21. Professional-Level Recommendation #12 — Add SIEM Integration

The current JSONL output provides a foundation for future security monitoring.

A professional deployment could forward normalized security events to:

* SIEM platforms.
* Security analytics systems.
* Centralized logging infrastructure.
* Alerting pipelines.

The event should contain stable fields such as:

```text
timestamp
request_id
rule_id
rule_version
category
severity
confidence
action
source_identifier
application_identifier
```

Sensitive request data should remain redacted.

---

# 22. Professional-Level Recommendation #13 — Add Health Checks

A deployed WAF should expose operational health information.

Potential checks:

```text
Rule set loaded
Configuration valid
Logging available
Output destination available
Upstream reachable
Worker capacity available
```

A WAF that silently fails open or fails closed without visibility can create significant operational risk.

---

# 23. Professional-Level Recommendation #14 — Define Fail-Open vs Fail-Closed

A production WAF must explicitly define behavior when the WAF itself encounters an error.

### Fail Open

```text
WAF error
   ↓
Request continues
```

Advantage:

* Better application availability.

Risk:

* Security control may be bypassed.

### Fail Closed

```text
WAF error
   ↓
Request blocked
```

Advantage:

* Stronger security posture.

Risk:

* WAF failure can cause application outage.

The correct strategy depends on application criticality, risk tolerance, architecture, and operational requirements.

This decision should be documented rather than accidental.

---

# 24. Professional-Level Recommendation #15 — Use a Reverse Proxy for Edge Deployment

For centralized deployment, a future architecture could be:

```text
Internet
   │
   ▼
┌─────────────────────┐
│ Reverse Proxy + WAF │
└──────────┬──────────┘
           │
           ▼
     Load Balancer
           │
      ┌────┴────┐
      ▼         ▼
 Backend A   Backend B
```

This allows multiple applications to share centralized security controls.

The current Day 26 engine can serve as the conceptual detection/policy core, while a production deployment would require a hardened proxy or middleware integration layer around it.

---

# 25. Professional-Level Recommendation #16 — Add Configuration Validation

Before starting the WAF, validate:

```text
Rule syntax
Severity values
Confidence values
File paths
Logging destinations
Request limits
Policy thresholds
Required configuration
```

Invalid configuration should fail immediately with a clear error rather than causing unpredictable runtime behavior.

---

# 26. Professional-Level Recommendation #17 — Add CI/CD Security Testing

Every change to WAF rules should trigger automated testing.

Recommended pipeline:

```text
Git Commit
    │
    ▼
Lint
    │
    ▼
Unit Tests
    │
    ▼
Security Boundary Tests
    │
    ▼
Regression Tests
    │
    ▼
Performance Tests
    │
    ▼
Build
    │
    ▼
Deployment Approval
```

No new WAF rule should be deployed without regression coverage.

---

# 27. Professional-Level Recommendation #18 — Add Rule Testing Against Benign Traffic

A WAF can cause availability problems if its rules are too aggressive.

Every new rule should therefore be tested against:

```text
Known suspicious input
Known benign input
Edge cases
Encoded input
Case variations
Expected application syntax
```

A professional rule-development workflow should measure:

```text
Detection Rate
False Positive Rate
Performance Cost
```

before enabling a rule globally.

---

# 28. Professional-Level Recommendation #19 — Add Dry-Run / Monitor Mode

Before enabling blocking in a new environment, use:

```text
MONITOR
```

mode.

Recommended rollout:

```text
Stage 1
MONITOR ONLY
      ↓
Review detections
      ↓
Tune rules
      ↓
Stage 2
Selective BLOCK
      ↓
Review false positives
      ↓
Stage 3
Production enforcement
```

This reduces the risk of accidentally blocking legitimate application traffic.

---

# 29. Professional-Level Recommendation #20 — Keep Target Configuration Separate

Do not hard-code authorized environments throughout the source tree.

Avoid patterns such as:

```python
TARGET = "10.10.10.20"
```

spread across multiple modules.

Prefer:

```text
Configuration
     │
     ▼
Integration Adapter
     │
     ▼
WAF Engine
```

This makes the same security engine reusable across:

```text
localhost
development
staging
authorized test environment
production
```

without modifying the detection logic.

---

# 30. What Should Change for a New Target?

The practical rule is:

| Requirement                 | File / Component                                                   |
| --------------------------- | ------------------------------------------------------------------ |
| New request fixtures        | `input/mock_requests.json`                                         |
| Different WAF policy        | `scanner/config.py`                                                |
| New detection rule          | `scanner/config.py` initially; preferably dedicated `rules/` later |
| New application integration | `scanner/cli.py` or dedicated adapter                              |
| New target environment      | Configuration / adapter layer                                      |
| New expected behavior       | `tests/`                                                           |
| New output destination      | CLI arguments/configuration                                        |
| Core detection behavior     | Usually **do not** change                                          |
| Normalization behavior      | Change only if justified by target protocol                        |
| Logging behavior            | Change only for operational requirements                           |
| Reporting format            | Change only when integration requires it                           |

---

# 31. Recommended Change Order

When adapting the WAF to another authorized environment:

### Step 1 — Confirm Authorization

Document:

```text
Target
Owner
Testing scope
Allowed methods
Testing window
Source system
Contact
```

Do not proceed without explicit authorization.

---

### Step 2 — Model the Request

Represent the authorized traffic using:

```python
HTTPRequest
```

or create an appropriate adapter.

---

### Step 3 — Update Configuration

Adjust:

```text
Severity thresholds
Confidence thresholds
Inspection fields
Enabled rules
```

---

### Step 4 — Add Regression Tests

Test:

```text
Expected benign traffic
Expected detections
False positives
Encoded input
Policy behavior
```

---

### Step 5 — Run the Full Test Suite

```bash
python3 -m pytest -q
```

---

### Step 6 — Run Controlled Integration Testing

Use the authorized environment according to the approved scope.

---

### Step 7 — Review Logs and Reports

Check:

```text
output/logs/
output/reports/
```

for unexpected detections or missing events.

---

### Step 8 — Run Formatting Validation

```bash
git diff --check
```

---

# 32. Recommended Professional Architecture

For future development, the target architecture should evolve toward:

```text
                 Authorized Traffic
                         │
                         ▼
              ┌────────────────────┐
              │ Integration Layer  │
              │                    │
              │ Middleware / Proxy │
              └──────────┬─────────┘
                         │
                         ▼
                ┌─────────────────┐
                │ Request Adapter │
                └────────┬────────┘
                         │
                         ▼
                  HTTPRequest
                         │
                         ▼
                ┌─────────────────┐
                │   Normalizer    │
                └────────┬────────┘
                         │
                         ▼
                ┌─────────────────┐
                │ Detection Rules │
                └────────┬────────┘
                         │
                         ▼
                ┌─────────────────┐
                │ Detection Engine│
                └────────┬────────┘
                         │
                         ▼
                ┌─────────────────┐
                │  Policy Engine  │
                └────────┬────────┘
                         │
              ┌──────────┼──────────┐
              ▼          ▼          ▼
           ALLOW      MONITOR      BLOCK
              │          │
              └──────────┼──────────┐
                         ▼          ▼
                    Application   SIEM
```

This preserves the existing Day 26 security logic while providing a scalable path toward a production-style architecture.

---

# 33. What Not to Do

Do not:

* Hard-code credentials into configuration.
* Commit API keys or session tokens.
* Store real passwords in fixtures.
* Use production traffic as an uncontrolled test dataset.
* Send attack payloads to unauthorized systems.
* Disable security tests simply because a rule produces false positives.
* Modify the core engine for every individual target.
* Log complete sensitive request bodies unnecessarily.
* Assume a blocked request means the application is secure.
* Treat regex detection as complete attack prevention.

---

# 34. Final Recommendation

For the current internship implementation, **keep the core WAF engine unchanged when switching environments**.

The preferred adaptation model is:

```text
New Authorized Target
        │
        ▼
New/Updated Input Adapter
        │
        ▼
Existing HTTPRequest Model
        │
        ▼
Existing WAF Engine
        │
        ▼
Existing Policy Engine
        │
        ▼
Existing Logging + Reporting
```

For the current educational version:

```text
input/mock_requests.json
```

is the primary target-data file.

For a more professional implementation, introduce a dedicated adapter/integration layer rather than turning `scanner/cli.py` into a network client.

---

# 35. Final Checklist

Before using the WAF against another authorized environment:

* [ ] Written authorization confirmed.
* [ ] Target and scope documented.
* [ ] Testing window documented.
* [ ] Allowed request types documented.
* [ ] Request adapter implemented if necessary.
* [ ] Target-specific configuration separated from core code.
* [ ] WAF rules reviewed.
* [ ] Regression tests added.
* [ ] False-positive tests added.
* [ ] Sensitive data redaction enabled.
* [ ] Request-size limits configured.
* [ ] Timeouts configured.
* [ ] Logging destination verified.
* [ ] Monitoring configured.
* [ ] Full test suite passes.
* [ ] CLI/integration test passes.
* [ ] Reports reviewed.
* [ ] `git diff --check` passes.

---

# 36. Summary

The Day 26 WAF is intentionally designed so that its **security engine is independent of the environment being inspected**.

The key principle is:

> **Change the integration layer, not the security engine.**

For controlled fixtures, modify:

```text
input/mock_requests.json
```

For policy changes, modify:

```text
scanner/config.py
```

For a new live integration, introduce an adapter rather than embedding target-specific networking throughout the WAF.

For professional-level evolution, prioritize:

```text
Dedicated adapters
Externalized configuration
Versioned rules
Sensitive-data redaction
Request limits
Rate limiting
Behavioral detection
Metrics
SIEM integration
Health checks
Fail-open/fail-closed policy
CI/CD security testing
Performance testing
False-positive measurement
Reverse-proxy deployment
```

The result is a cleaner security architecture that can evolve from a controlled internship laboratory into a more realistic WAF engineering platform without repeatedly rewriting the core detection and policy components.

> **Authorization remains mandatory regardless of architecture. A technically capable WAF does not provide permission to inspect or interfere with a system.**