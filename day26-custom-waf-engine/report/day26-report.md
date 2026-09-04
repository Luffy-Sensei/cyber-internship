# Day 26 — Custom Web Application Firewall (WAF) Engine

## 1. Executive Summary

Day 26 focused on the design and implementation of a lightweight, rule-based Web Application Firewall (WAF) engine.

The objective was to construct a defensive middleware-style security component capable of receiving structured HTTP request data, normalizing the request, evaluating configurable security rules, generating detections, applying enforcement policies, and recording the resulting security decisions.

The implementation specifically addresses three representative application-layer attack categories:

* SQL Injection (SQLi)
* Cross-Site Scripting (XSS)
* Path Traversal

The completed engine separates request normalization, detection, policy enforcement, logging, and reporting into independent components. This modular design improves testability, maintainability, and future extensibility.

Testing also included security-boundary and false-positive cases to verify that the engine does not indiscriminately block benign input.

The final CLI integration was validated using controlled mock HTTP request fixtures.

---

## 2. Objective

The primary objective of Day 26 was:

> Construct middleware logic capable of intercepting, inspecting, and enforcing decisions against suspicious HTTP request payloads using configurable WAF rules.

The implementation was designed to demonstrate the core processing model of a WAF without requiring live traffic interception or external exploitation.

---

## 3. Security Scope

This project is strictly defensive and educational.

Testing was performed using controlled JSON fixtures representing HTTP requests. No unauthorized systems, external targets, production traffic, or real malicious payloads were required.

The implementation demonstrates detection of representative indicators rather than attempting to provide complete protection against all application-layer attacks.

A production WAF would require substantially broader rule coverage, continuous tuning, operational monitoring, and integration with the surrounding application-security architecture.

---

# 4. Architecture

The completed processing pipeline is:

```text
                    HTTP Request
                         │
                         ▼
               ┌──────────────────┐
               │ RequestNormalizer│
               └────────┬─────────┘
                        │
                        ▼
               ┌──────────────────┐
               │   WAFRuleEngine  │
               │                  │
               │ SQLi             │
               │ XSS              │
               │ Path Traversal   │
               └────────┬─────────┘
                        │
                        ▼
             ┌──────────────────────┐
             │ WAFDetectionEngine   │
             └──────────┬───────────┘
                        │
                        ▼
             ┌──────────────────────┐
             │  WAFPolicyEngine     │
             │                      │
             │ ALLOW / MONITOR /    │
             │ BLOCK                │
             └──────────┬───────────┘
                        │
             ┌──────────┼───────────┐
             │          │           │
             ▼          ▼           ▼
           Backend     Audit       Reports
                      Logging
```

The architecture deliberately separates **detection** from **enforcement**.

This means that identifying suspicious traffic does not automatically determine how that traffic must be handled. The policy layer makes the final enforcement decision.

---

# 5. Implementation Components

## 5.1 Data Models

File:

```text
scanner/models.py
```

The model layer defines the primary WAF data structures.

Implemented models include:

* `HTTPRequest`
* `WAFRule`
* `WAFDetection`
* `WAFDecision`
* `WAFResult`

Enumerations define:

* `WAFAction`
* `RuleCategory`
* `Severity`
* `Confidence`

The models are immutable dataclasses where appropriate, providing predictable state management throughout the pipeline.

---

## 5.2 Configuration

File:

```text
scanner/config.py
```

The configuration layer defines:

* Default WAF rules.
* Severity thresholds.
* Confidence thresholds.
* Default enforcement behavior.
* Request fields selected for inspection.

The default policy is:

```text
LOW       → ALLOW
MEDIUM    → MONITOR
HIGH      → BLOCK
CRITICAL  → BLOCK
```

The minimum confidence threshold is configurable.

---

# 6. Request Normalization

File:

```text
scanner/normalizer.py
```

Normalization is performed before security-rule evaluation.

The normalizer:

* Uppercases HTTP methods.
* Removes unnecessary whitespace.
* Decodes URL-encoded values.
* Normalizes HTTP header names.
* Trims header values.
* Produces a canonical representation of the request.

This stage is important because a security rule that only examines raw input may miss encoded indicators.

For example:

```text
%3Cscript%3E
```

is decoded before rule inspection, allowing the XSS rule to identify the script-tag indicator.

---

# 7. WAF Rule Engine

File:

```text
scanner/rules.py
```

The rule engine compiles configured regular expressions and evaluates them against normalized request fields.

The currently implemented rules are:

| Rule ID         | Category       | Severity | Detection Purpose                      |
| --------------- | -------------- | -------- | -------------------------------------- |
| `SQLI-001`      | SQLI           | HIGH     | Detects `UNION SELECT` indicators      |
| `XSS-001`       | XSS            | HIGH     | Detects script-tag indicators          |
| `TRAVERSAL-001` | PATH_TRAVERSAL | HIGH     | Detects directory traversal indicators |

The engine evaluates:

```text
Path
Query
Headers
Body
```

Multiple detections are aggregated rather than stopping at the first match.

This allows a single request to produce multiple findings when more than one security indicator is present.

---

# 8. Detection Engine

File:

```text
scanner/engine.py
```

The detection engine orchestrates the normalization and rule-inspection stages.

Its responsibility is intentionally narrow:

```text
HTTPRequest
    │
    ▼
Rule Engine
    │
    ▼
WAFResult
```

The resulting `WAFResult` records:

* Request identifier.
* Detection collection.
* Whether a detection occurred.
* Total detection count.

The detection layer does not decide whether traffic should be allowed or blocked.

---

# 9. Policy Enforcement

File:

```text
scanner/policies.py
```

The policy engine converts detection results into enforcement decisions.

The current default behavior is:

```text
No Detection → ALLOW

LOW          → ALLOW

MEDIUM       → MONITOR

HIGH         → BLOCK

CRITICAL     → BLOCK
```

Confidence filtering is performed before the final action is selected.

This architecture allows organizations to adjust enforcement thresholds independently from the detection rules.

For example, a rule can remain enabled while an organization initially configures the policy to monitor medium-severity findings instead of blocking them.

---

# 10. Structured Audit Logging

File:

```text
scanner/logging.py
```

The audit logger records WAF decisions using JSON Lines.

Output:

```text
output/logs/waf-audit.jsonl
```

Each event records structured information such as:

* Timestamp.
* Request ID.
* HTTP method.
* Request path.
* Detection count.
* Triggered rules.
* Detection categories.
* Severity.
* Confidence.
* Final WAF action.

Evidence is intentionally bounded rather than logging unnecessary complete request bodies.

This reduces unnecessary information exposure while preserving useful security telemetry.

---

# 11. Security Reporting

File:

```text
scanner/reporting.py
```

The reporting component generates two report formats.

### JSON

```text
output/reports/day26-report.json
```

The JSON report is intended for machine-readable processing.

It contains:

* Run ID.
* Timestamp.
* Requests processed.
* Allowed count.
* Monitored count.
* Blocked count.
* Detection count.
* Triggered rules.
* Individual decisions.

### TXT

```text
output/reports/day26-report.txt
```

The TXT report provides a human-readable representation suitable for manual review and internship evidence.

---

# 12. CLI Integration

File:

```text
scanner/cli.py
```

The CLI provides the end-to-end runtime interface.

The default input file is:

```text
input/mock_requests.json
```

The default output locations are:

```text
output/logs/waf-audit.jsonl
output/reports/day26-report.json
output/reports/day26-report.txt
```

The engine can be executed using:

```bash
python3 -m scanner.cli
```

The CLI performs the complete pipeline:

```text
Load Fixtures
     ↓
Normalize
     ↓
Detect
     ↓
Apply Policy
     ↓
Log Decision
     ↓
Generate Reports
```

---

# 13. Controlled Runtime Validation

The runtime validation used two controlled request fixtures.

## Request 1 — Benign Request

```json
{
  "request_id": "req-001",
  "method": "GET",
  "path": "/products",
  "query": "category=books"
}
```

Expected behavior:

```text
Detections = 0
Action     = ALLOW
```

Observed behavior:

```text
req-001 | GET /products | Detections=0 | Action=ALLOW
```

The request was correctly identified as benign.

---

## Request 2 — Controlled XSS Indicator

```json
{
  "request_id": "req-002",
  "method": "GET",
  "path": "/search",
  "query": "q=%3Cscript%3E"
}
```

The query contains a URL-encoded script-tag indicator.

The normalization stage decodes the value before inspection.

Observed behavior:

```text
req-002 | GET /search | Detections=1 | Action=BLOCK
```

This confirms that the complete normalization, detection, and policy pipeline operates correctly.

---

# 14. Runtime Results

The validated CLI execution produced:

```text
=== DAY 26 CUSTOM WAF ENGINE ===
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

### Result Summary

| Metric             | Result |
| ------------------ | -----: |
| Requests processed |      2 |
| Allowed            |      1 |
| Monitored          |      0 |
| Blocked            |      1 |
| Detections         |      1 |

The result demonstrates both sides of the enforcement pipeline:

```text
Benign Request
      ↓
    ALLOW

Suspicious Request
      ↓
   DETECTION
      ↓
    BLOCK
```

---

# 15. Security Testing

The project includes dedicated security-boundary testing.

The test suite covers:

### Attack Indicators

* SQL Injection
* XSS
* Path Traversal
* Multiple simultaneous indicators
* URL-encoded indicators

### Validation and Safety

* Invalid request structures.
* Empty request identifiers.
* Empty paths.
* Empty query strings.
* Empty request bodies.
* Disabled rules.
* Confidence thresholds.
* Custom policy thresholds.

### False-Positive Checks

The implementation also tests benign strings that could otherwise trigger overly broad signatures.

Examples include:

```text
scriptwriting
union membership
parent-directory
```

These cases help verify that the WAF does not simply block every request containing loosely related keywords.

---

# 16. Testing Strategy

Testing was performed incrementally during development.

The project followed a phase-based validation model:

```text
Foundation
    ↓
Normalization
    ↓
Rules
    ↓
Detection
    ↓
Policy
    ↓
Logging & Reporting
    ↓
Security Boundary
    ↓
CLI Integration
```

Each phase was validated using focused tests before the complete test suite was executed.

The final security-boundary stage reached:

```text
16 focused tests passed
70 full-suite tests passed
```

The CLI integration stage was subsequently validated using controlled runtime fixtures.

The exact final test count should be re-confirmed with:

```bash
python3 -m pytest -q
```

before producing final release evidence.

---

# 17. Test Coverage Areas

The test suite provides coverage across:

```text
Models
Configuration
Normalization
Rule Compilation
Rule Detection
Detection Engine
Policy Enforcement
Structured Logging
Report Generation
CLI Input Loading
Security Boundaries
False-Positive Handling
```

This layered approach reduces the likelihood that changes in one component silently break another part of the pipeline.

---

# 18. Threat Detection Model

The WAF uses signature-based inspection.

Conceptually:

```text
Request
   │
   ▼
Normalize
   │
   ▼
Inspect Fields
   │
   ├── SQLi Rule
   ├── XSS Rule
   └── Traversal Rule
   │
   ▼
Generate Detection
   │
   ▼
Evaluate Severity
   │
   ▼
Apply Policy
```

Signature-based detection is useful for known indicators but has inherent limitations.

Attackers may use:

* Alternative encodings.
* Obfuscation.
* Application-specific syntax.
* Novel payload structures.
* Parser ambiguities.
* Logic flaws that do not match simple signatures.

Therefore, this engine should be considered one layer within a broader defense-in-depth architecture.

---

# 19. Inline WAF Architecture

An inline or middleware WAF can operate close to application request processing.

```text
Client
  │
  ▼
HTTP Request
  │
  ▼
WAF Middleware
  │
  ├── ALLOW ──► Application
  │
  ├── MONITOR ► Application + Logging
  │
  └── BLOCK
```

### Advantages

* Application-aware inspection.
* Straightforward integration.
* Access to application-specific request context.
* Useful for internal services and development environments.

### Limitations

* Security logic can become coupled to application infrastructure.
* Scaling may become more complex.
* Application compromise could potentially affect the security control.
* Centralized enforcement across multiple applications requires additional architecture.

---

# 20. Reverse-Proxy WAF Architecture

A reverse-proxy WAF operates before requests reach backend applications.

```text
Client
  │
  ▼
┌─────────────────┐
│ Reverse Proxy   │
│       +         │
│      WAF        │
└────────┬────────┘
         │
         ▼
    Application
```

### Advantages

* Centralized security enforcement.
* Multiple backend applications can share policies.
* Security processing is separated from application code.
* Suitable for larger service architectures.
* Can integrate naturally with load balancing.

### Limitations

* Requires additional infrastructure.
* Proxy configuration must be secure.
* TLS termination must be designed carefully.
* Incorrect rules can create availability problems through false positives.

---

# 21. Security Recommendations

For continued development, the following improvements are recommended.

## Rule Management

* Expand coverage carefully.
* Add regression tests for every new rule.
* Version security rules.
* Document the purpose and limitations of each rule.
* Measure false-positive rates.

## Logging

* Integrate with centralized security monitoring.
* Add correlation identifiers.
* Avoid logging sensitive request data unnecessarily.
* Define retention policies.

## Monitoring

Future deployments could expose:

* Detection rates.
* Block rates.
* False-positive rates.
* Top triggered rules.
* Requests per second.
* Rule performance.

## Production Hardening

A production implementation should additionally consider:

* Rate limiting.
* Authentication and authorization context.
* TLS termination.
* Secure proxy configuration.
* Distributed deployment.
* High availability.
* Configuration management.
* Alerting.
* SIEM integration.
* Operational dashboards.
* Incident-response integration.

---

# 22. Limitations

The Day 26 WAF is intentionally a compact educational implementation.

It is **not** intended to replace mature production WAF platforms.

Known limitations include:

1. The rule set is intentionally small.
2. Detection relies primarily on regular expressions.
3. Signature-based detection cannot identify every attack.
4. Advanced evasion techniques are outside the current scope.
5. No live reverse-proxy deployment is included.
6. No TLS termination is implemented.
7. No distributed architecture is implemented.
8. No rate-limiting subsystem is included.
9. No external SIEM integration is included.
10. Production-scale performance has not been benchmarked.
11. Rules require ongoing tuning to control false positives.
12. Blocking decisions should not be treated as proof that an application is secure.

---

# 23. Defensive Engineering Assessment

The implementation successfully demonstrates the fundamental lifecycle of a WAF request:

```text
INGEST
  ↓
NORMALIZE
  ↓
INSPECT
  ↓
DETECT
  ↓
CLASSIFY
  ↓
ENFORCE
  ↓
AUDIT
  ↓
REPORT
```

The separation of responsibilities provides a solid foundation for future development.

In particular, separating:

```text
Detection ≠ Policy
```

is an important architectural decision.

It allows the same detection engine to support different operational policies, such as:

```text
Development → MONITOR
Staging     → MONITOR / BLOCK
Production  → BLOCK
```

depending on organizational requirements.

---

# 24. Evidence Artifacts

The following artifacts are produced by the completed implementation:

```text
input/mock_requests.json

output/logs/waf-audit.jsonl

output/reports/day26-report.json

output/reports/day26-report.txt
```

Recommended evidence captures include:

1. Full `pytest` execution.
2. CLI runtime execution.
3. Generated JSON report.
4. Structured JSONL audit log.
5. Project directory structure.
6. Optional security-boundary test execution.

These artifacts provide evidence of both implementation and operational behavior.

---

# 25. Reproduction Procedure

From the Day 26 directory:

```bash
source .venv/bin/activate
```

Run the complete test suite:

```bash
python3 -m pytest -q
```

Run the WAF:

```bash
python3 -m scanner.cli
```

Inspect the audit log:

```bash
cat output/logs/waf-audit.jsonl
```

Inspect the JSON report:

```bash
cat output/reports/day26-report.json
```

Inspect the text report:

```bash
cat output/reports/day26-report.txt
```

Validate Git formatting:

```bash
git diff --check
```

---

# 26. Conclusion

Day 26 successfully implemented a modular, rule-based Web Application Firewall engine capable of processing controlled HTTP request fixtures through a complete defensive security pipeline.

The final implementation provides:

* Structured HTTP request models.
* Request normalization.
* Configurable security rules.
* SQLi detection.
* XSS detection.
* Path traversal detection.
* Multi-detection aggregation.
* Severity classification.
* Confidence filtering.
* Configurable policy enforcement.
* `ALLOW`, `MONITOR`, and `BLOCK` actions.
* Structured JSONL audit logging.
* JSON reporting.
* Human-readable TXT reporting.
* CLI integration.
* Security-boundary testing.
* False-positive regression testing.

The validated runtime demonstrated that a benign request was allowed while a URL-encoded XSS indicator was normalized, detected, and blocked.

The project therefore fulfills the primary Day 26 objective of demonstrating how a custom WAF can inspect application-layer request data and apply configurable defensive enforcement decisions.

---

## Final Status

```text
DAY 26 — CUSTOM WEB APPLICATION FIREWALL

Implementation       : COMPLETE
Detection Pipeline   : VALIDATED
Policy Engine        : VALIDATED
Logging              : VALIDATED
Reporting            : VALIDATED
CLI Integration      : VALIDATED
Security Boundaries  : VALIDATED
Controlled Runtime   : VALIDATED

STATUS: COMPLETE
```

> **Authorized-use requirement:** All future testing of this WAF against live applications, networks, or production traffic must be performed only with explicit authorization and within an approved security-testing scope.