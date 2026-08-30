# Day 21 — Cross-Site Scripting (XSS) Payload Sanitizer

A defensive Python security laboratory for detecting suspicious **Cross-Site Scripting (XSS)** constructs, neutralizing active structural tokens, and producing auditable validation evidence.

> **Security Notice:** This project is intended for authorized security testing, defensive engineering, education, and controlled laboratory environments. It does not provide a universal XSS protection mechanism. Production applications should rely on context-specific output encoding, safe templating, secure DOM APIs, and defense-in-depth controls.

---

## 1. Overview

Cross-Site Scripting (XSS) occurs when untrusted data reaches a browser interpretation context without appropriate security controls.

Day 21 implements a modular sanitizer that:

* Detects suspicious XSS-related constructs.
* Classifies detected patterns using security rule IDs.
* Assigns severity metadata.
* Replaces detected active constructs with neutral markers.
* HTML-encodes untrusted content.
* Returns structured sanitization results.
* Validates behavior against an adversarial input corpus.
* Produces JSON evidence.
* Maintains persistent execution logs.
* Provides automated regression tests.

The laboratory intentionally goes beyond a minimal `html.escape()` example by separating:

```text
Detection
    ↓
Classification
    ↓
Neutralization
    ↓
HTML Encoding
    ↓
Evidence
```

---

## 2. Objectives

The objectives of Day 21 are to:

1. Understand the mechanics of XSS injection.
2. Implement structural XSS detection rules.
3. Encode HTML-sensitive characters.
4. Neutralize recognized active constructs.
5. Assign contextual security classifications.
6. Build reusable sanitizer components.
7. Test defensive behavior against adversarial inputs.
8. Generate machine-readable validation evidence.
9. Maintain persistent security logs.
10. Document Stored, Reflected, and DOM-based XSS models.

---

## 3. Project Structure

```text
day21-xss-payload-sanitizer/
│
├── input/
│   └── adversarial_payloads.txt
│
├── output/
│   ├── logs/
│   │   └── day21_validation.log
│   │
│   └── reports/
│       └── day21_adversarial_validation.json
│
├── report/
│   └── day21-report.md
│
├── screenshots/
│
├── scanner/
│   ├── __init__.py
│   ├── analyzer.py
│   ├── models.py
│   ├── rules.py
│   └── sanitizer.py
│
├── tests/
│   ├── test_analyzer.py
│   ├── test_rules.py
│   ├── test_sanitizer.py
│   └── test_validation_runner.py
│
└── requirements.txt
```

### Component Overview

| Component                           | Purpose                                 |
| ----------------------------------- | --------------------------------------- |
| `models.py`                         | Structured sanitization result model    |
| `rules.py`                          | XSS detection rule definitions          |
| `sanitizer.py`                      | Detection, neutralization, and encoding |
| `analyzer.py`                       | Higher-level security analysis          |
| `test_sanitizer.py`                 | Sanitization behavior tests             |
| `test_rules.py`                     | Rule integrity tests                    |
| `test_analyzer.py`                  | Analysis tests                          |
| `test_validation_runner.py`         | Adversarial validation tests            |
| `adversarial_payloads.txt`          | Controlled validation corpus            |
| `day21_adversarial_validation.json` | Machine-readable evidence               |
| `day21_validation.log`              | Persistent execution log                |
| `day21-report.md`                   | Professional security assessment        |

---

## 4. Architecture

The sanitizer follows a layered defensive workflow:

```text
                 ┌──────────────────┐
                 │   Raw User Input │
                 └────────┬─────────┘
                          │
                          ▼
                 ┌──────────────────┐
                 │   Rule Detection  │
                 └────────┬─────────┘
                          │
              ┌───────────┴───────────┐
              │                       │
              ▼                       ▼
       No suspicious rule       Rule matched
              │                       │
              │                       ▼
              │              Neutralization Token
              │                       │
              └───────────┬───────────┘
                          ▼
                 ┌──────────────────┐
                 │   HTML Encoding  │
                 └────────┬─────────┘
                          │
                          ▼
                 ┌──────────────────┐
                 │ SanitizationResult│
                 └──────────────────┘
```

The implementation intentionally preserves both detection metadata and the resulting sanitized representation.

---

## 5. Detection Rules

The current rule set contains six XSS-related categories.

| Rule ID             | Description                  | Severity |
| ------------------- | ---------------------------- | -------- |
| `SCRIPT_TAG`        | HTML script element          | CRITICAL |
| `EVENT_HANDLER`     | Inline browser event handler | HIGH     |
| `JAVASCRIPT_SCHEME` | JavaScript URI scheme        | CRITICAL |
| `IFRAME_TAG`        | Iframe element               | HIGH     |
| `SVG_TAG`           | SVG element                  | MEDIUM   |
| `OBJECT_TAG`        | Object element               | HIGH     |

Rules are represented using structured metadata:

```text
rule_id
pattern
description
severity
```

This makes the rule engine easier to extend and test.

---

## 6. Sanitization Behavior

The sanitizer performs two principal defensive operations.

### Detection

The original input is inspected before encoding so that structural patterns remain detectable.

### Neutralization

Detected constructs are replaced with stable markers such as:

```text
[PROHIBITED_TOKEN]:SCRIPT_TAG
```

The resulting representation is subsequently HTML-escaped.

For example, conceptually:

```text
Raw input
    ↓
<script>...</script>
    ↓
Detected: SCRIPT_TAG
    ↓
Neutralized:
[PROHIBITED_TOKEN]:SCRIPT_TAG
    ↓
HTML encoding
    ↓
Safe output representation
```

The exact output is retained in the structured `SanitizationResult`.

---

## 7. Adversarial Validation

The validation corpus contains **10 explicit test cases** covering multiple categories of suspicious and benign input.

The corpus includes examples involving:

* Script elements
* Inline event handlers
* `onload`
* `onerror`
* SVG content
* JavaScript URI schemes
* Attribute-style injection
* Benign HTML-like content
* Encoded entities
* Ordinary text

The corpus is stored at:

```text
input/adversarial_payloads.txt
```

The validator processes the corpus and evaluates whether each case is correctly classified and neutralized according to the laboratory's expectations.

---

## 8. Validation Results

The final validation run completed successfully:

```text
============================================================
DAY 21 - XSS ADVERSARIAL VALIDATION
============================================================

Payloads : 10
Passed   : 10
Failed   : 0
Status   : PASS
```

### Summary

| Metric      |   Result |
| ----------- | -------: |
| Total cases |       10 |
| Passed      |       10 |
| Failed      |        0 |
| Pass rate   |     100% |
| Status      | **PASS** |

The machine-readable validation evidence is generated at:

```text
output/reports/day21_adversarial_validation.json
```

---

## 9. Validation Case Summary

| Case | Result | Severity | Tokens                     |
| ---: | ------ | -------- | -------------------------- |
|    1 | PASS   | CRITICAL | `SCRIPT_TAG`               |
|    2 | PASS   | HIGH     | `EVENT_HANDLER`            |
|    3 | PASS   | HIGH     | `EVENT_HANDLER`            |
|    4 | PASS   | HIGH     | `EVENT_HANDLER`, `SVG_TAG` |
|    5 | PASS   | CRITICAL | `JAVASCRIPT_SCHEME`        |
|    6 | PASS   | CRITICAL | `SCRIPT_TAG`               |
|    7 | PASS   | HIGH     | `EVENT_HANDLER`            |
|    8 | PASS   | LOW      | `NONE`                     |
|    9 | PASS   | LOW      | `NONE`                     |
|   10 | PASS   | LOW      | `NONE`                     |

---

## 10. Logging

The validation runner produces persistent execution logs.

Log location:

```text
output/logs/day21_validation.log
```

The log records:

* Validation start
* Input corpus
* Case execution
* Detection results
* Severity
* Pass/fail status
* Final statistics
* Evidence-report generation

Example:

```text
INFO | day21 | Day 21 adversarial validation starting
INFO | day21 | Payload corpus: input/adversarial_payloads.txt
INFO | day21 | Validating case 1
INFO | day21 | Case 1 result=PASS severity=CRITICAL tokens=SCRIPT_TAG
...
INFO | day21 | Validation complete: cases=10 passed=10 failed=0
```

Persistent logging makes the validation run independently auditable rather than relying only on terminal output.

---

## 11. Automated Testing

The complete pytest suite was executed after the validation runner was added.

Final result:

```text
34 passed in 0.16s
```

The suite verifies:

### Sanitizer

* HTML character encoding
* Script detection
* Event-handler detection
* JavaScript scheme detection
* Iframe detection
* SVG detection
* Object detection
* Benign input handling
* Quote encoding
* Type validation

### Rules

* Rule existence
* Rule ID uniqueness
* Required rule metadata
* Expected rule categories

### Analyzer

* Security classification behavior
* Analysis consistency

### Validation Runner

* Corpus processing
* Expected case count
* Validation status
* Evidence generation behavior

---

## 12. XSS Models

Day 21 also evaluates three major XSS architectures.

### Stored XSS

Malicious input is persisted by an application and subsequently served to users.

```text
Attacker
   ↓
Application
   ↓
Database
   ↓
Stored Content
   ↓
Victim Browser
```

Examples include malicious content stored in:

* Comments
* Profiles
* Messages
* Forum posts

Primary defenses include safe templating, context-aware output encoding, validation, and defense-in-depth browser controls.

---

### Reflected XSS

Untrusted input is immediately reflected by an application into a response.

```text
Crafted Request
      ↓
   Web App
      ↓
HTML Response
      ↓
Browser
```

Common locations include search parameters, error messages, and dynamically rendered request parameters.

Correct output encoding remains a primary defense.

---

### DOM-Based XSS

Untrusted data reaches a dangerous client-side DOM operation.

```text
Untrusted Data
      ↓
Client JavaScript
      ↓
DOM Sink
      ↓
Browser Interpretation
```

This model may occur without the server directly reflecting the dangerous content.

Client-side code review and safe DOM APIs are therefore particularly important.

---

## 13. XSS Model Comparison

| Property        | Stored                | Reflected        | DOM-Based             |
| --------------- | --------------------- | ---------------- | --------------------- |
| Data persisted  | Yes                   | Usually no       | Usually no            |
| Primary layer   | Server/storage        | Server response  | Client                |
| Trigger         | Stored content viewed | Crafted request  | Client-side data flow |
| Server required | Usually               | Usually          | Not necessarily       |
| Key defense     | Output encoding       | Output encoding  | Safe DOM APIs         |
| CSP             | Defense in depth      | Defense in depth | Defense in depth      |

---

## 14. Security Limitations

This project deliberately does **not** claim to be a universal XSS prevention system.

Regular expressions and blacklist-style detection have inherent limitations.

They may encounter:

* False positives
* False negatives
* Alternate representations
* Encoding transformations
* Browser parser differences
* Context-dependent behavior

Most importantly, **HTML escaping is not a universal substitute for context-specific output encoding**.

An application must consider whether untrusted data is being inserted into:

```text
HTML text
HTML attributes
JavaScript
CSS
URLs
DOM operations
```

Each context has different parsing and encoding requirements.

---

## 15. Production Security Recommendations

For production applications, the following controls are recommended.

### Input handling

* Validate data according to business requirements.
* Reject unnecessary markup.
* Treat all external data as untrusted.

### Output handling

* Apply context-specific output encoding.
* Use established framework escaping mechanisms.
* Prefer safe templating engines.
* Avoid constructing HTML through string concatenation.

### Client-side security

* Prefer safe DOM APIs.
* Avoid dangerous HTML interpretation sinks.
* Review client-side data flows.
* Apply appropriate Content Security Policy controls.

### Security testing

* Maintain regression tests.
* Test multiple output contexts.
* Review security-sensitive changes.
* Continuously update security rules based on application requirements.

---

## 16. Evidence

The completed Day 21 evidence set includes:

```text
input/adversarial_payloads.txt
output/logs/day21_validation.log
output/reports/day21_adversarial_validation.json
report/day21-report.md
tests/test_sanitizer.py
tests/test_rules.py
tests/test_analyzer.py
tests/test_validation_runner.py
```

These artifacts demonstrate:

```text
Implementation
     +
Automated Testing
     +
Adversarial Validation
     +
Persistent Logging
     +
Machine-Readable Evidence
     +
Security Documentation
```

---

## 17. Reproducing the Lab

Activate the project virtual environment:

```bash
source .venv/bin/activate
```

Run the complete test suite:

```bash
python3 -m pytest -q
```

Expected result:

```text
34 passed
```

Run the adversarial validation:

```bash
python3 -m scanner.validate --verbose
```

Expected result:

```text
Payloads : 10
Passed   : 10
Failed   : 0
Status   : PASS
```

Inspect the generated evidence:

```bash
cat output/logs/day21_validation.log
```

and:

```bash
cat output/reports/day21_adversarial_validation.json
```

Verify repository formatting:

```bash
git diff --check
```

---

## 18. Final Verification

Final automated verification:

```text
34 passed in 0.16s
```

Repository whitespace verification:

```text
git diff --check
```

Result:

```text
PASS
```

Adversarial validation:

```text
10 / 10 PASS
```

Evidence generation:

```text
JSON report: PASS
Persistent log: PASS
```

---

## 19. Key Security Lessons

Day 21 demonstrates several important application-security principles:

1. **Untrusted input must never be assumed safe.**
2. **Detection and prevention are different security functions.**
3. **Output encoding should be selected according to context.**
4. **Regex filtering should not be treated as a complete XSS defense.**
5. **Stored, Reflected, and DOM-based XSS require different analysis perspectives.**
6. **Safe framework and DOM APIs are preferable to manual HTML construction.**
7. **CSP provides defense in depth rather than replacing secure coding.**
8. **Security controls should be regression-tested.**
9. **Security testing should produce reproducible evidence.**
10. **Logs and structured reports improve auditability.**

---

## 20. Conclusion

Day 21 successfully evolved the initial XSS sanitization exercise into a structured defensive security laboratory.

The completed implementation provides:

* Modular XSS detection rules
* Structured sanitization results
* HTML encoding
* Rule-based neutralization
* Severity classification
* Adversarial validation
* Automated regression testing
* Persistent logging
* JSON evidence reporting
* Professional security documentation

The final results demonstrate:

```text
10/10 adversarial validation cases passed
34/34 automated tests passed
git diff --check passed
```

The project also establishes an important engineering boundary: a payload sanitizer based on pattern detection should be treated as a **supporting security control**, not as the application's sole XSS defense.

Robust XSS protection requires correct context-specific output encoding, safe application and DOM APIs, secure templating, appropriate validation, and defense-in-depth controls.

---

# Day 21 Status

```text
╔══════════════════════════════════════════════════════════╗
║          DAY 21 — XSS PAYLOAD SANITIZER                 ║
╠══════════════════════════════════════════════════════════╣
║ Foundation                 COMPLETE                     ║
║ Detection Engine           COMPLETE                     ║
║ Adversarial Validation     COMPLETE                     ║
║ JSON Evidence              COMPLETE                     ║
║ Persistent Logging         COMPLETE                     ║
║ Automated Tests            34 PASSED                   ║
║ Validation Cases           10 / 10 PASSED              ║
║ Repository Check           PASS                         ║
║ Documentation              COMPLETE                     ║
╠══════════════════════════════════════════════════════════╣
║ STATUS: DAY 21 — COMPLETE                               ║
╚══════════════════════════════════════════════════════════╝
```

**Authorized defensive security laboratory completed successfully.**
