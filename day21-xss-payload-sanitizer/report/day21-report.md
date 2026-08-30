# Day 21 — Cross-Site Scripting (XSS) Payload Sanitizer

## 1. Executive Summary

Day 21 focused on the development and validation of a defensive **Cross-Site Scripting (XSS) payload sanitizer** designed to identify suspicious client-side injection constructs and transform untrusted input into an HTML-safe representation.

The implementation combines:

* HTML output encoding using Python's `html.escape()`
* Rule-based detection of suspicious XSS constructs
* Stable classification tokens for detected patterns
* Structured sanitization results
* Severity metadata
* Adversarial validation
* Automated unit and integration testing
* JSON evidence reporting
* Persistent execution logging

The final validation corpus contained **10 explicit adversarial inputs** representing script elements, browser event handlers, JavaScript URI schemes, SVG constructs, encoded input, malformed/attribute-style payloads, and benign content.

The completed validation run achieved:

| Metric             |        Result |
| ------------------ | ------------: |
| Validation cases   |            10 |
| Passed             |            10 |
| Failed             |             0 |
| Validation status  |      **PASS** |
| Automated tests    | **34 passed** |
| `git diff --check` |      **PASS** |

The exercise demonstrates how structural detection and context-appropriate output encoding can reduce the risk of untrusted input being interpreted as active browser content.

---

## 2. Objective

The primary objective was to implement a defensive XSS payload sanitization component capable of:

1. Accepting untrusted string input.
2. Detecting predefined XSS-related structural patterns.
3. Classifying detected constructs using stable rule identifiers.
4. Encoding HTML-sensitive characters.
5. Replacing detected active constructs with neutral markers.
6. Producing structured sanitization results.
7. Validating behavior against adversarial test cases.
8. Generating reproducible security evidence.

The implementation was intentionally designed as a **defensive analysis and sanitization laboratory**, operating entirely on supplied input strings.

---

## 3. Scope

The Day 21 implementation covers detection of the following categories:

| Rule ID             | Construct                     | Severity |
| ------------------- | ----------------------------- | -------- |
| `SCRIPT_TAG`        | HTML `<script>` element       | CRITICAL |
| `EVENT_HANDLER`     | Inline browser event handlers | HIGH     |
| `JAVASCRIPT_SCHEME` | `javascript:` URI scheme      | CRITICAL |
| `IFRAME_TAG`        | HTML `<iframe>` element       | HIGH     |
| `SVG_TAG`           | SVG element                   | MEDIUM   |
| `OBJECT_TAG`        | HTML `<object>` element       | HIGH     |

The implementation also performs general HTML escaping on input regardless of whether a suspicious rule is detected.

---

## 4. Architecture

The Day 21 project follows a modular architecture:

```text
day21-xss-payload-sanitizer/
├── input/
│   └── adversarial_payloads.txt
├── output/
│   ├── logs/
│   │   └── day21_validation.log
│   └── reports/
│       └── day21_adversarial_validation.json
├── report/
│   └── day21-report.md
├── scanner/
│   ├── analyzer.py
│   ├── models.py
│   ├── rules.py
│   └── sanitizer.py
├── screenshots/
├── tests/
│   ├── test_analyzer.py
│   ├── test_rules.py
│   ├── test_sanitizer.py
│   └── test_validation_runner.py
└── requirements.txt
```

### Component responsibilities

#### `scanner/models.py`

Defines the structured `SanitizationResult` model.

The model records:

* Original input
* HTML-encoded representation
* Final sanitized representation
* Detected rule identifiers
* Whether neutralization occurred

This prevents the sanitizer from returning an unstructured string with no evidence about what happened during processing.

#### `scanner/rules.py`

Contains the centralized `XSSRule` definitions.

Each rule contains:

* Rule identifier
* Regular-expression pattern
* Description
* Severity

Centralizing detection metadata makes the detection engine easier to test, extend, and audit.

#### `scanner/sanitizer.py`

Implements the primary sanitization workflow:

```text
Raw Input
    │
    ▼
Rule Detection
    │
    ├── Suspicious constructs detected
    │
    ▼
Neutralization
    │
    ▼
HTML Encoding
    │
    ▼
SanitizationResult
```

HTML encoding is treated as the primary defensive transformation, while rule-based token replacement provides additional detection and evidence.

#### `scanner/analyzer.py`

Provides higher-level analysis functionality around sanitization results and security classifications.

#### `tests/`

Contains automated verification of:

* Rule definitions
* Rule uniqueness
* Detection behavior
* Sanitization behavior
* Input validation
* Analyzer behavior
* Validation-runner behavior

---

## 5. Sanitization Strategy

The sanitizer uses a two-stage defensive approach.

### Stage 1 — Detection

The original payload is inspected against the configured XSS rules.

For example, a script element is classified using:

```text
SCRIPT_TAG
```

An inline browser event handler is classified using:

```text
EVENT_HANDLER
```

Detection occurs against the original input rather than the already-encoded representation so that structural patterns remain identifiable.

### Stage 2 — Neutralization and Encoding

Detected constructs are replaced with stable neutral markers.

For example:

```text
[PROHIBITED_TOKEN]:SCRIPT_TAG
```

The resulting string is then HTML-escaped.

This produces a representation intended to prevent the original structural characters from being interpreted as executable HTML when inserted into an HTML context.

---

## 6. Detection Rules

### 6.1 `SCRIPT_TAG`

Detects script elements.

**Severity:** CRITICAL

Rationale:

A script element represents an explicit browser script execution context and therefore receives the highest classification in this laboratory.

---

### 6.2 `EVENT_HANDLER`

Detects inline event-handler attributes such as:

```text
onerror=
onload=
onclick=
onmouseover=
onfocus=
onsubmit=
```

**Severity:** HIGH

Rationale:

Inline event handlers can cause browser-side execution when inserted into an appropriate HTML context.

---

### 6.3 `JAVASCRIPT_SCHEME`

Detects the JavaScript URI scheme.

**Severity:** CRITICAL

Rationale:

A JavaScript URI can represent an active browser execution context when interpreted by a vulnerable application and browser context.

---

### 6.4 `IFRAME_TAG`

Detects iframe elements.

**Severity:** HIGH

Rationale:

An iframe can introduce external or embedded content and may become security-sensitive depending on application context and browser policies.

---

### 6.5 `SVG_TAG`

Detects SVG elements.

**Severity:** MEDIUM

Rationale:

SVG is a structured browser content format that can become security-sensitive when untrusted markup is inserted into an HTML document.

---

### 6.6 `OBJECT_TAG`

Detects object elements.

**Severity:** HIGH

Rationale:

Object elements can introduce embedded resources and therefore warrant elevated scrutiny when originating from untrusted input.

---

## 7. Adversarial Validation Corpus

The validation corpus contained ten explicit test cases.

The cases were designed to cover multiple classes of suspicious and benign input rather than testing only a single `<script>` example.

The validation set included:

1. Script-element payload
2. Image event-handler payload
3. Body `onload` payload
4. SVG event-handler payload
5. JavaScript URI
6. Attribute-breaking/script-style payload
7. Event-handler attribute fragment
8. Benign HTML-like text
9. Encoded entity representation
10. Ordinary security-related text

This provides broader behavioral coverage than a single known payload.

---

## 8. Validation Results

The final validation execution produced:

```text
============================================================
DAY 21 - XSS ADVERSARIAL VALIDATION
============================================================

Payloads : 10
Passed   : 10
Failed   : 0
Status   : PASS
```

### Case results

| Case | Result | Severity | Detection                  |
| ---: | ------ | -------- | -------------------------- |
|    1 | PASS   | CRITICAL | `SCRIPT_TAG`               |
|    2 | PASS   | HIGH     | `EVENT_HANDLER`            |
|    3 | PASS   | HIGH     | `EVENT_HANDLER`            |
|    4 | PASS   | HIGH     | `EVENT_HANDLER`, `SVG_TAG` |
|    5 | PASS   | CRITICAL | `JAVASCRIPT_SCHEME`        |
|    6 | PASS   | CRITICAL | `SCRIPT_TAG`               |
|    7 | PASS   | HIGH     | `EVENT_HANDLER`            |
|    8 | PASS   | LOW      | NONE                       |
|    9 | PASS   | LOW      | NONE                       |
|   10 | PASS   | LOW      | NONE                       |

Overall:

```text
Cases : 10
Passed: 10
Failed: 0
```

The complete machine-readable evidence was written to:

```text
output/reports/day21_adversarial_validation.json
```

---

## 9. Logging Evidence

Persistent execution logging was implemented to ensure that validation activity was not dependent solely on terminal output.

The generated log is:

```text
output/logs/day21_validation.log
```

The log records:

* Validation start
* Corpus location
* Individual case execution
* Pass/fail status
* Severity
* Detected rule identifiers
* Final validation totals
* Evidence-report creation

Example:

```text
INFO | day21 | Day 21 adversarial validation starting
INFO | day21 | Payload corpus: input/adversarial_payloads.txt
INFO | day21 | Validating case 1
INFO | day21 | Case 1 result=PASS severity=CRITICAL tokens=SCRIPT_TAG
...
INFO | day21 | Validation complete: cases=10 passed=10 failed=0
INFO | day21 | Evidence report written to output/reports/day21_adversarial_validation.json
```

This provides reproducible evidence that the validation process actually executed.

---

## 10. Automated Testing

The project was subjected to the complete pytest suite.

Final result:

```text
34 passed in 0.16s
```

The tests cover several layers of the application.

### Sanitizer tests

Verify:

* HTML special-character encoding
* Script detection
* Event-handler detection
* JavaScript scheme detection
* iframe detection
* SVG detection
* Object detection
* Plain-text handling
* Quote encoding
* Type validation

### Rule tests

Verify:

* Rules exist
* Rule IDs are unique
* Required metadata exists
* Expected security categories are present

### Analyzer tests

Verify higher-level security-analysis behavior.

### Validation-runner tests

Verify that the adversarial validation workflow correctly processes the expected corpus and produces the expected validation behavior.

---

## 11. XSS Threat Model

Cross-Site Scripting occurs when attacker-controlled data reaches a browser execution or markup interpretation context without appropriate defensive handling.

Three major XSS models were considered during this exercise.

### 11.1 Stored XSS

Stored XSS occurs when malicious input is persisted by an application and later delivered to other users.

Typical data flow:

```text
Attacker Input
      │
      ▼
Application
      │
      ▼
Database / Storage
      │
      ▼
Victim Request
      │
      ▼
HTML Response
      │
      ▼
Browser
```

The primary concern is persistence and repeated delivery.

Examples of potentially affected application components include:

* Comments
* User profiles
* Forum posts
* Stored messages
* Content-management systems

Defensive controls include:

* Context-specific output encoding
* Input validation
* Safe templating
* Content Security Policy
* Secure application architecture

---

### 11.2 Reflected XSS

Reflected XSS occurs when attacker-controlled input is immediately reflected into an application response.

Typical flow:

```text
Attacker-Controlled Request
          │
          ▼
       Web App
          │
          ▼
     HTML Response
          │
          ▼
        Browser
```

Unlike stored XSS, the payload generally does not need to be persisted.

Potentially affected locations include:

* Search parameters
* Error messages
* Query parameters
* Form submissions
* Dynamic page content

The primary defense remains correct output encoding for the context into which the value is inserted.

---

### 11.3 DOM-Based XSS

DOM-based XSS occurs primarily within client-side JavaScript when untrusted data is processed by browser-side code and inserted into a dangerous DOM context.

Typical flow:

```text
Untrusted Data
      │
      ▼
Client-side JavaScript
      │
      ▼
Dangerous DOM Sink
      │
      ▼
Browser Interpretation
```

Examples of risky DOM patterns include inappropriate use of APIs that interpret strings as HTML or executable browser content.

DOM-based XSS therefore requires client-side security analysis in addition to server-side filtering.

---

## 12. Comparison of XSS Models

| Property             | Stored XSS                  | Reflected XSS                       | DOM-Based XSS              |
| -------------------- | --------------------------- | ----------------------------------- | -------------------------- |
| Persistence          | Yes                         | Usually no                          | Usually no                 |
| Primary location     | Server/database             | Server response                     | Client-side JavaScript     |
| Trigger              | Victim views stored content | Victim follows crafted request/link | Client-side data flow      |
| Server involvement   | Usually                     | Usually                             | May be minimal/none        |
| Important defense    | Output encoding             | Output encoding                     | Safe DOM APIs and encoding |
| CSP relevance        | High                        | High                                | High                       |
| Client-side analysis | Useful                      | Useful                              | Essential                  |

The same malicious-looking string can have completely different security implications depending on the context in which the application processes it.

---

## 13. Security Design Considerations

The implementation deliberately does **not** treat regex filtering as a complete XSS defense.

This is an important security distinction.

A blacklist-based approach such as:

```text
script
onerror
onload
```

cannot reliably represent every possible browser parsing context or every valid application encoding state.

Likewise, detection rules may produce false positives or false negatives.

The implementation therefore uses the following defensive hierarchy:

```text
1. Context-aware application design
2. Context-specific output encoding
3. Safe templating / DOM APIs
4. Input validation
5. Detection and security monitoring
6. CSP as defense in depth
```

The sanitizer's rule engine should therefore be considered an **additional defensive and analytical layer**, not the sole security control.

---

## 14. Context-Specific Output Encoding

One of the primary lessons from this exercise is that encoding must correspond to the output context.

Different contexts have different parsing rules.

Examples include:

* HTML text context
* HTML attribute context
* JavaScript string context
* CSS context
* URL context

HTML escaping alone should not automatically be assumed to make a value safe for every possible context.

For example, a value intended for HTML text should be handled differently from a value incorporated into a JavaScript string or URL.

Applications should use established, context-aware encoding mechanisms and safe framework APIs instead of attempting to construct a universal XSS filter.

---

## 15. Limitations

The Day 21 implementation has intentional limitations.

### Regex limitations

Regular expressions are useful for identifying known structural patterns but are not equivalent to a browser parser.

### Context limitations

The sanitizer does not know the eventual context in which an application will use the returned value.

### Browser parsing complexity

Modern browsers support complex HTML, SVG, URL, CSS, and DOM parsing behavior that cannot be comprehensively represented by a small rule set.

### Encoded and transformed input

Attackers may use transformations, alternate encodings, or context-specific representations that are not covered by the configured rules.

### False positives

Security-sensitive tokens can occur in harmless text.

For example, a security training document may legitimately contain the word `script` without representing an executable script element.

### False negatives

A rule engine may fail to identify an unexpected or newly discovered injection construct.

For these reasons, the project should be viewed as a **training-oriented detection and sanitization component**, rather than a production-grade universal XSS prevention mechanism.

---

## 16. Recommended Remediation Controls

A production application handling untrusted content should implement layered controls.

### Application layer

* Validate input according to business requirements.
* Avoid unnecessary acceptance of raw HTML.
* Use framework-provided escaping mechanisms.
* Prefer safe templating engines.
* Avoid constructing HTML through string concatenation.

### Browser/client layer

* Prefer safe DOM APIs.
* Avoid dangerous HTML interpretation sinks when possible.
* Treat browser-side data flows as security-sensitive.
* Apply appropriate Content Security Policy controls.

### Security engineering layer

* Maintain security regression tests.
* Test multiple browser parsing contexts.
* Review new client-side sinks during code changes.
* Monitor security-sensitive input paths.
* Keep detection rules version-controlled and auditable.

---

## 17. Evidence Inventory

The final Day 21 evidence set consists of:

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

The evidence demonstrates both **implementation correctness** and **actual adversarial validation execution**.

---

## 18. Final Verification

The final project verification produced:

```text
34 passed in 0.16s
```

Repository formatting verification:

```text
git diff --check
```

Result:

```text
PASS
```

No whitespace errors were reported.

---

## 19. Conclusion

Day 21 successfully implemented a modular XSS payload sanitization and analysis laboratory.

The project progressed beyond a minimal demonstration by introducing:

* Structured security models
* Centralized XSS rules
* Detection and neutralization logic
* Severity classification
* Automated testing
* An adversarial validation corpus
* Machine-readable evidence
* Persistent execution logs
* Security-focused documentation

The final validation achieved **10/10 adversarial cases passed**, while the complete automated test suite achieved **34/34 tests passed**.

The most important security conclusion is that **XSS prevention cannot safely depend on a simple blacklist or regular-expression filter alone**. Reliable protection requires correct handling of untrusted data according to its eventual parsing context, supported by safe application frameworks, context-specific output encoding, secure client-side APIs, and defense-in-depth controls such as Content Security Policy.

Day 21 therefore demonstrates both the practical mechanics of payload detection and the broader application-security principle that **security controls must be designed around the context in which untrusted data is interpreted**.

**Status: DAY 21 — COMPLETE**
