# Day 20 — Web Directory Discovery & Exposure Scanner

A controlled Python-based web directory discovery scanner developed as part of the **Cybersecurity Internship — Week 4: Web Application Reconnaissance & Code Auditing**.

The project demonstrates how a security assessment can progress from HTTP path discovery to **security detection, risk classification, evidence generation, and structured reporting**.

> **Authorized-use notice:** This scanner is intended for local labs, CTFs, test environments, and systems for which explicit authorization has been granted. The Day 20 validation was performed exclusively against an intentionally vulnerable local HTTP server.

---

## 1. Objectives

The objectives of Day 20 are to:

* Discover HTTP-accessible application paths.
* Classify discovered endpoints using HTTP status codes.
* Detect potentially sensitive exposed resources.
* Assign security severity and risk scores.
* Generate machine-readable JSON reports.
* Generate human-readable TXT reports.
* Validate the complete scanner pipeline through automated tests.
* Execute the scanner against a controlled vulnerable local web application.
* Preserve evidence suitable for an internship-style security assessment.

---

## 2. Assessment Architecture

The scanner follows a layered processing pipeline:

```text
Wordlist
   │
   ▼
HTTP Client
   │
   ▼
PathResult
   │
   ▼
Security Detector
   │
   ▼
Risk Analyzer
   │
   ▼
Web Directory Analyzer
   │
   ▼
Scan Reporter
   ├──────────────┐
   ▼              ▼
 JSON             TXT
```

The architecture separates network communication, detection logic, risk assessment, analysis, and reporting so each component can be tested independently.

---

## 3. Project Structure

```text
day20-web-directory-scanner/
├── app/
│   └── server.py
│
├── input/
│   └── paths.txt
│
├── output/
│   ├── logs/
│   └── reports/
│       ├── day20_phase4.json
│       ├── day20_phase4.txt
│       ├── day20_phase5.json
│       └── day20_phase5.txt
│
├── report/
│   └── day20-report.md
│
├── screenshots/
│
├── scanner/
│   ├── __init__.py
│   ├── analyzer.py
│   ├── client.py
│   ├── cli.py
│   ├── config.py
│   ├── detector.py
│   ├── intelligence.py
│   ├── models.py
│   ├── reporting.py
│   ├── report_schema.py
│   ├── risk.py
│   ├── rules.py
│   └── wordlist.py
│
├── tests/
│   ├── test_analyzer.py
│   ├── test_client.py
│   ├── test_cli_integration.py
│   ├── test_config.py
│   ├── test_detector.py
│   ├── test_integration.py
│   ├── test_intelligence.py
│   ├── test_reporting.py
│   ├── test_risk.py
│   ├── test_rules.py
│   └── test_wordlist.py
│
└── requirements.txt
```

---

## 4. Core Components

### `scanner/models.py`

Defines the primary data structures used throughout the scanner.

`ScanConfig` contains:

* Base URL
* Wordlist path
* Request timeout
* Redirect behavior

`PathResult` represents the result of scanning an individual path, including:

* Path
* URL
* HTTP status code
* Response length
* Redirect location
* Error information
* Scan timestamp

---

### `scanner/client.py`

Implements HTTP requests using a `requests.Session`.

For every wordlist entry, the client:

1. Normalizes the path.
2. Constructs the target URL.
3. Sends an HTTP GET request.
4. Records the response status.
5. Records response length.
6. Records redirect information.
7. Captures request errors without terminating the complete scan.

---

### `scanner/detector.py`

Contains the security detection engine.

The detector evaluates `PathResult` objects and generates security findings for conditions including:

* HTTP 200 accessible endpoints
* HTTP 403 restricted endpoints
* HTTP redirects
* HTTP 5xx responses
* Sensitive paths returning successful responses

Sensitive resources are identified using the project's security rules.

---

### `scanner/risk.py`

Maps detected conditions to risk assessments.

Current scoring includes:

| Rule                 | Score | Severity |
| -------------------- | ----: | -------- |
| `SENSITIVE_EXPOSURE` |    90 | CRITICAL |
| `DIRECTORY_200`      |    20 | MEDIUM   |
| `DIRECTORY_5XX`      |    15 | MEDIUM   |
| `DIRECTORY_REDIRECT` |    10 | LOW      |
| `DIRECTORY_403`      |     5 | LOW      |

Each assessment also contains a classification and remediation recommendation.

---

### `scanner/analyzer.py`

Coordinates the detection and risk-analysis stages.

```text
PathResult
    ↓
SecurityDetector
    ↓
SecurityFinding
    ↓
RiskAnalyzer
    ↓
RiskAssessment
    ↓
Report Finding
```

The analyzer produces the finding objects consumed by the reporting layer.

---

### `scanner/reporting.py`

Generates structured assessment reports.

Supported formats:

* JSON
* TXT

JSON reports are validated against the project's report schema before being written.

Reports contain metadata such as:

* Schema version
* Scan ID
* Target
* Start/completion timestamps
* Scan duration
* Wordlist size
* Requests sent
* Findings
* Severity summary

---

### `scanner/cli.py`

Provides the command-line interface.

Available options:

```text
--url URL
--wordlist WORDLIST
--json JSON
--text TEXT
--timeout TIMEOUT
--follow-redirects
--verbose
```

Use:

```bash
python3 -m scanner.cli --help
```

for the complete command reference.

---

## 5. Input Wordlist

The scanner uses:

```text
input/paths.txt
```

The Day 20 laboratory wordlist contains common application paths, sensitive files, and operational locations.

Example entries:

```text
admin
dashboard
api
api/v1
.env
.git/
backup.sql
backup.zip
login
uploads
static
```

Blank lines and comments beginning with `#` are ignored automatically.

---

## 6. Local Vulnerable Laboratory

Day 20 includes an intentionally vulnerable HTTP server:

```text
app/server.py
```

The server is designed exclusively for controlled security testing.

The laboratory exposes selected routes with predetermined responses.

Expected behavior includes:

| Endpoint      | Expected Response | Purpose                             |
| ------------- | ----------------: | ----------------------------------- |
| `/`           |               200 | Baseline application                |
| `/admin`      |               403 | Access-control demonstration        |
| `/.env`       |               200 | Intentional sensitive-file exposure |
| `/backup.sql` |               200 | Intentional backup exposure         |
| `/missing`    |               404 | Negative control                    |

The vulnerable endpoints are intentionally configured to demonstrate the scanner's detection and risk-analysis capabilities.

---

## 7. Installation

Activate the project virtual environment:

```bash
source .venv/bin/activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

---

## 8. Automated Testing

The project contains unit and integration tests covering the scanner's major components.

Run the complete test suite:

```bash
python3 -m pytest -q
```

Current validation:

```text
42 passed
```

The test suite validates functionality including:

* Configuration validation
* Wordlist parsing
* HTTP client behavior
* Path-result handling
* Security detection
* Sensitive-path detection
* Risk scoring
* Analyzer behavior
* Report generation
* JSON schema validation
* CLI integration
* End-to-end reporting

---

## 9. Running the Local Laboratory

Start the intentionally vulnerable server:

```bash
python3 app/server.py
```

The laboratory listens on:

```text
http://127.0.0.1:5000
```

Verify the intentionally exposed resources manually:

```bash
curl -i http://127.0.0.1:5000/.env
```

```bash
curl -i http://127.0.0.1:5000/admin
```

```bash
curl -i http://127.0.0.1:5000/backup.sql
```

Expected results include:

```text
/.env        → HTTP 200
/admin       → HTTP 403
/backup.sql  → HTTP 200
```

---

## 10. Running the Scanner

With the local laboratory running:

```bash
python3 -m scanner.cli \
  --url http://127.0.0.1:5000 \
  --wordlist input/paths.txt \
  --json output/reports/day20_phase5.json \
  --text output/reports/day20_phase5.txt \
  --verbose
```

The scanner will test every usable wordlist entry and generate both report formats.

---

## 11. Phase 5 Validation Results

The scanner was executed against the local intentionally vulnerable server.

Observed scan metrics:

```text
Target        : http://127.0.0.1:5000
Wordlist      : 11 entries
Requests      : 11
Findings      : 5
Critical      : 2
High          : 0
Medium        : 2
Low           : 1
```

The two critical findings were:

```text
/.env
severity=CRITICAL
score=90
```

and:

```text
/backup.sql
severity=CRITICAL
score=90
```

The `/admin` endpoint returned:

```text
HTTP 403 Forbidden
```

demonstrating a restricted endpoint within the same controlled application.

---

## 12. Security Findings

### Critical — `.env` Exposure

The scanner identified:

```text
/.env → HTTP 200
```

The local laboratory intentionally returned environment-style configuration data.

Potential real-world impact includes exposure of:

* Application configuration
* Database connection information
* API credentials
* Secret keys
* Debug settings
* Environment-specific configuration

### Recommended Remediation

Sensitive environment files should never be stored inside a web-accessible document root.

Recommended controls include:

* Move configuration files outside the web root.
* Deny direct access to hidden configuration files.
* Remove secrets from deployed static resources.
* Rotate exposed credentials when exposure occurs.
* Add deployment checks preventing sensitive files from being published.

---

### Critical — Database Backup Exposure

The scanner identified:

```text
/backup.sql → HTTP 200
```

The local laboratory intentionally returned SQL backup content.

Potential real-world impact includes exposure of:

* Database structure
* Application data
* User information
* Credentials
* Internal schema information

### Recommended Remediation

Database backups should be stored outside the web-accessible filesystem.

Recommended controls include:

* Remove backup files from the document root.
* Store backups in protected storage.
* Apply restrictive filesystem permissions.
* Prevent backup extensions from being served publicly.
* Monitor deployments for accidentally exposed archives and database dumps.

---

### Low — Administrative Endpoint

The scanner identified:

```text
/admin → HTTP 403
```

This indicates that the endpoint exists but access is currently restricted.

Recommended controls:

* Maintain authentication and authorization controls.
* Verify that alternate paths cannot bypass protection.
* Review access-control behavior periodically.
* Avoid unnecessarily exposing administrative interfaces.

---

## 13. Evidence

Phase 5 generated:

```text
output/reports/day20_phase5.json
output/reports/day20_phase5.txt
```

The JSON report provides structured machine-readable results.

The TXT report provides a human-readable assessment summary.

Additional evidence should be stored under:

```text
screenshots/
```

Recommended evidence includes:

```text
phase5-scan-results.png
phase5-sensitive-env.png
phase5-sensitive-backup.png
```

These screenshots document:

1. Successful CLI execution.
2. Direct `.env` exposure.
3. Direct `backup.sql` exposure.

---

## 14. Report Schema

The generated JSON report follows schema version:

```text
1.0
```

The report includes:

```text
schema_version
scan_id
target
started_at
completed_at
duration_seconds
wordlist_size
requests_sent
findings
summary
```

The report writer validates the structure before saving the JSON artifact.

This provides an additional integrity check between the analysis layer and final evidence.

---

## 15. Security Considerations

This project is intended for **authorized security testing only**.

Recommended use cases:

* Local development environments
* Intentionally vulnerable applications
* Cybersecurity training labs
* CTF environments
* Authorized penetration-testing engagements
* Internal security validation

Do not scan systems without explicit authorization.

The included Day 20 validation was performed against:

```text
127.0.0.1:5000
```

which is the local intentionally vulnerable training server.

---

## 16. Learning Outcomes

By completing Day 20, the following practical concepts were demonstrated:

* Web path discovery
* HTTP response classification
* Sensitive resource detection
* Security-rule implementation
* Risk scoring
* Severity classification
* Security recommendations
* CLI design
* HTTP client implementation
* Automated unit testing
* Integration testing
* JSON schema validation
* Security evidence collection
* Local vulnerable-lab execution
* Machine-readable reporting
* Human-readable reporting

---

## 17. Day 20 Pipeline Verification

The complete implementation has been validated as:

```text
Wordlist
   ↓
HTTP Client
   ↓
PathResult
   ↓
Detector
   ↓
SecurityFinding
   ↓
Risk Analyzer
   ↓
RiskAssessment
   ↓
WebDirectoryAnalyzer
   ↓
ScanReporter
   ├──→ JSON
   └──→ TXT
```

Automated validation:

```text
42 passed
```

Local Phase 5 validation:

```text
11 requests
5 findings
2 critical
2 medium
1 low
```

---

## 18. Final Status

```text
DAY 20 — WEB DIRECTORY DISCOVERY SCANNER

[✓] Scanner architecture implemented
[✓] HTTP client implemented
[✓] Wordlist processing implemented
[✓] Security detection implemented
[✓] Sensitive-path detection implemented
[✓] Risk analysis implemented
[✓] JSON reporting implemented
[✓] TXT reporting implemented
[✓] Report schema validation implemented
[✓] Unit tests implemented
[✓] Integration tests implemented
[✓] CLI integration validated
[✓] Local vulnerable lab implemented
[✓] Phase 5 execution completed
[✓] Evidence collected
[✓] Remediation documented

Status: COMPLETE
```

---

## 19. Internship Deliverables

The completed Day 20 package provides:

* Source code
* Automated test suite
* Controlled vulnerable HTTP lab
* Input wordlist
* Phase 4 integration reports
* Phase 5 real-execution reports
* Evidence screenshots
* Security findings
* Risk classifications
* Remediation guidance
* Professional assessment documentation

This transforms the project from a standalone Python scanner into a reproducible **security assessment laboratory and reporting workflow**.
