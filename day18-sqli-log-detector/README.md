# Day 18 — SQL Injection Log Detection Engine

A defensive Python security tool for detecting SQL Injection (SQLi) indicators in HTTP access logs.

The engine parses web interaction records, identifies known SQLi signatures, assigns confidence and risk classifications, and produces structured JSON and human-readable TXT security reports.

> **Scope:** This project is designed for authorized defensive security analysis, detection engineering, and security education. It does not perform SQL injection against live applications or databases.

---

## Objectives

- Parse HTTP access-log entries into structured records.
- Detect common SQL Injection indicators.
- Identify multiple signatures within a single request.
- Assign detection confidence levels.
- Calculate security risk scores.
- Classify findings by severity.
- Generate machine-readable JSON reports.
- Generate human-readable TXT reports.
- Maintain structured execution logs.
- Provide a reusable command-line interface.
- Validate behavior with an automated test suite.

---

## Detection Coverage

The current detection engine identifies signatures including:

| Signature | Description | Typical Confidence |
|---|---|---|
| `TAUTOLOGY` | Logical expressions such as `' OR '1'='1` | HIGH |
| `UNION_SELECT` | `UNION SELECT` SQL composition indicators | HIGH |
| `SQL_COMMENT` | SQL comment sequences such as `--` | MEDIUM |

Multiple indicators can be detected within the same request.

For example, a request containing both `UNION SELECT` and `--` may receive a higher overall risk classification than either indicator individually.

---

## Architecture

```text
                    CLI
                     |
                     v
              Configuration
                     |
                     v
                  Parser
                     |
                     v
                Detection
                     |
                     v
              Intelligence
                     |
                     v
                Risk Engine
                     |
                     v
                Reporting
                 /      \
                v        v
              JSON       TXT
                     |
                     v
                  Logging
```
## Components
| Module                     | Responsibility                       |
| -------------------------- | ------------------------------------ |
| `scanner/models.py`        | Structured data models               |
| `scanner/config.py`        | Detector configuration               |
| `scanner/parser.py`        | Access-log parsing                   |
| `scanner/signatures.py`    | SQLi signature definitions           |
| `scanner/detector.py`      | Signature detection                  |
| `scanner/intelligence.py`  | Security analysis and classification |
| `scanner/risk.py`          | Risk scoring and severity            |
| `scanner/reporting.py`     | JSON/TXT report generation           |
| `scanner/report_schema.py` | Report validation                    |
| `scanner/logging_utils.py` | Logging configuration                |
| `scanner/cli.py`           | Command-line interface               |
## Project Structure
```text
day18-sqli-log-detector/
├── input/
│   └── mock_access.log
├── output/
│   ├── logs/
│   │   └── day18_detector.log
│   └── reports/
│       ├── day18_sqli.json
│       └── day18_sqli.txt
├── report/
│   └── day18-report.md
├── screenshots/
│   ├── CLI_execution.png
│   ├── Detection_evidence.png
│   ├── report_validation.png
│   └── Test_suite.png
├── scanner/
│   ├── cli.py
│   ├── config.py
│   ├── detector.py
│   ├── intelligence.py
│   ├── logging_utils.py
│   ├── models.py
│   ├── parser.py
│   ├── reporting.py
│   ├── report_schema.py
│   ├── risk.py
│   └── signatures.py
├── tests/
│   ├── test_cli.py
│   ├── test_detector.py
│   ├── test_intelligence.py
│   ├── test_logging.py
│   ├── test_parser.py
│   ├── test_reporting.py
│   └── test_risk.py
└── requirements.txt
```
## Requirements
- Python 3.13+
- pytest

A virtual environment is recommended.

### Setup
```bash
python -m venv .venv
source .venv/bin/activate
```
Install dependencies:
```bash
pip install -r requirements.txt
```
## Running the Detector

Use the default input and output locations:
```bash
python -m scanner.cli
```
The default input is:
```text
input/mock_access.log
```
The default reports are:
```text
output/reports/day18_sqli.json
output/reports/day18_sqli.txt
```
## Command-Line Options

Display the available options:
```bash
python -m scanner.cli --help
```
### Custom input
```bash
python -m scanner.cli \
  --input input/mock_access.log
```
### Custom JSON report
```bash
python -m scanner.cli \
  --json output/reports/custom.json
```
### Custom TXT report
```bash
python -m scanner.cli \
  --text output/reports/custom.txt
```
### Verbose logging
```bash
python -m scanner.cli --verbose
```
### Full custom execution
```bash
python -m scanner.cli \
  --input input/mock_access.log \
  --json output/reports/custom.json \
  --text output/reports/custom.txt \
  --verbos
  ```
### Example Detection Result

The included mock log contains three entries.

The detector identifies two security findings:
```text
Detections : 2
Critical   : 1
High       : 1
Medium     : 0
Low        : 0
```
Example finding:
```text
Source       : 10.0.4.12
Method       : POST
Path         : /auth/login?user=admin%27%20OR%20%271%27=%271
Status       : 401
Severity     : HIGH
Risk Score   : 70
Classification: SQLI_INDICATOR
```
Detected signature:
```text
TAUTOLOGY (HIGH)
Evidence: OR '1'='1
```
Another request containing multiple SQLi indicators is classified as:
```text
Severity   : CRITICAL
Risk Score : 100
```
## Reporting
### JSON

The JSON report contains:

- Report version
- Unique run identifier
- Generation timestamp
- Input source
- Detection statistics
- Severity counts
- Individual findings
- Detection signatures
- Evidence
- Risk classification
- Recommendations
### TXT

The TXT report provides a human-readable security summary suitable for analyst review and documentation.

## Logging

Execution logs are stored in:
```text
output/logs/day18_detector.log
```
The logging layer records events such as:
```text
INFO
WARNING
ERROR
```
Malformed access-log entries are skipped rather than terminating the entire analysis.

Example:
```text
WARNING | day18 | Skipping malformed line 2:
Invalid access-log entry
```
Missing input files are reported as errors and cause the CLI to return a non-zero exit status.

Defensive SQL Injection Analysis

SQL Injection occurs when application-controlled input becomes executable SQL syntax.

### Unsafe pattern

Conceptually, an application may construct a query by combining SQL syntax and user input directly:
```text
SQL statement + user-controlled input
```
This creates an opportunity for input to alter the intended SQL structure.

### Secure pattern

Prepared statements separate the SQL structure from parameter values:
```text
SQL structure
     +
parameter value
```
The database driver treats the supplied value as data rather than allowing it to redefine the SQL statement.

## Defensive principle

Applications should:

- Use parameterized queries / prepared statements.
- Validate input according to application requirements.
- Apply least-privilege database accounts.
- Monitor suspicious request patterns.
- Log relevant security events.
- Review repeated SQLi indicators.
- Avoid exposing detailed database errors to clients.
## Testing

Run the complete test suite:
```bash
python -m pytest -q
```
Final Day 18 validation:
```text
25 passed
```
The test suite covers:

- Parsing
- SQLi signature detection
- Risk classification
- Security intelligence
- Report generation
- Report schema validation
- CLI behavior
- Missing-input handling
- Logging
## Security Considerations

This tool performs detection and analysis only.

It should be used against:

- Authorized log files
- Lab environments
- Systems where security monitoring is explicitly permitted
- Controlled security-testing environments

The engine does not attempt to exploit detected requests or interact with a target database.

Detection signatures are indicators rather than definitive proof of compromise. Security analysts should correlate findings with application logs, database telemetry, authentication events, and other available evidence.

## Limitations

The current implementation is intentionally lightweight.

It does not provide:

- Full SQL grammar parsing
- Database-side telemetry
- Application-aware semantic analysis
- Distributed log ingestion
- Persistent alert storage
- Real-time SIEM integration
- Advanced anomaly detection
- ML-based classification

These are potential future extensions.

## Future Improvements

Potential enhancements include:

1. Additional SQLi signature families.
2. URL decoding and normalization before detection.
3. Signature weighting based on context.
4. Repeated-source correlation.
5. Time-window based attack detection.
6. Rate-based anomaly detection.
7. SIEM-compatible output.
8. CSV reporting.
9. Configurable detection policies.
10. Unit and integration test expansion.
11. Structured JSON logging.
12. Dashboard integration.
## Day 18 Outcome

Day 18 establishes a reusable defensive detection pipeline:
```text
Raw Web Logs
     ↓
Structured Parsing
     ↓
SQLi Signature Detection
     ↓
Security Intelligence
     ↓
Risk Classification
     ↓
Validated Reports
     ↓
Analyst Review
```
The project demonstrates how security engineering can transform raw application telemetry into actionable defensive intelligence.

***Day 18 — SQL Injection Log Detection Engine***

***Status: Complete***