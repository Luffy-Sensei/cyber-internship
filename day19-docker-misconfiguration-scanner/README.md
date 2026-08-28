# Day 19 — Docker Container Misconfiguration Scanner

## Overview

Day 19 implements a static security analysis engine for Dockerfiles.

The scanner evaluates container build specifications against common security hardening requirements, identifies configuration weaknesses, assigns risk severity and scores, and produces structured JSON and human-readable TXT reports.

The project is designed as a defensive security-auditing tool for authorized development, CI/CD, and container-security workflows.

---

## Objective

Audit Dockerfile configurations for security-relevant deployment weaknesses, including:

* Implicit root execution
* Explicit `USER root` configuration
* Unpinned `latest` base-image tags
* SSH exposure through `EXPOSE 22`
* Missing security-hardening directives
* Other rule-defined container configuration risks

The scanner provides actionable findings rather than simply reporting raw configuration matches.

---

## Security Concepts

### 1. Non-Privileged Runtime

Containers should avoid running application processes as root whenever possible.

A Dockerfile containing an explicit non-root `USER` directive establishes a safer runtime context and reduces the potential impact of application compromise.

### 2. Explicit Root Execution

An explicit:

```dockerfile
USER root
```

directive represents a privileged runtime configuration and is therefore treated as a security finding.

### 3. Immutable Base Images

Using:

```dockerfile
FROM python:latest
```

introduces version drift because the `latest` tag can resolve to different image versions over time.

Production builds should use a specific version or, where appropriate, an immutable image digest.

### 4. SSH Exposure

Exposing TCP port 22 from an application container can unnecessarily increase the attack surface.

The scanner therefore treats:

```dockerfile
EXPOSE 22
```

as a critical configuration finding.

---

## Architecture

```text
day19-docker-misconfiguration-scanner/
│
├── input/
│   ├── Dockerfile.test
│   └── Dockerfile.insecure
│
├── output/
│   ├── logs/
│   │   └── day19_detector.log
│   └── reports/
│       ├── day19_docker.json
│       ├── day19_docker.txt
│       ├── day19_insecure.json
│       └── day19_insecure.txt
│
├── report/
│   └── day19-report.md
│
├── scanner/
│   ├── analyzer.py
│   ├── cli.py
│   ├── config.py
│   ├── detector.py
│   ├── logging_utils.py
│   ├── models.py
│   ├── parser.py
│   ├── reporting.py
│   ├── report_schema.py
│   ├── risk.py
│   └── rules.py
│
├── screenshots/
│   ├── insecure_scan.png
│   ├── report_output.png
│   ├── secure_scan.png
│   └── test_suite.png
│
├── tests/
│   ├── test_analyzer.py
│   ├── test_cli.py
│   ├── test_config.py
│   ├── test_detector.py
│   ├── test_logging.py
│   ├── test_parser.py
│   ├── test_reporting.py
│   ├── test_risk.py
│   └── test_rules.py
│
├── requirements.txt
└── README.md
```

---

## Processing Pipeline

The scanner follows a structured analysis pipeline:

```text
Dockerfile
    │
    ▼
Parser
    │
    ▼
Structured Dockerfile Model
    │
    ▼
Security Rules
    │
    ▼
Evidence Extraction
    │
    ▼
Risk Intelligence
    │
    ├── Severity
    ├── Risk Score
    ├── Classification
    └── Recommendation
    │
    ▼
Report Generation
    │
    ├── JSON
    └── TXT
    │
    ▼
CLI / Logging
```

This separation keeps parsing, detection, risk analysis, and reporting independently testable.

---

## Security Rules

The detection layer evaluates Dockerfile instructions against rule identifiers and produces structured findings containing:

* Rule identifier
* Severity
* Line number
* Evidence
* Security message
* Recommendation

The implemented rule set includes checks for:

| Rule           | Description                       | Example Risk             |
| -------------- | --------------------------------- | ------------------------ |
| Missing `USER` | No explicit runtime user          | Privileged execution     |
| `USER root`    | Container explicitly runs as root | Privilege exposure       |
| `LATEST_TAG`   | Base image uses `latest`          | Build/version drift      |
| `EXPOSE_22`    | SSH port exposed                  | Increased attack surface |

---

## Risk Intelligence

Detected issues are passed through the risk-analysis layer.

Each finding can contain:

* Severity
* Numerical risk score
* Classification
* Remediation recommendation

The analyzer also aggregates findings to provide an overall security picture of the scanned Dockerfile.

Severity levels used by the project are:

```text
CRITICAL
HIGH
MEDIUM
LOW
```

---

## CLI Usage

Run the scanner using the Python module interface:

```bash
python -m scanner.cli
```

Default execution analyzes:

```text
input/Dockerfile.test
```

### Help

```bash
python -m scanner.cli --help
```

Available options:

```text
--input INPUT
--json JSON
--text TEXT
--verbose
```

### Scan a specific Dockerfile

```bash
python -m scanner.cli \
  --input input/Dockerfile.insecure
```

### Specify report destinations

```bash
python -m scanner.cli \
  --input input/Dockerfile.insecure \
  --json output/reports/custom.json \
  --text output/reports/custom.txt
```

### Enable verbose logging

```bash
python -m scanner.cli --verbose
```

---

## Validation

The project includes automated tests covering:

* Dockerfile parsing
* Configuration
* Security rules
* Detection
* Evidence and line numbers
* Risk scoring
* Severity classification
* Recommendations
* Report generation
* JSON schema validation
* CLI behavior
* Logging
* Error handling
* Missing input files
* Malformed Dockerfile input

Final validation:

```text
28 passed
```

---

## Secure Configuration Test

The baseline Dockerfile contains a non-privileged runtime configuration and does not trigger the implemented security rules.

Example execution result:

```text
Instructions: 6
Findings    : 0
Critical    : 0
High        : 0
Medium      : 0
Low         : 0
```

This demonstrates the expected clean result for a compliant test configuration.

---

## Insecure Configuration Test

The intentionally insecure Dockerfile is used to validate detection and risk classification.

Example execution result:

```text
Instructions: 5
Findings    : 3
Critical    : 1
High        : 1
Medium      : 1
Low         : 0
```

This confirms that the scanner can identify multiple independent Docker security weaknesses and classify them according to the implemented risk model.

---

## Reporting

Every successful scan can produce two report formats.

### JSON

The JSON report is designed for structured processing and future integration with security automation or CI/CD pipelines.

It includes:

* Report version
* Run identifier
* Generation timestamp
* Input file
* Statistics
* Findings
* Rule information
* Risk information
* Recommendations

Example location:

```text
output/reports/day19_insecure.json
```

### TXT

The TXT report provides a human-readable security assessment suitable for analyst review.

Example location:

```text
output/reports/day19_insecure.txt
```

---

## Operational Logging

The scanner records operational events in:

```text
output/logs/day19_detector.log
```

Logging includes events such as:

* Scanner startup
* Successful analysis
* Analysis statistics
* Missing input errors
* Other operational conditions

This provides traceability during command-line execution and testing.

---

## Error Handling

The CLI handles common operational failures without silently producing misleading security results.

Examples include:

* Missing Dockerfile
* Invalid or malformed input
* Parsing failures
* Invalid command-line input

The project also includes automated tests for error-handling behavior.

---

## Defensive Scope

This project performs **static analysis only**.

It does not:

* Build Docker images
* Execute Dockerfiles
* Start containers
* Attempt container breakout
* Exploit vulnerable configurations
* Modify host or container infrastructure

The test Dockerfiles are intentionally local fixtures used to validate defensive detection logic.

---

## Secure Dockerfile Checklist

For production container images, the following baseline should be considered:

* [ ] Use a specific base-image version instead of `latest`
* [ ] Prefer immutable image digests for controlled production builds
* [ ] Run application processes as a non-root user
* [ ] Avoid unnecessary `USER root`
* [ ] Do not expose SSH unless operationally required
* [ ] Use multi-stage builds where appropriate
* [ ] Keep the final image minimal
* [ ] Avoid embedding secrets in Dockerfiles or image layers
* [ ] Remove unnecessary build dependencies from runtime images
* [ ] Restrict exposed network services
* [ ] Validate images through automated security checks before deployment
* [ ] Maintain reproducible and reviewable build configurations

---

## Evidence

The `screenshots/` directory contains execution evidence for the completed lab:

```text
test_suite.png
secure_scan.png
insecure_scan.png
report_output.png
```

These demonstrate automated validation, clean configuration analysis, insecure configuration detection, and generated reporting.

---

## Day 19 Deliverables

| Deliverable                    | Status   |
| ------------------------------ | -------- |
| Dockerfile parser              | Complete |
| Security detection engine      | Complete |
| Rule identifiers               | Complete |
| Evidence extraction            | Complete |
| Risk scoring                   | Complete |
| Severity classification        | Complete |
| Recommendations                | Complete |
| JSON reporting                 | Complete |
| TXT reporting                  | Complete |
| Report schema validation       | Complete |
| CLI interface                  | Complete |
| Verbose logging                | Complete |
| Error handling                 | Complete |
| Automated tests                | Complete |
| Secure Dockerfile validation   | Complete |
| Insecure Dockerfile validation | Complete |
| Execution screenshots          | Complete |
| Technical report               | Complete |

---

## Conclusion

Day 19 delivers a modular Dockerfile security scanner capable of transforming static container configuration into structured security findings.

The implementation demonstrates the complete defensive workflow:

```text
Parse
  ↓
Detect
  ↓
Extract Evidence
  ↓
Assess Risk
  ↓
Classify
  ↓
Recommend Remediation
  ↓
Generate Reports
  ↓
Validate
```

The resulting architecture provides a foundation that can be extended with additional Dockerfile rules, CI/CD integration, policy enforcement, image metadata analysis, and broader container-security controls in future labs.
