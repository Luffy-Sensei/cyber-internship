# Day 17 — Local Network Port & Service Scanner

## Overview

Day 17 implements a controlled TCP port and service scanner for authorized local security assessment.

The project demonstrates how socket connectivity can be used to identify exposed TCP services, enrich results with service intelligence, evaluate basic security exposure, and generate structured security reports.

The scanner is currently restricted to the local loopback target:

    127.0.0.1

This restriction keeps the laboratory implementation focused on controlled, authorized testing.

---

## Objectives

- Discover TCP ports accepting connections.
- Measure connection latency.
- Map known ports to likely services.
- Perform lightweight application-level service verification.
- Collect service evidence where available.
- Assign basic security exposure levels.
- Build a logical network topology from observed services.
- Generate JSON and plaintext security reports.
- Maintain execution logs.
- Validate generated report structure.
- Provide automated regression tests.

---

## Architecture

    CLI
     │
     ▼
    Configuration
     │
     ▼
    TCP Scanner
     │
     ▼
    Service Intelligence
     │
     ▼
    Evidence Collection
     │
     ▼
    Risk Analysis
     │
     ├──────────────┐
     ▼              ▼
    Topology      Reporting
     │              │
     └──────┬───────┘
            ▼
    Report Validation
            │
            ▼
       JSON + TXT

---

## Project Structure

    day17-network-scanner/
    │
    ├── scanner/
    │   ├── cli.py
    │   ├── config.py
    │   ├── logging_config.py
    │   ├── models.py
    │   ├── scanner.py
    │   ├── services.py
    │   ├── risk.py
    │   ├── topology.py
    │   ├── reporting.py
    │   ├── report_schema.py
    │   └── safety.py
    │
    ├── tests/
    │   ├── test_scanner.py
    │   ├── test_services.py
    │   ├── test_risk.py
    │   ├── test_reporting.py
    │   ├── test_topology.py
    │   └── test_report_schema.py
    │
    ├── input/
    │
    ├── output/
    │   ├── logs/
    │   ├── reports/
    │   └── runs/
    │
    └── README.md

---

## Default Scan Scope

The default laboratory scan checks:

    22/TCP
    80/TCP
    443/TCP
    5432/TCP
    8080/TCP

The default target is:

    127.0.0.1

The scanner validates target and port configuration before execution.

---

## Service Intelligence

Known ports are mapped to likely services and categories.

Example:

    22    SSH         REMOTE_ADMINISTRATION
    80    HTTP        WEB
    443   HTTPS       WEB
    5432  PostgreSQL  DATABASE
    8080  HTTP-ALT    WEB

When an HTTP service is reachable, the scanner performs a lightweight HTTP probe.

Example evidence:

    HTTP/1.1 200 OK

Evidence-based detection increases confidence compared with relying only on port numbers.

---

## Risk Analysis

The scanner evaluates exposed services using a basic security exposure model.

Current laboratory output:

    CRITICAL : 0
    HIGH     : 0
    MEDIUM   : 0
    LOW      : 1

The observed low-risk finding was:

    80/TCP — HTTP web service exposed

Risk output is intended for defensive assessment and prioritization rather than vulnerability exploitation.

---

## Topology

The scanner converts confirmed open services into a logical topology representation.

Example:

    localhost
       │
       └── TCP/80
            ├── HTTP
            ├── OPEN
            └── LOW

Closed ports are not represented as exposed topology edges.

---

## Reporting

Each scan produces:

    output/reports/day17_scan.json
    output/reports/day17_scan.txt

The JSON report contains structured information including:

- Run metadata
- Target information
- Port scan results
- Service intelligence
- Security findings
- Risk summary
- Network topology

Reports are validated against the project's required schema before being written.

---

## Logging

Execution logs are stored under:

    output/logs/day17_scanner.log

Verbose execution provides additional diagnostic information for individual port checks.

---

## Testing

The project uses automated regression tests.

Current test status:

    16 passed

Run:

    pytest -q

---

## Example Usage

Run the default laboratory scan:

    python -m scanner.cli

Enable verbose logging:

    python -m scanner.cli --verbose

Specify ports:

    python -m scanner.cli --ports 22 80 443

Change the connection timeout:

    python -m scanner.cli --timeout 2

Invalid configuration is rejected before scanning.

---

## Security Scope

This project is intended for:

- Local security laboratories
- Authorized development environments
- Educational cybersecurity exercises
- Defensive network exposure assessment

Only scan systems and networks for which explicit authorization has been obtained.

---

## Day 17 Result

The laboratory successfully identified an HTTP service listening on TCP/80 and verified it using application-level evidence.

Final automated test status:

    16 passed

Day 17 demonstrates the progression from basic socket connectivity testing to structured security assessment, service intelligence, risk analysis, topology modeling, and validated reporting.