# Day 17 — Local Network Port & Service Scanning Report

## 1. Executive Summary

Day 17 implemented a controlled TCP port and service scanning capability for local security assessment.

The scanner evaluated selected TCP ports on the authorized loopback target `127.0.0.1`, identified reachable services, performed lightweight service verification, assessed security exposure, generated a logical topology, and produced structured JSON and plaintext reports.

The assessment completed successfully with all automated tests passing.

---

## 2. Assessment Scope

**Target**

    127.0.0.1

**Ports**

    22/TCP
    80/TCP
    443/TCP
    5432/TCP
    8080/TCP

**Connection Timeout**

    1.0 seconds

**Assessment Type**

    Controlled local TCP service exposure assessment

---

## 3. Port Results

| Port | State | Service | Category |
|---:|---|---|---|
| 22 | CLOSED | SSH | REMOTE_ADMINISTRATION |
| 80 | OPEN | HTTP | WEB |
| 443 | CLOSED | HTTPS | WEB |
| 5432 | CLOSED | PostgreSQL | DATABASE |
| 8080 | CLOSED | HTTP-ALT | WEB |

---

## 4. Service Intelligence

TCP/80 was identified as HTTP.

The scanner performed an application-level HTTP probe and received:

    HTTP/1.1 200 OK

Detection method:

    HTTP_PROBE

Confidence:

    HIGH

This provides stronger evidence than identifying the service solely from its port number.

---

## 5. Security Findings

### LOW — TCP/80 HTTP Exposure

**Service:** HTTP

**Category:** WEB

**Description:**

HTTP is accepting TCP connections on port 80.

**Recommendation:**

Verify that the web service is intentional and apply appropriate application and transport security.

No HIGH or CRITICAL exposure was identified during the assessment.

---

## 6. Risk Summary

    CRITICAL : 0
    HIGH     : 0
    MEDIUM   : 0
    LOW      : 1
    NONE     : 4

Overall observed exposure:

    LOW

---

## 7. Network Topology

The confirmed exposed service can be represented as:

    localhost (127.0.0.1)
           │
           └── TCP/80
                │
                ├── HTTP
                ├── OPEN
                └── LOW RISK

Only confirmed open services are represented as exposed topology edges.

---

## 8. Reporting Artifacts

Generated artifacts:

    output/reports/day17_scan.json
    output/reports/day17_scan.txt

Execution logging:

    output/logs/day17_scanner.log

The JSON report includes a unique `run_id` for execution tracking and contains the generated topology and security assessment data.

---

## 9. Validation

Automated regression testing completed successfully:

    16 passed

The generated report was also validated against the project's required report structure.

---

## 10. Conclusion

The Day 17 laboratory successfully demonstrated controlled TCP port discovery, service classification, application-level verification, security exposure analysis, topology generation, logging, and structured reporting.

The assessment identified one exposed HTTP service on TCP/80 with a LOW security exposure classification.

No HIGH, CRITICAL, or database-service exposure was observed within the configured scan scope.

Day 17 objectives were successfully completed.