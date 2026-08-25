# Day 16 — HTTP Security Header Analysis

## Overview

Day 16 of Phase 2 focuses on HTTP security header analysis and browser-enforced security policies.

The lab was conducted entirely within an authorized localhost environment on Parrot OS. The objective was to:

- Inspect HTTP response headers.
- Identify missing security controls.
- Configure important HTTP security headers.
- Re-run the audit to verify remediation.
- Demonstrate Content Security Policy (CSP) enforcement.
- Analyze how CSP restricts unauthorized JavaScript sources.

## Objectives

The following HTTP security headers were analyzed:

- `Strict-Transport-Security`
- `Content-Security-Policy`
- `X-Frame-Options`
- `X-Content-Type-Options`

The primary analytical focus was CSP and its ability to restrict unauthorized script sources.

## Lab Environment

| Component | Configuration |
|---|---|
| Operating System | Parrot OS |
| Python | CPython 3.13.5 |
| Python Environment | `.venv` |
| Main Application | `127.0.0.1:8000` |
| CSP Test Server | `127.0.0.1:9000` |
| HTTP Client | `curl` |
| Security Auditor | Python `requests` |
| Browser Testing | Firefox/Chromium-based browser |

All testing was performed against locally controlled services.

## Project Structure

```text
day16-http-security-headers/
├── app/
│   ├── external/
│   ├── external_server.py
│   ├── server.py
│   └── static/
│       └── allowed.js
├── output/
│   ├── baseline-audit.txt
│   ├── head-response.txt
│   ├── secured-audit.txt
│   └── secured-response.txt
├── report/
│   └── day16-report.md
├── requirements.txt
├── scanner/
│   └── header_audit.py
└── screenshots/
    ├── csp-blocked-external-script.png
    └── csp-same-origin-allowed.png
```
## Security Header Analysis
### Strict-Transport-Security

HSTS instructs compatible browsers to use HTTPS for the protected host for a specified period.

Example:
```http
Strict-Transport-Security: max-age=31536000
```
In a production deployment, HSTS should be evaluated in conjunction with a correctly configured HTTPS/TLS deployment. The localhost lab demonstrates the header mechanism but is not a production TLS deployment.

### Content-Security-Policy

CSP defines which sources a browser is permitted to use for resources such as JavaScript, stylesheets, images, and other content.

The lab used:
```http
Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'
```
The important directive for the experiment was:
```text
script-src 'self'
```
This allows scripts from the application's own origin while rejecting scripts from unauthorized origins.

### X-Frame-Options

The lab configured:
```text
X-Frame-Options: DENY
```
This prevents the application from being rendered inside a frame, providing protection against clickjacking scenarios.

### X-Content-Type-Options

The lab configured:
```text
X-Content-Type-Options: nosniff
```
This instructs the browser not to MIME-sniff responses and to respect the declared content type.

### Baseline

The initial HTTP security header audit found all four target headers missing.

The baseline evidence is stored in:
```text
output/baseline-audit.txt
```
## Remediation

The application was modified to return the four security headers.

The resulting configuration was verified through:
```text
curl
Python requests
```
The secured audit is stored in:
```text
output/secured-audit.txt
```
The direct HTTP response is stored in:
```text
output/secured-response.txt
```
HEAD request verification is stored in:
```text
output/head-response.tx
```
## CSP Experiment

The CSP experiment used two local origins:
```text
http://127.0.0.1:8000
http://127.0.0.1:9000
```
The main application used:
```text
script-src 'self'
```
A same-origin JavaScript file was loaded from:
```text
http://127.0.0.1:8000/static/allowed.js
```
This script was permitted by the CSP policy.

A second JavaScript resource was hosted at:
```text
http://127.0.0.1:9000/external.js
```
Because port 9000 represents a different origin from port 8000, it was not authorized by:
```text
script-src 'self'
```
The browser therefore blocked the external script and reported a CSP violation.

Evidence is stored in:
```text
screenshots/csp-same-origin-allowed.png
screenshots/csp-blocked-external-script.png
```
## Key Finding

The experiment demonstrated that CSP is actively enforced by the browser rather than merely being a passive HTTP metadata field.

The application successfully loaded its same-origin script while the cross-origin script was blocked because it violated:
```text
script-src 'self'
```
This demonstrates how CSP can restrict unauthorized script-loading vectors and provide defense in depth against certain XSS scenarios.

## Limitations

This lab is intentionally local and educational.

Important limitations include:

- The application is a minimal Python HTTP server.
- No production TLS configuration was implemented.
- HSTS was demonstrated as a response header but should be evaluated with HTTPS in a real deployment.
- CSP does not replace secure input handling, output encoding, or other XSS prevention mechanisms.
- The Python scanner checks whether headers exist but does not perform a complete policy-quality assessment.
## Conclusion

Day 16 successfully demonstrated HTTP security header identification, remediation, automated verification, and browser-level CSP enforcement.

The lab followed the security assessment workflow:
```text
Identify
   ↓
Analyze
   ↓
Remediate
   ↓
Verify
   ↓
Document
```
All testing was performed against an authorized local environment.