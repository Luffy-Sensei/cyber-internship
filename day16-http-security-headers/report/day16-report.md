# Day 16 Report — HTTP Security Header Analysis

## Objective

The objective of Day 16 was to analyze HTTP response security headers, identify missing browser security controls, implement defensive headers, and verify their behavior within an authorized localhost environment. The primary analytical focus was Content Security Policy (CSP) and its role in restricting unauthorized script-loading vectors.

## Methodology

A local Python HTTP server was deployed at `127.0.0.1:8000`. A Python auditing script using the `requests` library inspected four security headers:

- `Strict-Transport-Security`
- `Content-Security-Policy`
- `X-Frame-Options`
- `X-Content-Type-Options`

The initial baseline audit showed all four headers missing. The application was then configured to return security policies for these headers. A second audit verified that all four controls were present.

HTTP behavior was additionally verified using both GET and HEAD requests with `curl`.

## Security Header Findings

**Strict-Transport-Security (HSTS)** instructs browsers to use HTTPS for a host for a defined period. The lab used `max-age=31536000`. In a production environment, HSTS should be deployed only with a correctly configured HTTPS/TLS service.

**Content-Security-Policy (CSP)** defines permitted resource sources and is enforced by the browser. The lab used:

```text
default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'
```
The `script-src 'self'` directive restricts JavaScript execution to the application's own origin unless additional trusted sources are explicitly authorized.

**X-Frame-Options: DENY** prevents the application from being embedded in frames and provides protection against clickjacking.

**X-Content-Type-Options: nosniff** prevents browsers from MIME-sniffing resources and instructs them to respect declared content types.
## CSP Experiment

To demonstrate CSP enforcement, two locally controlled origins were used:
```text
http://127.0.0.1:8000
http://127.0.0.1:9000
```
The application at port `8000` loaded a same-origin JavaScript resource from `/static/allowed.js`. Because this resource originated from the same origin, it satisfied:
```text
script-src 'self'
```
and was permitted to execute.

A second JavaScript resource was served from port `9000`. Although the resource was reachable and returned `HTTP 200 OK`, the browser rejected it because `127.0.0.1:9000`is a different origin from `127.0.0.1:8000`.

The browser explicitly reported that the external script violated:
```text
script-src 'self'
```
This experimentally demonstrates that CSP is an active browser-enforced policy. The browser does not simply check whether the resource exists; it evaluates whether the resource's origin is authorized by the CSP.

## CSP and Cross-Site Script Loading

CSP can reduce the impact of script injection and certain XSS scenarios by limiting the origins from which executable JavaScript may be loaded. If malicious content attempts to load a script from an unauthorized origin, the browser evaluates the request against the declared `script-src` policy and can block execution.

However, CSP is a defense-in-depth mechanism rather than a replacement for secure application development. Input validation, contextual output encoding, safe DOM APIs, secure frameworks, and other XSS prevention techniques remain necessary.

## Results
| Test                           | Result                      |
| ------------------------------ | --------------------------- |
| Baseline security-header audit | Four target headers missing |
| Security-header remediation    | Four headers configured     |
| GET verification               | HTTP 200 OK                 |
| HEAD verification              | HTTP 200 OK                 |
| Same-origin JavaScript         | Allowed                     |
| Cross-origin JavaScript        | Blocked by CSP              |
| Browser CSP enforcement        | Confirmed                   |
## Conclusion

The Day 16 lab successfully demonstrated the complete security-header assessment lifecycle:
```text
Baseline Assessment
        ↓
Security Configuration
        ↓
Automated Verification
        ↓
Browser-Level CSP Testing
        ↓
Evidence Collection
```
The experiment confirmed that CSP can restrict unauthorized script-loading sources through browser enforcement, providing an additional security boundary against certain script-injection and XSS-related attack paths.