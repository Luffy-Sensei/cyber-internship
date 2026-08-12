# Day 03 — Phishing Page Anatomy & Detection

Python-based phishing URL risk-scoring and detection lab.

## Objective

Analyze common phishing indicators and implement a Python-based detector that identifies suspicious URL characteristics.

This project focuses on detection and analysis only. No phishing page was created, deployed, or used against real users.

## Learning Objectives

- Understand common phishing URL characteristics.
- Identify suspicious domain structures.
- Detect brand names used in deceptive subdomains.
- Identify authentication-related keywords.
- Detect unencrypted HTTP connections.
- Detect URLs that use raw IP addresses instead of registered domain names.
- Produce explainable risk scores rather than binary phishing/not-phishing decisions.
- Export structured JSON results for further analysis.

## Lab Environment

- Parrot OS VM
- Python 3
- Python standard library
- JSON
- `jq`

## Detection Methodology

The detector parses supplied URLs and evaluates multiple indicators.

### 1. Transport Security

URLs using HTTP instead of HTTPS receive a risk penalty because the connection is not encrypted.

Example:

    http://example.com

### 2. Authentication Keywords

The detector checks URL paths for keywords commonly associated with authentication or account-related actions, including:

- login
- verify
- secure
- update
- account
- bank

The presence of such a keyword does not prove that a URL is malicious. It is treated as one risk indicator.

### 3. Brand Abuse in Subdomains

The detector checks whether known brand names appear in a subdomain while the registered domain belongs to another entity.

Example:

    https://paypal-login.evil.com/verify

The registered domain is:

    evil.com

while `paypal` appears in the subdomain.

This is treated as a strong brand-abuse indicator.

### 4. Raw IP Addresses

The detector identifies URLs that use an IPv4 address instead of a registered domain.

Example:

    https://192.0.2.10/login

This can be suspicious in phishing contexts because users normally expect legitimate services to be represented by recognizable domain names.

### 5. Explainable Risk Scoring

Each indicator contributes a defined number of points.

The detector produces:

- Risk score
- Risk level
- Indicator count
- Indicator type
- Severity
- Points
- Human-readable reason

The score represents observed URL risk indicators. It does not establish that a URL is definitively malicious.

## Test Cases

The detector was tested against four URLs:

1. A deceptive brand-containing subdomain:
   
       https://paypal-login.evil.com/verify

2. A normal HTTPS domain:

       https://github.com

3. An HTTP URL:

       http://example.com

4. An IPv4-based URL containing an authentication path:

       https://192.0.2.10/login

## Observed Results

| Test Case | Score | Level | Main Indicators |
|---|---:|---|---|
| paypal-login.evil.com/verify | 55 | MEDIUM | Brand abuse, authentication keyword |
| github.com | 0 | LOW | None |
| http://example.com | 25 | LOW | Unencrypted HTTP |
| 192.0.2.10/login | 55 | MEDIUM | Raw IP, authentication keyword |

## Output

The detector generates a structured JSON report:

    output/phishing_scan.json

The report contains:

- Scan metadata
- Original URL
- Domain breakdown
- Risk assessment
- Risk categories
- Individual indicators

## Validation

The detector was executed against all four test cases and successfully generated the structured JSON report.

The JSON output was validated using:

    jq . output/phishing_scan.json

## Ethics & Scope

This project is strictly defensive.

No phishing page was created, hosted, distributed, or used to collect credentials.

The detector analyzes URL characteristics and produces risk indicators for security-awareness and defensive analysis.

## Limitations

This detector is heuristic-based.

A high score does not automatically mean that a URL is malicious, and a low score does not guarantee that a URL is safe.

Attackers can use legitimate-looking domains, compromised websites, URL shorteners, redirects, HTTPS certificates, and other techniques that cannot be reliably identified from URL structure alone.

The tool should therefore be treated as an initial triage mechanism rather than a complete phishing detection system.

## Conclusion

Day 03 demonstrates how phishing-related URL characteristics can be converted into explainable detection indicators.

The completed detector identifies transport-security issues, authentication-related URL paths, deceptive brand usage in subdomains, and raw IP-based URLs while producing structured and auditable risk assessments.

**Day 03 Status: COMPLETE**
