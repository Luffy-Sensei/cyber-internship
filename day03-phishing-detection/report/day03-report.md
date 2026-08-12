# DAY 03 — PHISHING PAGE ANATOMY & DETECTION

## 1. Objective

Develop a Python-based URL phishing risk scorer that identifies suspicious URL characteristics without creating or deploying phishing pages.

## 2. Lab Environment

- Parrot OS VM
- Python 3
- Python standard library
- JSON
- jq

## 3. Detection Methodology

The detector analyzes URL structure and assigns explainable risk points based on observed indicators.

Detection categories include:

- Unencrypted HTTP
- Authentication-related keywords
- Known-brand usage in deceptive subdomains
- Raw IPv4 addresses

Each finding contains a severity level, point value, indicator type, and explanation.

## 4. Test Results

### Test 1 — Brand Abuse

`https://paypal-login.evil.com/verify`

**Risk:** 55/100 — MEDIUM

Indicators:

- 40 points — Known brand `paypal` used in a subdomain while the registered domain is `evil.com`.
- 15 points — Authentication keyword `verify` found in the URL path.

### Test 2 — Normal HTTPS Domain

`https://github.com`

**Risk:** 0/100 — LOW

No indicators were triggered.

### Test 3 — HTTP Connection

`http://example.com`

**Risk:** 25/100 — LOW

Indicator:

- 25 points — URL uses an unencrypted HTTP connection.

### Test 4 — Raw IP Address

`https://192.0.2.10/login`

**Risk:** 55/100 — MEDIUM

Indicators:

- 40 points — URL uses a raw IPv4 address instead of a registered domain name.
- 15 points — Authentication keyword `login` found in the URL path.

## 5. Output

The detector generated:

`output/phishing_scan.json`

The JSON report contains scan metadata, domain breakdown, risk assessment, categorized indicators, severity, points, and explanations.

The output was validated using:

```bash
jq . output/phishing_scan.json
6. Security Analysis

The exercise demonstrates that phishing detection can be approached as an explainable risk-scoring problem rather than a simple binary classification.

Important observations:

A brand name appearing in a subdomain does not mean the registered domain belongs to that brand.
Authentication keywords are useful indicators but are not proof of malicious intent.
HTTP indicates an unencrypted connection but does not independently prove phishing.
Raw IP addresses can be suspicious in authentication URLs but are not inherently malicious.
7. Limitations

The detector is heuristic-based and should be treated as an initial triage mechanism.

A high score does not prove that a URL is malicious, while a low score does not guarantee that a URL is safe.

The detector does not perform full webpage analysis, credential analysis, browser-based inspection, or reputation-based verification.

8. Ethics

No phishing page was created, hosted, distributed, or used to collect credentials.

The project was performed strictly as a defensive security-awareness and detection exercise.

9. Conclusion

Day 03 successfully implemented and validated an explainable phishing URL detection engine.

Day 03 Status: COMPLETE
