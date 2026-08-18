# Day 07 — Password Attacks & Credential Stuffing

## Overview

Day 07 focuses on understanding password-attack techniques and defensive authentication controls through a controlled local laboratory.

The lab contains:

- A local Flask authentication server
- A Python authentication-attempt simulator
- A configurable candidate-password wordlist
- Rate-limit detection
- Controlled request delays
- JSON and text evidence reports
- Defensive observations based on observed server behavior

All authentication testing in this project is performed against:

`http://127.0.0.1:5000/login`

No external systems are targeted.

---

## Objectives

The objectives of Day 07 are to:

1. Understand brute-force authentication logic.
2. Understand the difference between brute force, dictionary attacks, and credential stuffing.
3. Simulate controlled authentication attempts against a local Flask application.
4. Detect HTTP `429 Too Many Requests` responses.
5. Measure when the authentication rate limit is triggered.
6. Record authentication results as structured evidence.
7. Understand defensive controls such as rate limiting, lockout, MFA, and CAPTCHA.

---

## Concepts

### Brute Force

A brute-force attack systematically attempts possible passwords until a valid credential is discovered.

### Dictionary Attack

A dictionary attack uses a predefined list of likely passwords instead of generating every possible combination.

This lab uses a small controlled candidate list.

### Credential Stuffing

Credential stuffing involves testing previously leaked username/password combinations against other services.

This project does **not** perform credential stuffing against external services. The concept is studied only for defensive understanding.

### Rate Limiting

Rate limiting restricts how frequently authentication attempts can be made.

The local lab is configured with:

- Maximum failed attempts: `5`
- Observation window: `30 seconds`
- Lockout/rate-limit period: `30 seconds`

When the threshold is reached, the server returns HTTP `429`.

---

## Lab Architecture

```text
                 Localhost Only
                       │
                       ▼
┌──────────────────────────────────────┐
│       Flask Authentication Lab       │
│                                      │
│  http://127.0.0.1:5000/login         │
│                                      │
│  User: admin                         │
│  Rate limit: 5 failed attempts       │
│  Window: 30 seconds                  │
│  Lockout: 30 seconds                 │
└──────────────────┬───────────────────┘
                   │
                   │ HTTP POST
                   ▼
┌──────────────────────────────────────┐
│     Authentication Simulator         │
│                                      │
│  Candidate passwords                 │
│  Configurable delay                  │
│  Authentication result detection     │
│  HTTP 429 detection                  │
└──────────────────┬───────────────────┘
                   │
                   ▼
        JSON / Text Evidence

Project Structure
day07-password-attacks/
├── app.py
├── brute_force_simulator.py
├── requirements.txt
├── input/
│   └── ...
├── output/
│   ├── bruteforce_results.json
│   └── bruteforce_results.txt
├── screenshots/
│   ├── flask-server.png
│   ├── authentication-success.png
│   ├── rate-limit-evidence.png
│   ├── simulator-rate-limit.png
│   └── json-report.png
└── report/
    └── day07-report.md
Requirements
Python 3
Flask
Requests

Install dependencies inside the project virtual environment:

pip install -r requirements.txt
Running the Flask Lab

Start the local authentication server:

python3 app.py

The server runs at:

http://127.0.0.1:5000

The login endpoint is:

http://127.0.0.1:5000/login

The lab credentials are intentionally limited to the local training environment.

Testing the Authentication Endpoint

A single failed authentication attempt can be tested with:

curl -i -X POST \
-d "username=admin&password=wrong" \
http://127.0.0.1:5000/login

A successful authentication test uses the lab credential configured in app.py.

Running the Authentication Simulator

Run the normal authentication simulation:

python3 brute_force_simulator.py admin --mode auth

The simulator:

Loads the candidate password list.
Sends authentication requests to the local Flask server.
Classifies each response.
Stops when authentication succeeds or rate limiting is detected.
Saves JSON and text evidence.
Running the Rate-Limit Test

Use the dedicated rate-limit wordlist:

python3 brute_force_simulator.py admin \
--mode rate-limit \
--wordlist rate_limit_wordlist.txt \
--delay 0.1

The expected defensive behavior is:

Attempt 1 → HTTP 401
Attempt 2 → HTTP 401
Attempt 3 → HTTP 401
Attempt 4 → HTTP 401
Attempt 5 → HTTP 429

The simulator should report:

Rate-Limited Attempts: 1
Rate Limit Detected: True
Trigger Attempt: 5
HTTP Status: 429
Retry After: 30 seconds
Command-Line Options

The simulator supports configurable testing parameters.

Example:

python3 brute_force_simulator.py admin \
--mode rate-limit \
--wordlist rate_limit_wordlist.txt \
--delay 0.1

Important options include:

Option	Purpose
username	Lab username to test
--mode	Select authentication or rate-limit simulation
--wordlist	Supply a candidate-password file
--delay	Add a controlled delay between attempts
--url	Specify the local authentication endpoint

The URL should point to the authorized local laboratory.

Evidence Generated

The simulator generates:

JSON
output/bruteforce_results.json

The JSON report records:

Simulation metadata
Target endpoint
Username
Candidate count
Attempt results
HTTP status codes
Authentication outcomes
Rate-limit events
Retry information
Defensive observations
Text
output/bruteforce_results.txt

The text report provides a human-readable summary of the simulation.

Observed Results

The authentication simulation demonstrated:

Failed authentication attempts returning HTTP 401
Successful authentication returning HTTP 200
Rate limiting returning HTTP 429
The server providing retry information
The simulator correctly identifying the rate-limit condition

The rate-limit test triggered the defensive control on attempt 5.

Observed response:

HTTP 429 Too Many Requests
Retry After: 30 seconds
Defensive Lessons

The lab demonstrates why authentication systems should implement multiple defensive controls.

Rate Limiting

Limits repeated authentication attempts and reduces password-guessing effectiveness.

Account Lockout

Temporarily prevents further authentication attempts after repeated failures.

Multi-Factor Authentication

Provides an additional authentication factor even if a password is compromised.

CAPTCHA

Can increase the cost of automated authentication attempts.

Breach Monitoring

Organizations can monitor for exposed credentials and force password resets when necessary.

Strong Password Policies

Long, unique passwords reduce the effectiveness of dictionary-based guessing.

Ethical Scope

This project is a local security-awareness and defensive testing laboratory.

Testing is restricted to:

127.0.0.1
localhost

Do not use this simulator against systems, accounts, websites, APIs, or infrastructure without explicit authorization.

The purpose of the project is to understand authentication security and demonstrate defensive rate-limiting behavior.

Learning Outcome

After completing Day 07, the learner should understand:

How password-guessing simulations work
How authentication responses can be classified
How rate limits affect automated attempts
How HTTP 429 can indicate throttling
Why authentication controls should be layered
How to collect reproducible security-testing evidence
Status

Day 07 — Complete

Implemented and tested:

Local Flask authentication lab
Authentication-attempt simulator
Candidate wordlist support
Controlled request delay
Authentication result classification
Rate-limit detection
HTTP 429 evidence collection
JSON reporting
Text reporting
