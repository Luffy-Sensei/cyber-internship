# Day 07 — Password Attacks & Credential Stuffing

## 1. Objective

The objective of Day 07 was to understand password-attack logic and demonstrate defensive authentication controls through a controlled local Flask laboratory.

The implementation focused on:

- Authentication-attempt simulation
- Dictionary-style password testing
- Rate-limit detection
- HTTP response classification
- Evidence generation
- Defensive authentication controls

All testing was performed against the local laboratory endpoint:

```text
http://127.0.0.1:5000/login
No external systems were targeted.

2. Lab Environment
Authentication Server
Framework: Flask
Host: 127.0.0.1
Port: 5000
Endpoint: /login
Username: admin
Authentication Protection
Maximum failed attempts: 5
Observation window: 30 seconds
Lockout/rate-limit period: 30 seconds
Rate-limit response: HTTP 429
Client
Python
Requests
3. Implementation

The lab consists of two primary components.

Flask Authentication Lab

The Flask application provides a deliberately controlled authentication endpoint.

It returns different responses depending on the authentication state:

200 — successful authentication
401 — invalid credentials
429 — rate limit triggered

The server also exposes information such as the number of failed attempts and remaining attempts before rate limiting.

Authentication Simulator

The Python simulator sends a controlled candidate-password list to the local authentication endpoint.

For every attempt, it records:

Attempt number
Timestamp
HTTP status
Authentication result
Server response
Rate-limit state

The simulator stops when a successful authentication occurs or when the server reports rate limiting.

4. Authentication Simulation

The normal authentication simulation was executed with:

python3 brute_force_simulator.py admin --mode auth

The simulator tested the controlled candidate list.

Observed results:

Total Attempts: 4
Failed Attempts: 3
Successful Attempts: 1
Rate-Limited Attempts: 0
Request Errors: 0
Rate Limit Detected: False

The successful authentication occurred on attempt 4.

This demonstrated that the simulator correctly distinguishes invalid authentication responses from a successful application-level authentication result.

5. Rate-Limit Test

A dedicated rate-limit test was performed using a wordlist containing invalid candidate passwords.

Command:

python3 brute_force_simulator.py admin \
--mode rate-limit \
--wordlist rate_limit_wordlist.txt \
--delay 0.1

The controlled delay was used to make the test reproducible while avoiding unnecessary request bursts.

Observed Sequence
Attempt 1 → HTTP 401
Attempt 2 → HTTP 401
Attempt 3 → HTTP 401
Attempt 4 → HTTP 401
Attempt 5 → HTTP 429

The simulator reported:

Total Attempts: 5
Failed Attempts: 4
Successful Attempts: 0
Rate-Limited Attempts: 1
Request Errors: 0
Rate Limit Detected: True
Rate-Limit Evidence
Trigger Attempt: 5
HTTP Status: 429
Retry After: 30 seconds

This confirms that the local authentication server's rate-limiting control was triggered after the configured number of failed attempts.

6. HTTP Response Analysis
HTTP 401

The server returned HTTP 401 Unauthorized for invalid credentials.

This indicates that the authentication attempt was rejected.

HTTP 200

The server returned HTTP 200 OK when the correct lab credential was supplied.

The simulator additionally checked the application's JSON response to confirm authentication success.

HTTP 429

The server returned HTTP 429 Too Many Requests after the failed-attempt threshold was reached.

The response also supplied retry information.

This provides direct evidence that the rate-limit mechanism was functioning.

7. Evidence Collection

The simulator generated two report formats.

JSON Evidence
output/bruteforce_results.json

The JSON report contains:

Simulation metadata
Target endpoint
Username
Candidate count
Attempt history
HTTP status codes
Authentication results
Rate-limit results
Server responses
Defensive observations
Text Evidence
output/bruteforce_results.txt

The text report provides a concise human-readable summary of the same testing session.

8. Security Observations

The laboratory demonstrated several important authentication-security principles.

Rate Limiting

Repeated failed authentication attempts can be restricted by the server.

This prevents an attacker from making unlimited authentication attempts.

Controlled Delays

Introducing a delay between requests provides controlled testing behavior and avoids unnecessary request bursts against the laboratory.

Application-Level Validation

HTTP status alone should not always be treated as proof of authentication success.

The simulator checks the application's JSON response and the HTTP status together.

Multi-Factor Authentication

MFA provides an additional layer of protection if a password is compromised.

Strong Passwords

Unique and sufficiently strong passwords reduce the effectiveness of dictionary-based password guessing.

9. Defensive Recommendations

The following controls should be considered for production authentication systems:

Implement authentication rate limiting.
Use temporary account lockout or progressive delays where appropriate.
Deploy MFA for sensitive accounts.
Monitor repeated authentication failures.
Alert on suspicious authentication patterns.
Prevent password reuse across services.
Monitor exposed credentials through appropriate breach-monitoring processes.
Avoid revealing unnecessary authentication details in error responses.
10. Ethical Scope

This exercise was performed exclusively against a locally controlled Flask laboratory.

Authorized target:

127.0.0.1

The simulator is intended for cybersecurity education, defensive testing, and security-awareness training.

No external accounts, websites, or infrastructure were tested.

11. Conclusion

Day 07 successfully demonstrated controlled authentication-attempt simulation and defensive rate-limit detection.

The normal authentication test demonstrated successful result classification, while the dedicated rate-limit test demonstrated the expected defensive behavior:

4 failed authentication attempts
        ↓
5th attempt
        ↓
HTTP 429 Too Many Requests
        ↓
30-second retry period

The resulting JSON and text reports provide reproducible evidence of the test.

Day 07 completed successfully.
