# Day 10 Report — Baiting & Watering Hole Attack Simulation

**Internship:** Sqrock Cybersecurity Internship  
**Phase:** Phase 1  
**Day:** 10  
**Topic:** Baiting & Watering Hole Attack Simulation  
**Date:** 21 August 2026  
**Environment:** Parrot OS VM  
**Target:** Localhost (`127.0.0.1`)  
**Status:** Completed

---

## 1. Objective

The objective of Day 10 was to understand the concepts behind baiting and watering-hole attacks and implement a controlled Python honeypot capable of detecting and logging interaction with simulated bait links.

The lab was designed as a defensive awareness exercise.

No real external website or target was contacted or compromised.

---

## 2. Theory

### Baiting

Baiting is a social-engineering technique where an attacker presents an attractive resource to encourage a victim to interact with it.

Examples include:

- Free software
- Fake software updates
- Important documents
- Free downloads
- Other attractive files or resources

The interaction may eventually be used as an entry point for further malicious activity.

### Watering Hole

A watering-hole attack targets a website or online resource that a particular group is likely to visit.

Instead of directly targeting the victim, the attacker attempts to place malicious content where the intended victims are expected to browse.

For this lab, no real website was compromised.

A local HTTP honeypot was used to simulate the detection side of the scenario.

---

## 3. Lab Design

The lab consisted of:

```text
Test Client
     |
     | HTTP request
     v
127.0.0.1:8080
     |
     v
Honeypot Tracker
     |
     +--> Compare requested path
     |
     +--> Identify bait interaction
     |
     +--> Record event
     |
     +--> JSON/TXT reports
The honeypot was bound to the loopback interface:

127.0.0.1

This ensured that the experiment remained local to the test environment.

4. Project Structure
day10-baiting-watering-hole/
├── honeypot_tracker.py
├── input/
│   └── bait_links.json
├── output/
│   ├── honeypot_events.json
│   └── honeypot_events.txt
├── README.md
├── report/
│   └── day10-report.md
├── requirements.txt
└── screenshots/
    └── honeypot-server-events.png
5. Configured Bait Paths

The simulator used the following local bait paths:

/free-download
/important-document
/software-update
/bait

These paths were only simulated routes.

They did not provide real malicious files, malware, credentials, or external resources.

6. Logging Mechanism

For every HTTP GET request, the honeypot records:

timestamp
IP address
HTTP method
requested path
User-Agent
bait_triggered

The bait_triggered field indicates whether the requested path matched one of the configured bait paths.

7. Testing Procedure

The honeypot was started locally and tested using curl.

A normal request was first generated:

curl http://127.0.0.1:8080/

Bait paths were then requested:

curl http://127.0.0.1:8080/free-download
curl http://127.0.0.1:8080/software-update
curl http://127.0.0.1:8080/bait

The resulting requests were recorded by the honeypot.

8. Results

The test generated four logged events.

Event	HTTP Method	Path	IP	Bait Triggered
1	GET	/	127.0.0.1	False
2	GET	/free-download	127.0.0.1	True
3	GET	/software-update	127.0.0.1	True
4	GET	/bait	127.0.0.1	True
Summary
Total HTTP events:       4
Normal requests:         1
Bait interactions:       3
Source address:          127.0.0.1

The honeypot successfully distinguished normal traffic from requests to configured bait paths.

9. Evidence
Screenshot — Honeypot Server Events
screenshots/honeypot-server-events.png

The screenshot provides visual evidence of the local honeypot execution and captured request events.

JSON Evidence
output/honeypot_events.json

The JSON report contains the structured event records.

Text Evidence
output/honeypot_events.txt

The text report provides a human-readable representation of the same events.

10. Security Analysis

The exercise demonstrates how a defender could use a controlled honeypot to identify interaction with suspicious resources.

Useful information captured during the simulation includes:

Timestamp

Helps establish when the interaction occurred.

Source IP

Identifies the network source of the request.

In this controlled lab, the source was:

127.0.0.1
Requested Path

Shows which resource was requested and whether it matched a bait indicator.

User-Agent

Provides basic information about the client software generating the request.

Bait Trigger

Provides a simple detection indicator that separates ordinary requests from interaction with configured bait resources.

11. Defensive Controls

Organizations can reduce the risk associated with baiting and watering-hole attacks through:

Web filtering
Endpoint protection
Browser security controls
Script blocking
Patch management
DNS filtering
Security monitoring
User awareness training
Network traffic analysis
Deception/honeypot technologies

Users should also verify unexpected downloads, software updates, and links before interacting with them.

12. Limitations

This simulator is intentionally simple.

It does not:

Detect real malicious websites
Identify actual attackers
Perform malware analysis
Exploit browsers
Deliver drive-by downloads
Collect credentials
Track users across external websites
Determine whether a real-world user is malicious

A bait_triggered result only means that the requested local path matched a configured bait path.

It does not prove malicious intent.

13. Ethical Considerations

All testing was conducted locally against:

127.0.0.1

The experiment did not target third-party systems.

No malware or exploit payload was deployed.

The purpose of the project was to demonstrate defensive monitoring and security awareness.

14. Learning Outcomes

After completing Day 10, the following concepts were demonstrated:

Understanding of baiting attacks
Understanding of watering-hole attacks
Understanding of deceptive links
Building a basic HTTP honeypot
Capturing HTTP request metadata
Detecting configured bait paths
Generating structured JSON logs
Generating human-readable logs
Using localhost for safe security experimentation
Understanding the defensive role of honeypots
15. Conclusion

The Day 10 Baiting & Watering Hole Attack Simulation was successfully completed.

The Python honeypot successfully monitored local HTTP requests and identified interactions with configured bait paths.

The final test produced four events, including three successful bait-path detections.

The lab demonstrates how a simple deception system can provide useful visibility into suspicious resource interaction while maintaining a safe and controlled testing environment.

Day 10 Status: COMPLETE
