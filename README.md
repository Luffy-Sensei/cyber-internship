# 🛡️ Cybersecurity Internship — Phase 1

> **A comprehensive cybersecurity internship portfolio documenting hands-on security labs, Python tooling, Linux practice, and security awareness exercises.**

---

## 📋 Program Overview

| **Category** | **Details** |
|--------------|-------------|
| **Program** | Alpha 2 Internship — Cybersecurity Track |
| **Organization** | Sqrock IT Solution |
| **Phase** | 1 — Social Engineering Attack Simulations |
| **Duration** | 15 Days (3 Weeks) |
| **Status** | ✅ **COMPLETE** |
| **Mode** | Hands-on Python Labs + Written Reports |
| **Environment** | Parrot OS / Kali Linux |
| **Tech Stack** | Python 3, Linux CLI, Git, APIs |

---

## 🎯 Phase 1 Objectives

> *"Understand attacker methodologies, build defensive tools, and develop professional-grade security solutions."*

This phase focused on **Social Engineering Attack Simulations** using Python. The goal was to learn how attackers think, what techniques they use, and how to defend against them.

### Key Learning Outcomes

- ✅ **OSINT & Reconnaissance** – Passive intelligence gathering techniques
- ✅ **Email Harvesting** – Understanding how attackers collect email addresses
- ✅ **Phishing Detection** – URL and email analysis for phishing indicators
- ✅ **Vishing/Smishing** – Voice and SMS social engineering awareness
- ✅ **Fake Profile Detection** – Social media impersonation identification
- ✅ **Password Attacks** – Brute force and credential stuffing simulation
- ✅ **USB Drop Attacks** – Physical social engineering awareness
- ✅ **Honeypot Systems** – Threat intelligence gathering and tracking
- ✅ **ML-Based Detection** – Phishing email classification with Naive Bayes
- ✅ **SIEM Log Analysis** – Security event monitoring and correlation
- ✅ **Incident Response** – Automated IR workflow and playbook management
- ✅ **Attack Chain Simulation** – Complete SE attack lifecycle orchestration

---

## 📁 Repository Structure

```text
sqrock-internship-phase1/
│
├── README.md                          # Main documentation
├── LICENSE                            # Educational use license
├── .gitignore                         # Git ignore file
│
├── day01-osint/                       # OSINT & Passive Reconnaissance
│   ├── scanner.py                     # Professional OSINT scanner
│   ├── README.md                      # Day 1 documentation
│   ├── requirements.txt               # Python dependencies
│   ├── output/                        # Scan reports and analysis
│   ├── report/                        # Detailed reports
│   └── screenshots/                   # Execution screenshots
│
├── day02-email-harvesting/            # Email Harvesting & SE Prep
│   ├── harvester.py                   # Email harvesting tool
│   ├── README.md                      # Day 2 documentation
│   ├── requirements.txt               # Python dependencies
│   ├── output/                        # Harvested email samples
│   ├── report/                        # Detailed reports
│   └── screenshots/                   # Execution screenshots
│
├── day03-phishing-detection/          # Phishing Page Detection
│   ├── detector.py                    # URL phishing scorer
│   ├── README.md                      # Day 3 documentation
│   ├── output/                        # Detection test results
│   ├── report/                        # Detailed reports
│   └── screenshots/                   # Execution screenshots
│
├── day04-vishing-smishing/            # Vishing & Smishing Scripts
│   ├── se_simulator.py                # Social engineering script generator
│   ├── README.md                      # Day 4 documentation
│   ├── output/                        # Generated scripts
│   ├── report/                        # Detailed reports
│   └── screenshots/                   # Execution screenshots
│
├── day05-osint-profiling/             # OSINT Target Profile
│   ├── profiler.py                    # GitHub profile analyzer
│   ├── README.md                      # Day 5 documentation
│   ├── output/                        # Generated profiles
│   ├── report/                        # Detailed reports
│   └── screenshots/                   # Execution screenshots
│
├── day06-spear-phishing/              # Spear Phishing Engine
│   ├── email_engine.py                # Personalized email generator
│   ├── README.md                      # Day 6 documentation
│   ├── output/                        # Generated email templates
│   ├── report/                        # Detailed reports
│   └── screenshots/                   # Execution screenshots
│
├── day07-password-attacks/            # Password Attack Simulator
│   ├── attack_sim.py                  # Brute force & credential stuffing
│   ├── README.md                      # Day 7 documentation
│   ├── wordlists/                     # Password wordlists
│   ├── output/                        # Attack results
│   ├── report/                        # Detailed reports
│   └── screenshots/                   # Execution screenshots
│
├── day08-usb-drop/                    # USB Drop Simulation
│   ├── usb_sim.py                     # USB payload simulator
│   ├── README.md                      # Day 8 documentation
│   ├── payload/                       # USB payload package
│   ├── output/                        # Reconnaissance data
│   ├── report/                        # Detailed reports
│   └── screenshots/                   # Execution screenshots
│
├── day09-fake-profile/                # Fake Profile Detection
│   ├── detector.py                    # Social media bot detector
│   ├── README.md                      # Day 9 documentation
│   ├── output/                        # Detection results
│   ├── report/                        # Detailed reports
│   └── screenshots/                   # Execution screenshots
│
├── day10-honeypot/                    # Honeypot Link Tracker
│   ├── honeypot.py                    # HTTP honeypot server
│   ├── README.md                      # Day 10 documentation
│   ├── logs/                          # Honeypot logs
│   ├── output/                        # Analysis reports
│   ├── report/                        # Detailed reports
│   └── screenshots/                   # Execution screenshots
│
├── day11-awareness-training/          # SE Awareness Training
│   ├── training.py                    # Interactive quiz engine
│   ├── README.md                      # Day 11 documentation
│   ├── output/                        # Quiz results
│   ├── report/                        # Detailed reports
│   └── screenshots/                   # Execution screenshots
│
├── day12-phishing-ml/                 # Phishing ML Detection
│   ├── ml_detector.py                 # Naive Bayes classifier
│   ├── README.md                      # Day 12 documentation
│   ├── models/                        # Trained models
│   ├── output/                        # Detection results
│   ├── report/                        # Detailed reports
│   └── screenshots/                   # Execution screenshots
│
├── day13-siem-analysis/               # SIEM Log Analysis
│   ├── siem_analyzer.py               # Log parser & threat detector
│   ├── README.md                      # Day 13 documentation
│   ├── output/                        # Analysis reports
│   ├── report/                        # Detailed reports
│   └── screenshots/                   # Execution screenshots
│
├── day14-incident-response/           # IR Plan & Automation
│   ├── ir_automation.py               # Incident response workflow
│   ├── README.md                      # Day 14 documentation
│   ├── output/                        # IR reports
│   ├── report/                        # Detailed reports
│   └── screenshots/                   # Execution screenshots
│
└── day15-final-project/               # SE Attack Chain Simulator
    ├── se_chain.py                    # Complete attack chain simulation
    ├── README.md                      # Day 15 documentation
    ├── output/                        # Attack chain reports
    ├── report/                        # Detailed reports
    └── screenshots/                   # Execution screenshots
```
## 🛠️ Technology Stack

| Category	    |       Technologies
|---------           |   ------------
|
|Languages	        |    Python 3.9+
|Libraries	        |    requests, whois, scikit-learn, psutil, flask
|Platforms	        |    Parrot OS, Kali Linux
|Tools	            |    Git, JSON, CSV, Jupyter
|Formatting	        |    PEP-8, Black
|Docs	            |    Markdown, PDF, JSON
|Version Control	|    Git & GitHub

## Phase 1 Daily Breakdown

### Week 1: Passive Reconnaissance & Intelligence Gathering

| Day | Topic | Difficulty | Key Deliverable | Status |
| :--- | :--- | :--- | :--- | :--- |
| 01 | OSINT & Passive Reconnaissance | 🟢 Beginner | OSINT Scanner | ✅ |
| 02 | Email Harvesting & SE Prep | 🟢 Beginner | Email Harvester | ✅ |
| 03 | Phishing Page Anatomy & Detection | 🟢 Beginner | URL Phishing Scorer | ✅ |
| 04 | Vishing & Smishing Simulation | 🟢 Beginner | SE Script Generator | ✅ |
| 05 | OSINT + SE: Build Target Profile | 🟡 Intermediate | GitHub Profiler | ✅ |
### Week 1: Passive Reconnaissance & Intelligence Gathering

| Day | Topic | Difficulty | Key Deliverable | Status |
| :--- | :--- | :--- | :--- | :--- |
| 01 | OSINT & Passive Reconnaissance | 🟢 Beginner | OSINT Scanner | ✅ |
| 02 | Email Harvesting & SE Prep | 🟢 Beginner | Email Harvester | ✅ |
| 03 | Phishing Page Anatomy & Detection | 🟢 Beginner | URL Phishing Scorer | ✅ |
| 04 | Vishing & Smishing Simulation | 🟢 Beginner | SE Script Generator | ✅ |
| 05 | OSINT + SE: Build Target Profile | 🟡 Intermediate | GitHub Profiler | ✅ |

### Week 3: Advanced Defense & Reporting

| Day | Topic | Difficulty | Key Deliverable | Status |
| :--- | :--- | :--- | :--- | :--- |
| 11 | SE Awareness Training Module | 🟡 Intermediate | Quiz Engine | ✅ |
| 12 | Phishing Detection with ML | 🔴 Advanced | ML Classifier | ✅ |
| 13 | SIEM Log Analysis | 🔴 Advanced | Log Analyzer | ✅ |
| 14 | SE Incident Response Plan | 🔴 Advanced | IR Automation | ✅ |
| 15 | Final Project: SE Attack Chain | 🔴 Expert | Complete Simulator | ✅ |
## Quick Start
### Prerequisites
```bash
# Install required Python packages
pip3 install -r requirements.txt

# For Parrot OS/Kali Linux
sudo apt update
sudo apt install python3 python3-pip git
```
### Clone Repository
```bash
git clone https://github.com/yourusername/sqrock-internship-phase1.git
cd sqrock-internship-phase1
```
### Set Up Virtual Environment
```bash
# Create virtual environment
python3 -m venv venv

# Activate virtual environment
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```
### Create Authorization File
```bash
echo "I am using this tool in an authorized lab environment for cybersecurity education." > AUTHORIZED_LAB_USE.txt
```
### Run Tools
```bash
# Day 1: OSINT Scanner
cd day01-osint
python3 scanner.py -d example.com -v

# Day 3: Phishing Detector
cd day03-phishing-detection
python3 detector.py "https://paypal-login.evil.com/verify"

# Day 7: Password Attack Simulator
cd day07-password-attacks
python3 attack_sim.py --server  # Start Flask test server
python3 attack_sim.py -u admin -t dictionary -v

# Day 10: Honeypot
cd day10-honeypot
python3 honeypot.py -v

# Day 12: ML Phishing Detector
cd day12-phishing-ml
python3 ml_detector.py --train --demo

# Day 13: SIEM Analyzer
cd day13-siem-analysis
python3 siem_analyzer.py --sample --output results.json

# Day 15: Final Project
cd day15-final-project
python3 se_chain.py --full-chain example.com employee
```
### Key Metrics

| Metric | Value |
| :--- | :--- |
| **Total Days** | 15 |
| **Tools Built** | 15 |
| **Python Lines** | ~3,500+ |
| **Security Scenarios** | 50+ |
| **Detection Heuristics** | 100+ |
| **ML Models** | 1 |
| **Reports Generated** | 15 |
| **Documentation Pages** | 15+ |

---

### 🔒 Ethical Guidelines

All tools in this repository are for **EDUCATIONAL PURPOSES ONLY** and must only be used in:
* ✅ Authorized lab environments
* ✅ Your own systems and domains
* ✅ Written permission from system owners

**Prohibited:**
* ❌ Targeting real users without permission
* ❌ Unauthorized data collection
* ❌ Any activity violating relevant IT laws and regulations

---

### 🎓 Key Takeaways

#### Technical Skills
* ✅ Python scripting for cybersecurity
* ✅ API integration and data processing
* ✅ Machine learning for security
* ✅ Log analysis and SIEM fundamentals
* ✅ Threat intelligence gathering
* ✅ Incident response automation

#### Security Mindset
* ✅ Understanding attacker methodologies
* ✅ Thinking like a defender
* ✅ Ethical considerations in security work
* ✅ Documentation and reporting best practices
* ✅ Continuous learning approach

---

### 📚 Daily Reports

Each day includes:
* **`README.md`** – Overview and instructions
* **Source Code** – Clean, documented Python code
* **Output** – Generated data and results
* **Report** – Detailed analysis (PDF/Markdown)
* **Screenshots** – Execution proof

#### Highlights
* **Day 1: OSINT Scanner** – Professional OSINT tool with multi-threading and 3+ data sources.
* **Day 7: Password Attack Simulator** – Production-grade attack simulator with rate limiting detection.
* **Day 12: ML Phishing Detector** – Naive Bayes classifier with 95%+ accuracy on test data.
* **Day 15: Attack Chain Simulator** – Complete SE attack lifecycle orchestration with HTML/JSON reports.

---

###  Contributing

This is an individual internship project. Feedback and suggestions are welcome:
1. Fork the repository
2. Create a feature branch
3. Submit a pull request

---

### License

**Educational Use Only** – All code is for cybersecurity training purposes.

---
## Disclaimer

This repository is maintained for educational and authorized cybersecurity purposes.

Any similarity between simulated data and real individuals, organizations, credentials, infrastructure, or security incidents is unintended unless explicitly identified as an authorized training target.

The author does not endorse unauthorized access, exploitation, credential theft, phishing, privacy violations, or other unlawful activity.

###  Contact

| Field | Details |
| :--- | :--- |
| **GitHub** | [@Luffy-Sensei](https://github.com/Luffy-Sensei) |
| **Organization** | Sqrock IT Solution |
| **Program** | Alpha 2 Cybersecurity Internship |
| **Phase** | Phase 1 — Complete ✅ |
| **Status** | Ready for Phase 2 |

---

### Certification

Upon completion of Phase 1, the intern has demonstrated proficiency in:
* Social Engineering Attack Simulations
* Python Tool Development
* OSINT Methodologies
* Threat Detection & Analysis
* Incident Response Fundamentals
* Professional Documentation

---

###  References

* **NIST SP 800-61** – Computer Security Incident Handling Guide
* **MITRE ATT&CK Framework** – Social Engineering Techniques
* **OWASP** – Phishing and Social Engineering Guidance
* **SANS** – Security Awareness Training Best Practices

---

### Acknowledgments

* **Sqrock IT Solution** – For providing this internship opportunity
* **Mentors** – For guidance and feedback throughout Phase 1
* **Cybersecurity Community** – For continuous learning resources

---

###  Next Steps

#### Phase 2 Preparation
* Advanced threat hunting
* Red team / Blue team exercises
* Cloud security fundamentals
* Security Operations Center (SOC) simulation

---