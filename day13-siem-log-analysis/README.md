# 🛡️ Sqrock Cybersecurity Internship - Phase 1

## 📋 Program Overview

**Program:** Alpha 2 Internship — Cybersecurity Track  
**Organization:** Sqrock IT Solution  
**Duration:** 15 Days (3 Weeks)  
**Mode:** Hands-on Python Labs + Written Reports  
**Status:** ✅ In Progress  

---

## 🎯 Program Objectives

This internship program focuses on **Social Engineering Attack Simulations** using Python. The goal is to understand attacker methodologies, build defensive tools, and develop professional-grade security solutions.

### Key Learning Areas:
- 🔍 **OSINT & Reconnaissance** – Passive intelligence gathering
- 📧 **Email Harvesting** – Public data collection techniques
- 🎣 **Phishing Detection** – URL and email analysis
- 📞 **Vishing/Smishing** – Voice/SMS social engineering
- 🎭 **Fake Profile Detection** – Social media impersonation
- 🔐 **Password Attacks** – Brute force & credential stuffing
- 🍯 **Honeypot Systems** – Threat intelligence gathering
- 🤖 **ML-Based Detection** – Phishing email classification
- 📊 **SIEM Log Analysis** – Security event monitoring

---

## 🛠️ Technology Stack

| Category | Technologies |
|----------|--------------|
| **Languages** | Python 3.9+ |
| **Libraries** | requests, whois, scikit-learn, psutil, flask |
| **Platforms** | Parrot OS, Kali Linux, Windows |
| **Tools** | Git, JSON, CSV, Jupyter |
| **Formatting** | PEP-8, Black, Flake8 |
| **Docs** | Markdown, PDF, JSON |

---

## 📚 Daily Breakdown

### Week 1: Passive Reconnaissance & Intelligence Gathering

| Day | Topic | Difficulty | Key Deliverable |
|-----|-------|------------|-----------------|
| 01 | OSINT & Passive Reconnaissance | 🟢 Beginner | OSINT Scanner |
| 02 | Email Harvesting & SE Prep | 🟢 Beginner | Email Harvester |
| 03 | Phishing Page Anatomy & Detection | 🟢 Beginner | URL Phishing Scorer |
| 04 | Vishing & Smishing Simulation | 🟢 Beginner | SE Script Generator |
| 05 | OSINT + SE: Build Target Profile | 🟡 Intermediate | GitHub Profiler |

### Week 2: Active Attacks & Defense

| Day | Topic | Difficulty | Key Deliverable |
|-----|-------|------------|-----------------|
| 06 | Spear Phishing Email Craft | 🟡 Intermediate | Email Engine |
| 07 | Password Attacks & Credential Stuffing | 🟡 Intermediate | Attack Simulator |
| 08 | USB Drop Attack Simulation | 🟡 Intermediate | USB Payload |
| 09 | Social Media Impersonation Detection | 🟡 Intermediate | Fake Profile Detector |
| 10 | Baiting & Watering Hole Attack | 🟡 Intermediate | Honeypot Tracker |

### Week 3: Advanced Defense & Reporting

| Day | Topic | Difficulty | Key Deliverable |
|-----|-------|------------|-----------------|
| 11 | SE Awareness Training Module | 🟡 Intermediate | Quiz Engine |
| 12 | Phishing Detection with ML | 🔴 Advanced | ML Classifier |
| 13 | SIEM Log Analysis | 🔴 Advanced | Log Analyzer |
| 14 | SE Incident Response Plan | 🔴 Advanced | IR Automation |
| 15 | Final Project: SE Attack Chain | 🔴 Advanced | Complete Simulator |

---

## 🚀 Quick Start

### Prerequisites

```bash
# Required Python packages
pip install -r requirements.txt

# For Parrot OS/Kali Linux
sudo apt update
sudo apt install python3 python3-pip
Environment Setup
bash
# Clone the repository
git clone https://github.com/yourusername/sqrock-internship.git
cd sqrock-internship

# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Create authorization file (required for some tools)
echo "I am using this tool in an authorized lab environment" > AUTHORIZED_LAB_USE.txt
Running Tools
bash
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
🔒 Ethical Guidelines
All tools in this repository are for EDUCATIONAL PURPOSES ONLY and must only be used in:

✅ Authorized lab environments
✅ Your own systems and domains
✅ Written permission from system owners

Prohibited:
❌ Targeting real users without permission
❌ Unauthorized data collection
❌ Any activity violating IT Act 2000 (India), CFAA (US), or GDPR (EU)
Key Metrics
text
Total Code: ~3,500+ lines
Tools Built: 13
Security Scenarios: 50+
Detection Heuristics: 100+
ML Models: 1
Reports Generated: 13
🤝 Contributing
This is an individual internship project. However, feedback and suggestions are welcome!

Fork the repository

Create a feature branch

Submit a pull request

📝 License
Educational Use Only – All code is for cybersecurity training purposes
