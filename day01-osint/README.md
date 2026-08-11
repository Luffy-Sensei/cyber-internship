# Day 01 — OSINT & Passive Reconnaissance

**Cybersecurity Internship — Phase 1**

## Overview

Day 01 focuses on Open-Source Intelligence (OSINT) and passive reconnaissance.

The objective was to understand how publicly available information can be collected and correlated without directly probing the target infrastructure.

A Python-based OSINT scanner was developed to collect publicly available information including WHOIS registration data, DNS information, IP resolution, IP geolocation, passive host intelligence, and passive subdomain information.

## Learning Objectives

* Understand OSINT fundamentals.
* Understand passive vs. active reconnaissance.
* Understand WHOIS registration information.
* Understand DNS records.
* Understand domain-to-IP resolution.
* Understand IP geolocation limitations.
* Understand third-party passive intelligence services.
* Understand passive subdomain discovery.
* Automate OSINT collection with Python.
* Generate structured machine-readable reports.
* Practice cybersecurity documentation and ethical decision-making.

## Passive vs. Active Reconnaissance

### Passive Reconnaissance

Passive reconnaissance collects information from existing public or third-party sources without directly probing the target infrastructure.

Examples include:

* WHOIS databases
* Public DNS information
* Certificate transparency data
* Public code repositories
* Search engines
* Third-party internet intelligence databases

### Active Reconnaissance

Active reconnaissance directly interacts with the target infrastructure.

Examples include:

* Port scanning
* Service enumeration
* Direct HTTP probing
* Network probing
* Vulnerability scanning

The distinction is important because active interaction can generate logs, alerts, and other observable network activity on the target.

## Tool Workflow

```text
Target Domain
      │
      ▼
WHOIS Information
      │
      ▼
DNS Records
      │
      ▼
IP Resolution
      │
      ▼
IP Geolocation
      │
      ▼
Passive Host Intelligence
      │
      ▼
Passive Subdomain Discovery
      │
      ▼
Structured JSON Report
```

## Information Collected

### WHOIS

The scanner attempts to retrieve publicly available registration information such as:

* Registrar
* Creation date
* Expiration date
* Name servers

Not every domain exposes every WHOIS field.

A `null` registrar value does not necessarily indicate an error. It can indicate that the information was unavailable through the selected WHOIS source or library.

### DNS

The scanner examines available DNS information including:

* A records
* AAAA records
* MX records
* NS records
* TXT records

DNS results describe DNS configuration and should not automatically be interpreted as proof that a host is actively serving an application.

### IP Resolution

The scanner resolves the target domain to available IP addresses.

An IP address provides a network destination but does not by itself prove that a particular service is online or that the IP represents the organization's physical location.

### IP Geolocation

The scanner queries a third-party geolocation service to obtain approximate information such as:

* Country
* Region
* City
* ISP
* Organization
* Autonomous System

Geolocation should be treated as an approximation. Cloud providers, hosting companies, CDNs, proxies, VPNs, and routing infrastructure can cause the IP location to differ from the organization's physical location.

### Passive Host Intelligence

The project can query third-party internet intelligence data to identify information that has previously been indexed by those services.

Such information may include:

* Indexed ports
* Hostnames
* CPE information
* Historical vulnerability references

An indexed result should not automatically be interpreted as proof of the target's current configuration.

### Passive Subdomain Discovery

The scanner attempts to identify subdomains using publicly available third-party sources.

Individual sources may fail, rate-limit requests, time out, or return incomplete data.

A source failure therefore does not necessarily indicate a failure of the target or the entire scanner.

## Error Handling

The scanner is designed to tolerate failures from individual third-party services.

Examples include:

* HTTP 404
* HTTP 429 rate limiting
* HTTP 502 gateway errors
* Request timeouts
* Missing DNS records
* Missing WHOIS fields

These conditions are recorded as source-level limitations rather than automatically being treated as target failures.

## Ethical Boundary

The project is intended for authorized cybersecurity training and educational use.

Passive information collection should not be interpreted as blanket authorization to investigate arbitrary organizations.

Before performing active reconnaissance or collecting information from third-party infrastructure, appropriate authorization should be obtained.

Results involving third-party infrastructure should also be handled responsibly and should not be unnecessarily published.

## Lessons Learned

The exercise demonstrated that OSINT is primarily an information-correlation problem.

Individual pieces of information can appear insignificant, but combining:

* Domain registration data
* DNS information
* IP addresses
* Hosting information
* Passive host intelligence
* Subdomain information

can produce a useful picture of an organization's externally visible infrastructure.

The exercise also demonstrated that OSINT data must be interpreted carefully because third-party databases can be incomplete, stale, rate-limited, or geographically approximate.

## Skills Practiced

* Python
* Linux
* DNS fundamentals
* WHOIS
* IP addressing
* OSINT
* Passive reconnaissance
* JSON
* `jq`
* API interaction
* Error handling
* Technical documentation
* Ethical cybersecurity methodology

## Project Status

**Day 01 — Complete**
