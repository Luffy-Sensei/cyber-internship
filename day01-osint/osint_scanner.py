#!/usr/bin/env python3
"""
Day 1 - 100% Passive OSINT & Reconnaissance Tool

Educational cybersecurity scanner for passive info-gathering.
Zero direct connections are made to the target host/IP.

Features:
    - Input sanitization (strips http/https, paths, ports)
    - WHOIS registration details (via Registrar servers)
    - Public DNS record lookup (A, AAAA, MX, NS, TXT via DNS Resolvers)
    - IPv4 & IPv6 resolution
    - IP Geolocation (via ip-api.com HTTP API)
    - Passive Threat & Open Port Intelligence (via Shodan InternetDB API)
    - Multi-source passive subdomain discovery (crt.sh, HackerTarget, AlienVault OTX)
    - Structured JSON report export
    - Plaintext subdomains TXT export

Usage:
    python3 osint_scanner.py example.com
    python3 osint_scanner.py https://example.com/path -o output/scan.json
"""

import argparse
import json
import re
import socket
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

import dns.resolver
import requests
import whois

USER_AGENT = "Day01-Passive-OSINT-Lab/1.0"


def sanitize_domain(target):
    """Clean protocol prefixes, paths, and port numbers from input string."""
    target = target.strip()
    # Remove http:// or https://
    target = re.sub(r"^https?://", "", target, flags=re.IGNORECASE)
    # Strip paths, queries, and ports (keep only the domain/hostname)
    target = target.split("/")[0].split(":")[0]
    return target.strip().lower()


def get_whois_data(domain):
    """Collect publicly available domain registration information from WHOIS servers."""
    try:
        data = whois.whois(domain)
        return {
            "registrar": data.registrar,
            "creation_date": str(data.creation_date),
            "expiration_date": str(data.expiration_date),
            "name_servers": data.name_servers,
        }
    except Exception as exc:
        return {"error": f"WHOIS lookup failed: {exc}"}


def get_dns_records(domain):
    """Collect public DNS records using standard recursive DNS queries."""
    record_types = ["A", "AAAA", "MX", "NS", "TXT"]
    records = {}

    for record_type in record_types:
        try:
            answers = dns.resolver.resolve(domain, record_type)
            records[record_type] = [answer.to_text() for answer in answers]
        except (
            dns.resolver.NoAnswer,
            dns.resolver.NXDOMAIN,
            dns.resolver.NoNameservers,
            dns.exception.Timeout,
        ):
            records[record_type] = []
        except Exception as exc:
            records[record_type] = [f"Error: {exc}"]

    return records


def resolve_domain(domain):
    """Resolve IPv4 and IPv6 addresses for the domain via OS DNS resolver."""
    result = {"ipv4": [], "ipv6": []}

    try:
        ipv4 = socket.gethostbyname_ex(domain)[2]
        result["ipv4"] = sorted(set(ipv4))
    except socket.gaierror:
        pass

    try:
        ipv6 = socket.getaddrinfo(domain, None, socket.AF_INET6)
        result["ipv6"] = sorted({item[4][0] for item in ipv6})
    except socket.gaierror:
        pass

    return result


def get_ip_geolocation(ip):
    """Retrieve geolocation via ip-api.com (uses HTTP free endpoint)."""
    try:
        response = requests.get(
            f"http://ip-api.com/json/{ip}",
            params={
                "fields": (
                    "status,message,country,regionName,"
                    "city,isp,org,as,query"
                )
            },
            headers={"User-Agent": USER_AGENT},
            timeout=10,
        )
        response.raise_for_status()
        data = response.json()

        if data.get("status") != "success":
            return {"error": data.get("message", "Geolocation lookup failed")}

        return data
    except requests.RequestException as exc:
        return {"error": f"Geolocation request failed: {exc}"}


def get_shodan_internetdb(ip):
    """
    Passively retrieve indexed port and host intelligence from Shodan InternetDB API.
    Zero traffic is sent to the target IP.
    """
    try:
        url = f"https://internetdb.shodan.io/{ip}"
        response = requests.get(url, headers={"User-Agent": USER_AGENT}, timeout=10)

        if response.status_code == 404:
            return {"status": "No historical data found in Shodan InternetDB for this IP"}

        response.raise_for_status()
        data = response.json()

        return {
            "open_ports": data.get("ports", []),
            "hostnames": data.get("hostnames", []),
            "cpes": data.get("cpes", []),
            "vulnerabilities": data.get("vulns", []),
        }
    except requests.RequestException as exc:
        return {"error": f"Shodan InternetDB request failed: {exc}"}


# --- Passive Subdomain Discovery Modules ---


def get_subdomains_crtsh(domain):
    """Passively enumerate subdomains via Certificate Transparency logs (crt.sh)."""
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    subdomains = set()

    try:
        response = requests.get(url, headers={"User-Agent": USER_AGENT}, timeout=15)
        response.raise_for_status()
        data = response.json()

        for entry in data:
            name_value = entry.get("name_value", "")
            for line in name_value.split("\n"):
                sub = line.strip().lower()
                if sub.startswith("*."):
                    sub = sub[2:]
                if sub and (sub.endswith(f".{domain}") or sub == domain):
                    subdomains.add(sub)

        return sorted(subdomains)
    except requests.RequestException as exc:
        return {"error": f"crt.sh request failed: {exc}"}
    except json.JSONDecodeError:
        return {"error": "crt.sh returned invalid JSON (server busy)"}
    except Exception as exc:
        return {"error": f"crt.sh discovery failed: {exc}"}


def get_subdomains_hackertarget(domain):
    """Passively enumerate subdomains via HackerTarget Host Search API."""
    url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
    subdomains = set()

    try:
        response = requests.get(url, headers={"User-Agent": USER_AGENT}, timeout=10)
        response.raise_for_status()
        text = response.text

        if "API count exceed" in text or "error" in text.lower():
            return {"error": "HackerTarget rate limit exceeded"}

        for line in text.splitlines():
            if "," in line:
                sub = line.split(",")[0].strip().lower()
                if sub.startswith("*."):
                    sub = sub[2:]
                if sub and (sub.endswith(f".{domain}") or sub == domain):
                    subdomains.add(sub)

        return sorted(subdomains)
    except requests.RequestException as exc:
        return {"error": f"HackerTarget request failed: {exc}"}
    except Exception as exc:
        return {"error": f"HackerTarget discovery failed: {exc}"}


def get_subdomains_alienvault(domain):
    """Passively enumerate subdomains via AlienVault OTX Passive DNS API."""
    url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
    subdomains = set()

    try:
        response = requests.get(url, headers={"User-Agent": USER_AGENT}, timeout=10)
        response.raise_for_status()
        data = response.json()

        for entry in data.get("passive_dns", []):
            hostname = entry.get("hostname", "").strip().lower()
            if hostname.startswith("*."):
                hostname = hostname[2:]
            if hostname and (hostname.endswith(f".{domain}") or hostname == domain):
                subdomains.add(hostname)

        return sorted(subdomains)
    except requests.RequestException as exc:
        return {"error": f"AlienVault OTX request failed: {exc}"}
    except json.JSONDecodeError:
        return {"error": "AlienVault OTX returned invalid JSON response"}
    except Exception as exc:
        return {"error": f"AlienVault OTX discovery failed: {exc}"}


def get_all_subdomains(domain):
    """Concurrently query passive subdomain discovery sources."""
    sources = {
        "crt.sh": get_subdomains_crtsh,
        "HackerTarget": get_subdomains_hackertarget,
        "AlienVault OTX": get_subdomains_alienvault,
    }

    results_by_source = {}
    aggregated_subdomains = set()

    with ThreadPoolExecutor(max_workers=3) as executor:
        future_to_source = {
            executor.submit(func, domain): source_name
            for source_name, func in sources.items()
        }

        for future in as_completed(future_to_source):
            source_name = future_to_source[future]
            try:
                result = future.result()
                results_by_source[source_name] = result
                if isinstance(result, list):
                    aggregated_subdomains.update(result)
            except Exception as exc:
                results_by_source[source_name] = {"error": f"Execution error: {exc}"}

    return {
        "total_unique": len(aggregated_subdomains),
        "combined_subdomains": sorted(aggregated_subdomains),
        "sources": results_by_source,
    }


# --- Main Scanner Workflow ---


def run_scan(domain, max_workers=10):
    """Run 100% passive OSINT checks concurrently using ThreadPoolExecutor."""
    start_time = datetime.now(timezone.utc)

    print("\n" + "=" * 60)
    print("      DAY 01 - 100% PASSIVE OSINT RECONNAISSANCE")
    print("=" * 60)
    print(f"[+] Target domain : {domain}")
    print(f"[+] Scan mode     : Strictly Passive (Zero Direct Contact)")
    print(f"[+] Started       : {start_time.isoformat()}")
    print("[+] Querying public third-party APIs...")

    geolocation = {}
    shodan_intel = {}

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Submit independent domain-level tasks
        future_whois = executor.submit(get_whois_data, domain)
        future_dns = executor.submit(get_dns_records, domain)
        future_resolution = executor.submit(resolve_domain, domain)
        future_subdomains = executor.submit(get_all_subdomains, domain)

        # Wait for IP resolution so third-party IP lookups can dispatch
        addresses = future_resolution.result()

        # Submit passive geolocation and Shodan checks for IPv4s concurrently
        geo_futures = {
            executor.submit(get_ip_geolocation, ip): ip
            for ip in addresses.get("ipv4", [])
        }
        shodan_futures = {
            executor.submit(get_shodan_internetdb, ip): ip
            for ip in addresses.get("ipv4", [])
        }

        # Gather domain-level results
        whois_data = future_whois.result()
        dns_data = future_dns.result()
        subdomain_data = future_subdomains.result()

        # Gather geolocation results
        for future in as_completed(geo_futures):
            ip = geo_futures[future]
            try:
                geolocation[ip] = future.result()
            except Exception as exc:
                geolocation[ip] = {"error": f"Task failed: {exc}"}

        # Gather Shodan InternetDB results
        for future in as_completed(shodan_futures):
            ip = shodan_futures[future]
            try:
                shodan_intel[ip] = future.result()
            except Exception as exc:
                shodan_intel[ip] = {"error": f"Task failed: {exc}"}

    # Format terminal summary output
    print("\n[1] WHOIS Registration Information")
    print("    Registrar:", whois_data.get("registrar", "N/A"))

    print("\n[2] DNS Records")
    for record_type, values in dns_data.items():
        print(f"    {record_type}:")
        if values:
            for value in values:
                print(f"        {value}")
        else:
            print("        N/A")

    print("\n[3] IP Resolution")
    print("    IPv4:")
    for ip in addresses["ipv4"]:
        print(f"        {ip}")
    print("    IPv6:")
    for ip in addresses["ipv6"]:
        print(f"        {ip}")

    print("\n[4] IP Geolocation (via ip-api)")
    for ip, location in geolocation.items():
        print(f"    IP: {ip}")
        if "error" not in location:
            print(
                "        Location: "
                f"{location.get('city', 'N/A')}, "
                f"{location.get('country', 'N/A')}"
            )
            print(f"        ISP:      {location.get('isp', 'N/A')}")
        else:
            print(f"        Error:    {location['error']}")

    print("\n[5] Passive Host Intelligence (via Shodan InternetDB)")
    for ip, intel in shodan_intel.items():
        print(f"    IP: {ip}")
        if "error" not in intel and "status" not in intel:
            print(f"        Open Ports (Indexed): {intel.get('open_ports', [])}")
            print(f"        Hostnames          : {intel.get('hostnames', [])}")
            print(f"        Indexed CVEs Count : {len(intel.get('vulnerabilities', []))}")
        elif "status" in intel:
            print(f"        Status             : {intel['status']}")
        else:
            print(f"        Error              : {intel['error']}")

    print("\n[6] Passive Subdomain Discovery")
    for source_name, source_result in subdomain_data.get("sources", {}).items():
        if isinstance(source_result, list):
            print(f"        [{source_name:14}] Discovered {len(source_result)} subdomains")
        elif isinstance(source_result, dict) and "error" in source_result:
            print(f"        [{source_name:14}] {source_result['error']}")

    total_unique = subdomain_data.get("total_unique", 0)
    combined = subdomain_data.get("combined_subdomains", [])
    print(f"\n    Total Unique Subdomains: {total_unique}")

    if combined:
        display_limit = 10
        for sub in combined[:display_limit]:
            print(f"        {sub}")
        if len(combined) > display_limit:
            print(f"        ... and {len(combined) - display_limit} more (saved to outputs)")

    end_time = datetime.now(timezone.utc)
    duration = (end_time - start_time).total_seconds()
    print(f"\n[+] Scan completed in {duration:.2f} seconds.")

    return {
        "scan_metadata": {
            "domain": domain,
            "scan_type": "100% Passive OSINT",
            "timestamp_utc": start_time.isoformat(),
            "execution_time_seconds": round(duration, 2),
        },
        "whois": whois_data,
        "dns": dns_data,
        "resolution": addresses,
        "geolocation": geolocation,
        "shodan_passive_intel": shodan_intel,
        "subdomains": subdomain_data,
    }


def save_outputs(data, json_filename):
    """Save scan results as structured JSON and export line-separated subdomains.txt."""
    json_path = Path(json_filename)
    json_path.parent.mkdir(parents=True, exist_ok=True)

    with open(json_path, "w", encoding="utf-8") as file:
        json.dump(data, file, indent=4, default=str)

    txt_path = json_path.parent / "subdomains.txt"
    subdomains = data.get("subdomains", {}).get("combined_subdomains", [])

    with open(txt_path, "w", encoding="utf-8") as file:
        file.write("\n".join(subdomains) + ("\n" if subdomains else ""))

    return json_path, txt_path


def main():
    parser = argparse.ArgumentParser(
        description="100% Passive OSINT scanner for cybersecurity research."
    )
    parser.add_argument("domain", help="Domain to investigate (e.g. scanme.nmap.org or example.com)")
    parser.add_argument(
        "-o",
        "--output",
        default="output/scan.json",
        help="JSON output file (default: output/scan.json)",
    )
    parser.add_argument(
        "-w",
        "--workers",
        type=int,
        default=10,
        help="Max worker threads (default: 10)",
    )

    args = parser.parse_args()
    domain = sanitize_domain(args.domain)

    if not domain:
        print("[-] Error: Domain cannot be empty.")
        sys.exit(1)

    try:
        results = run_scan(domain, max_workers=args.workers)
        json_path, txt_path = save_outputs(results, args.output)

        print("\n" + "=" * 60)
        print(f"[+] JSON Report saved to      : {json_path}")
        print(f"[+] Subdomains TXT exported to : {txt_path}")
        print("=" * 60)

    except KeyboardInterrupt:
        print("\n[-] Scan interrupted by user.")
        sys.exit(130)
    except Exception as exc:
        print(f"\n[-] Unexpected error: {exc}")
        sys.exit(1)


if __name__ == "__main__":
    main()
