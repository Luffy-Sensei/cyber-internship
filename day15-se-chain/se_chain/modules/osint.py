#!/usr/bin/env python3

"""
SE Chain Simulator - OSINT Module

Production-oriented passive OSINT integration.

Design principles:
    - Passive/public intelligence only.
    - No direct target probing.
    - Provider failures are isolated.
    - No CLI interaction.
    - No report writing.
    - No process termination.
    - Authorization decisions belong to the safety layer.
    - Results are returned through ModuleResult.
"""

from __future__ import annotations

import json
import re
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import Any, Callable

import dns.exception
import dns.resolver
import requests
import whois

from se_chain.exceptions import OSINTError
from se_chain.models import ChainContext, ModuleResult


class OSINTModule:
    """
    Execute passive OSINT collection for the current chain context.
    """

    name = "osint"

    USER_AGENT = "SE-Chain-Simulator/1.0"

    DNS_RECORD_TYPES = (
        "A",
        "AAAA",
        "MX",
        "NS",
        "TXT",
    )

    def run(self, context: ChainContext) -> ModuleResult:
        """
        Execute passive OSINT collection.

        Provider failures are isolated and reported as warnings.
        """

        result = ModuleResult(
            module=self.name,
            success=False,
            message="OSINT execution started",
        )

        try:
            target = self._get_target(context)
            target = self._sanitize_target(target)

            started_at = datetime.now(timezone.utc)

            data: dict[str, Any] = {
                "scan_metadata": {
                    "target": target,
                    "scan_type": "Passive OSINT",
                    "collection_mode": "passive_third_party",
                    "direct_target_probing": False,
                    "timestamp_utc": started_at.isoformat(),
                },
                "whois": {},
                "dns": {},
                "resolution": {
                    "ipv4": [],
                    "ipv6": [],
                },
                "geolocation": {},
                "shodan_passive_intel": {},
                "subdomains": {
                    "total_unique": 0,
                    "combined_subdomains": [],
                    "sources": {},
                },
            }

            provider_results = self._execute_domain_providers(target)

            for provider_name, provider_result in provider_results.items():
                if provider_name == "whois":
                    data["whois"] = provider_result

                elif provider_name == "dns":
                    data["dns"] = provider_result

                elif provider_name == "resolution":
                    data["resolution"] = provider_result

                elif provider_name == "subdomains":
                    data["subdomains"] = provider_result

            # ----------------------------------------------------------
            # IP-dependent providers
            # ----------------------------------------------------------

            ipv4_addresses = data["resolution"].get("ipv4", [])

            ip_results = self._execute_ip_providers(ipv4_addresses)

            data["geolocation"] = ip_results["geolocation"]
            data["shodan_passive_intel"] = ip_results["shodan"]

            # ----------------------------------------------------------
            # Provider failure handling
            # ----------------------------------------------------------

            warnings = self._collect_provider_warnings(data)

            result.data = data

            for warning in warnings:
                result.warnings.append(warning)

            result.success = True

            if warnings:
                result.message = (
                    "Passive OSINT collection completed with "
                    f"{len(warnings)} provider warning(s)"
                )
            else:
                result.message = "Passive OSINT collection completed"

            result.complete()

            return result

        except OSINTError as exc:
            result.fail(str(exc))
            return result

        except Exception as exc:
            result.fail(f"Unexpected OSINT failure: {exc}")
            return result

    # ==================================================================
    # Target handling
    # ==================================================================

    @staticmethod
    def _get_target(context: ChainContext) -> str:
        """
        Extract target from ChainContext.
        """

        if context is None:
            raise OSINTError("OSINT context is missing")

        target = context.metadata.target

        if not target:
            raise OSINTError(
                "OSINT target is missing from chain context"
            )

        return target

    @staticmethod
    def _sanitize_target(target: str) -> str:
        """
        Normalize a hostname/domain.

        Protocols, paths, queries and fragments are removed.
        """

        target = target.strip()

        if not target:
            raise OSINTError("OSINT target cannot be empty")

        target = re.sub(
            r"^https?://",
            "",
            target,
            flags=re.IGNORECASE,
        )

        target = target.split("/", 1)[0]
        target = target.split("?", 1)[0]
        target = target.split("#", 1)[0]

        # Handle hostname:port.
        if target.count(":") == 1:
            target = target.split(":", 1)[0]

        target = target.strip().lower()

        if not target:
            raise OSINTError("OSINT target became empty after sanitization")

        return target

    # ==================================================================
    # Provider orchestration
    # ==================================================================

    def _execute_domain_providers(
        self,
        target: str,
    ) -> dict[str, Any]:
        """
        Execute independent domain-level providers concurrently.

        A failed provider returns a structured error instead of
        terminating the entire OSINT run.
        """

        providers: dict[str, Callable[[str], Any]] = {
            "whois": self._get_whois,
            "dns": self._get_dns,
            "resolution": self._resolve_domain,
            "subdomains": self._get_subdomains,
        }

        results: dict[str, Any] = {}

        with ThreadPoolExecutor(
            max_workers=len(providers)
        ) as executor:

            futures = {
                executor.submit(provider, target): name
                for name, provider in providers.items()
            }

            for future in as_completed(futures):
                provider_name = futures[future]

                try:
                    results[provider_name] = future.result()

                except Exception as exc:
                    results[provider_name] = {
                        "_provider_error": (
                            f"{provider_name} provider failed: {exc}"
                        )
                    }

        return results

    def _execute_ip_providers(
        self,
        addresses: list[str],
    ) -> dict[str, dict[str, Any]]:
        """
        Execute passive third-party providers for resolved IPv4s.
        """

        results = {
            "geolocation": {},
            "shodan": {},
        }

        if not addresses:
            return results

        with ThreadPoolExecutor(
            max_workers=min(len(addresses), 10)
        ) as executor:

            futures: dict[Any, tuple[str, str]] = {}

            for ip in addresses:
                futures[
                    executor.submit(
                        self._get_ip_geolocation,
                        ip,
                    )
                ] = ("geolocation", ip)

                futures[
                    executor.submit(
                        self._get_shodan_internetdb,
                        ip,
                    )
                ] = ("shodan", ip)

            for future in as_completed(futures):
                provider_name, ip = futures[future]

                try:
                    results[provider_name][ip] = future.result()

                except Exception as exc:
                    results[provider_name][ip] = {
                        "_provider_error": (
                            f"{provider_name} provider failed: {exc}"
                        )
                    }

        return results

    # ==================================================================
    # WHOIS
    # ==================================================================

    @staticmethod
    def _get_whois(domain: str) -> dict[str, Any]:
        """
        Retrieve public WHOIS information.
        """

        try:
            data = whois.whois(domain)

            return {
                "registrar": data.registrar,
                "creation_date": str(data.creation_date),
                "expiration_date": str(data.expiration_date),
                "name_servers": data.name_servers,
            }

        except Exception as exc:
            return {
                "_provider_error": f"WHOIS lookup failed: {exc}"
            }

    # ==================================================================
    # DNS
    # ==================================================================

    def _get_dns(self, domain: str) -> dict[str, Any]:
        """
        Retrieve public DNS records.
        """

        records: dict[str, list[str]] = {}

        for record_type in self.DNS_RECORD_TYPES:
            try:
                answers = dns.resolver.resolve(
                    domain,
                    record_type,
                )

                records[record_type] = [
                    answer.to_text()
                    for answer in answers
                ]

            except (
                dns.resolver.NoAnswer,
                dns.resolver.NXDOMAIN,
                dns.resolver.NoNameservers,
                dns.exception.Timeout,
            ):
                records[record_type] = []

            except Exception as exc:
                records[record_type] = [
                    f"Error: {exc}"
                ]

        return records

    # ==================================================================
    # DNS resolution
    # ==================================================================

    @staticmethod
    def _resolve_domain(domain: str) -> dict[str, list[str]]:
        """
        Resolve IPv4 and IPv6 addresses using the local resolver.
        """

        result = {
            "ipv4": [],
            "ipv6": [],
        }

        try:
            ipv4 = socket.gethostbyname_ex(domain)[2]

            result["ipv4"] = sorted(
                set(ipv4)
            )

        except socket.gaierror:
            pass

        try:
            ipv6 = socket.getaddrinfo(
                domain,
                None,
                socket.AF_INET6,
            )

            result["ipv6"] = sorted(
                {
                    item[4][0]
                    for item in ipv6
                }
            )

        except socket.gaierror:
            pass

        return result

    # ==================================================================
    # IP geolocation
    # ==================================================================

    def _get_ip_geolocation(
        self,
        ip: str,
    ) -> dict[str, Any]:
        """
        Query public IP geolocation intelligence.
        """

        try:
            response = requests.get(
                f"http://ip-api.com/json/{ip}",
                params={
                    "fields": (
                        "status,message,country,regionName,"
                        "city,isp,org,as,query"
                    )
                },
                headers={
                    "User-Agent": self.USER_AGENT
                },
                timeout=10,
            )

            response.raise_for_status()

            data = response.json()

            if data.get("status") != "success":
                return {
                    "_provider_error": data.get(
                        "message",
                        "Geolocation lookup failed",
                    )
                }

            return data

        except requests.RequestException as exc:
            return {
                "_provider_error": (
                    f"Geolocation request failed: {exc}"
                )
            }

    # ==================================================================
    # Shodan InternetDB
    # ==================================================================

    def _get_shodan_internetdb(
        self,
        ip: str,
    ) -> dict[str, Any]:
        """
        Retrieve passive indexed host intelligence.
        """

        try:
            response = requests.get(
                f"https://internetdb.shodan.io/{ip}",
                headers={
                    "User-Agent": self.USER_AGENT
                },
                timeout=10,
            )

            if response.status_code == 404:
                return {
                    "status": (
                        "No indexed data found"
                    )
                }

            response.raise_for_status()

            data = response.json()

            return {
                "open_ports": data.get(
                    "ports",
                    [],
                ),
                "hostnames": data.get(
                    "hostnames",
                    [],
                ),
                "cpes": data.get(
                    "cpes",
                    [],
                ),
                "vulnerabilities": data.get(
                    "vulns",
                    [],
                ),
            }

        except requests.RequestException as exc:
            return {
                "_provider_error": (
                    f"Shodan InternetDB request failed: {exc}"
                )
            }

        except json.JSONDecodeError:
            return {
                "_provider_error": (
                    "Shodan InternetDB returned invalid JSON"
                )
            }

    # ==================================================================
    # Passive subdomain discovery
    # ==================================================================

    def _get_subdomains(
        self,
        domain: str,
    ) -> dict[str, Any]:
        """
        Query passive subdomain intelligence sources.
        """

        providers = {
            "crt.sh": self._get_crtsh,
            "HackerTarget": self._get_hackertarget,
            "AlienVault OTX": self._get_alienvault,
        }

        results: dict[str, Any] = {}
        combined: set[str] = set()

        with ThreadPoolExecutor(
            max_workers=len(providers)
        ) as executor:

            futures = {
                executor.submit(
                    provider,
                    domain,
                ): name
                for name, provider in providers.items()
            }

            for future in as_completed(futures):
                provider_name = futures[future]

                try:
                    provider_result = future.result()

                    results[provider_name] = provider_result

                    if isinstance(
                        provider_result,
                        list,
                    ):
                        combined.update(provider_result)

                except Exception as exc:
                    results[provider_name] = {
                        "_provider_error": (
                            f"{provider_name} failed: {exc}"
                        )
                    }

        return {
            "total_unique": len(combined),
            "combined_subdomains": sorted(combined),
            "sources": results,
        }

    def _get_crtsh(
        self,
        domain: str,
    ) -> list[str] | dict[str, str]:
        """
        Passive Certificate Transparency discovery.
        """

        url = (
            f"https://crt.sh/?q=%.{domain}"
            "&output=json"
        )

        try:
            response = requests.get(
                url,
                headers={
                    "User-Agent": self.USER_AGENT
                },
                timeout=15,
            )

            response.raise_for_status()

            data = response.json()

            subdomains: set[str] = set()

            for entry in data:
                for name in entry.get(
                    "name_value",
                    "",
                ).splitlines():

                    name = self._normalize_subdomain(
                        name,
                        domain,
                    )

                    if name:
                        subdomains.add(name)

            return sorted(subdomains)

        except requests.RequestException as exc:
            return {
                "_provider_error": (
                    f"crt.sh request failed: {exc}"
                )
            }

        except json.JSONDecodeError:
            return {
                "_provider_error": (
                    "crt.sh returned invalid JSON"
                )
            }

    def _get_hackertarget(
        self,
        domain: str,
    ) -> list[str] | dict[str, str]:
        """
        Passive HackerTarget host-search discovery.
        """

        try:
            response = requests.get(
                "https://api.hackertarget.com/hostsearch/",
                params={"q": domain},
                headers={
                    "User-Agent": self.USER_AGENT
                },
                timeout=10,
            )

            response.raise_for_status()

            text = response.text

            if "API count exceed" in text:
                return {
                    "_provider_error": (
                        "HackerTarget rate limit exceeded"
                    )
                }

            subdomains: set[str] = set()

            for line in text.splitlines():
                if "," not in line:
                    continue

                hostname = line.split(
                    ",",
                    1,
                )[0].strip()

                hostname = self._normalize_subdomain(
                    hostname,
                    domain,
                )

                if hostname:
                    subdomains.add(hostname)

            return sorted(subdomains)

        except requests.RequestException as exc:
            return {
                "_provider_error": (
                    f"HackerTarget request failed: {exc}"
                )
            }

    def _get_alienvault(
        self,
        domain: str,
    ) -> list[str] | dict[str, str]:
        """
        Passive AlienVault OTX discovery.
        """

        url = (
            "https://otx.alienvault.com/api/v1/"
            f"indicators/domain/{domain}/passive_dns"
        )

        try:
            response = requests.get(
                url,
                headers={
                    "User-Agent": self.USER_AGENT
                },
                timeout=10,
            )

            response.raise_for_status()

            data = response.json()

            subdomains: set[str] = set()

            for entry in data.get(
                "passive_dns",
                [],
            ):
                hostname = entry.get(
                    "hostname",
                    "",
                ).strip()

                hostname = self._normalize_subdomain(
                    hostname,
                    domain,
                )

                if hostname:
                    subdomains.add(hostname)

            return sorted(subdomains)

        except requests.RequestException as exc:
            return {
                "_provider_error": (
                    f"AlienVault OTX request failed: {exc}"
                )
            }

        except json.JSONDecodeError:
            return {
                "_provider_error": (
                    "AlienVault OTX returned invalid JSON"
                )
            }

    # ==================================================================
    # Helpers
    # ==================================================================

    @staticmethod
    def _normalize_subdomain(
        hostname: str,
        domain: str,
    ) -> str | None:
        """
        Normalize and validate a discovered hostname.
        """

        hostname = hostname.strip().lower()

        if hostname.startswith("*."):
            hostname = hostname[2:]

        if not hostname:
            return None

        if (
            hostname == domain
            or hostname.endswith(f".{domain}")
        ):
            return hostname

        return None

    @staticmethod
    def _collect_provider_warnings(
        data: dict[str, Any],
    ) -> list[str]:
        """
        Find provider-level failures without treating them as
        complete module failures.
        """

        warnings: list[str] = []

        def inspect(
            provider_name: str,
            value: Any,
        ) -> None:

            if isinstance(value, dict):
                if "_provider_error" in value:
                    warnings.append(
                        str(value["_provider_error"])
                    )

                for nested_name, nested_value in value.items():
                    if nested_name == "sources":
                        inspect(
                            provider_name,
                            nested_value,
                        )

            elif isinstance(value, list):
                return

        for name, value in data.items():
            inspect(name, value)

        return warnings
