#!/usr/bin/env python3

"""
Tests for the SE Chain passive OSINT module.
"""

from se_chain.models import ChainContext, RunMetadata
from se_chain.modules.osint import OSINTModule


def make_context(target: str = "example.com") -> ChainContext:
    """Create a minimal authorized test context."""

    metadata = RunMetadata(
        target=target,
        mode="lab",
    )

    return ChainContext(
        metadata=metadata,
        authorized=True,
    )


def test_osint_success(monkeypatch):
    """OSINT should complete when providers return normally."""

    module = OSINTModule()

    monkeypatch.setattr(
        module,
        "_execute_domain_providers",
        lambda target: {
            "whois": {
                "registrar": "Test Registrar",
            },
            "dns": {
                "A": ["192.0.2.10"],
                "AAAA": [],
                "MX": [],
                "NS": [],
                "TXT": [],
            },
            "resolution": {
                "ipv4": ["192.0.2.10"],
                "ipv6": [],
            },
            "subdomains": {
                "total_unique": 1,
                "combined_subdomains": [
                    "www.example.com"
                ],
                "sources": {},
            },
        },
    )

    monkeypatch.setattr(
        module,
        "_execute_ip_providers",
        lambda addresses: {
            "geolocation": {
                "192.0.2.10": {
                    "country": "Test"
                }
            },
            "shodan": {
                "192.0.2.10": {
                    "open_ports": []
                }
            },
        },
    )

    result = module.run(
        make_context()
    )

    assert result.success is True
    assert result.status == "completed"
    assert result.errors == []

    assert "whois" in result.data
    assert "dns" in result.data
    assert "resolution" in result.data
    assert "geolocation" in result.data
    assert "shodan_passive_intel" in result.data
    assert "subdomains" in result.data


def test_osint_missing_target():
    """Missing targets must produce a controlled module failure."""

    context = make_context("")

    result = OSINTModule().run(context)

    assert result.success is False
    assert result.status == "failed"
    assert result.errors


def test_osint_target_sanitization(monkeypatch):
    """HTTP URLs should be normalized to hostnames."""

    module = OSINTModule()

    captured = {}

    def fake_domain_providers(target):
        captured["target"] = target

        return {
            "whois": {},
            "dns": {},
            "resolution": {
                "ipv4": [],
                "ipv6": [],
            },
            "subdomains": {
                "total_unique": 0,
                "combined_subdomains": [],
                "sources": {},
            },
        }

    monkeypatch.setattr(
        module,
        "_execute_domain_providers",
        fake_domain_providers,
    )

    monkeypatch.setattr(
        module,
        "_execute_ip_providers",
        lambda addresses: {
            "geolocation": {},
            "shodan": {},
        },
    )

    result = module.run(
        make_context(
            "https://Example.COM:443/login"
        )
    )

    assert result.success is True
    assert captured["target"] == "example.com"


def test_osint_provider_failure(monkeypatch):
    """
    A provider failure should become a warning rather than
    crashing the complete OSINT module.
    """

    module = OSINTModule()

    monkeypatch.setattr(
        module,
        "_execute_domain_providers",
        lambda target: {
            "whois": {
                "_provider_error": "WHOIS unavailable"
            },
            "dns": {
                "A": ["192.0.2.10"]
            },
            "resolution": {
                "ipv4": [],
                "ipv6": [],
            },
            "subdomains": {
                "total_unique": 0,
                "combined_subdomains": [],
                "sources": {},
            },
        },
    )

    monkeypatch.setattr(
        module,
        "_execute_ip_providers",
        lambda addresses: {
            "geolocation": {},
            "shodan": {},
        },
    )

    result = module.run(
        make_context()
    )

    assert result.success is True
    assert result.status == "completed"

    assert result.errors == []

    assert any(
        "WHOIS unavailable" in warning
        for warning in result.warnings
    )


def test_osint_no_resolved_ips(monkeypatch):
    """No IP resolution should not cause module failure."""

    module = OSINTModule()

    monkeypatch.setattr(
        module,
        "_execute_domain_providers",
        lambda target: {
            "whois": {},
            "dns": {},
            "resolution": {
                "ipv4": [],
                "ipv6": [],
            },
            "subdomains": {
                "total_unique": 0,
                "combined_subdomains": [],
                "sources": {},
            },
        },
    )

    called_with = {}

    def fake_ip_providers(addresses):
        called_with["addresses"] = addresses

        return {
            "geolocation": {},
            "shodan": {},
        }

    monkeypatch.setattr(
        module,
        "_execute_ip_providers",
        fake_ip_providers,
    )

    result = module.run(
        make_context()
    )

    assert result.success is True
    assert result.status == "completed"
    assert called_with["addresses"] == []


def test_osint_subdomain_deduplication():
    """Subdomain normalization should remove duplicates."""

    module = OSINTModule()

    assert (
        module._normalize_subdomain(
            "*.WWW.Example.COM",
            "example.com",
        )
        == "www.example.com"
    )

    assert (
        module._normalize_subdomain(
            "www.example.com",
            "example.com",
        )
        == "www.example.com"
    )

    assert (
        module._normalize_subdomain(
            "evil.example.net",
            "example.com",
        )
        is None
    )
