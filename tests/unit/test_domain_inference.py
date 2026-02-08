from __future__ import annotations

import re

from structly import FieldPattern

from structly_whois.domain_inference import DomainPatternRegistry, normalise_tld, split_domain


def test_domain_pattern_registry_refresh_deduplicates_patterns() -> None:
    registry = DomainPatternRegistry()
    base_fields = {
        "domain_name": {
            "patterns": [
                FieldPattern.starts_with("Domain Name:"),
                FieldPattern.regex(r"(?i)^domain name:\s*(?P<domain>[a-z0-9.-]+)$"),
            ]
        }
    }
    overrides = {
        "info": {
            "domain_name": {
                "extend_patterns": [FieldPattern.starts_with("Domain Name:")],
                "patterns": [FieldPattern.regex(r"(?i)^domain name:\s*(?P<domain>[a-z0-9.-]+)$")],
            }
        }
    }

    registry.refresh(base_fields, overrides)

    assert registry.prefixes == ("Domain Name:",)
    assert len(registry.regexes) == 1


def test_domain_pattern_registry_infer_uses_lastindex_and_group_zero() -> None:
    registry = DomainPatternRegistry()
    registry.regexes = (
        re.compile(r"(?i)Domain Label:\s*([a-z0-9.-]+)", re.MULTILINE),
        re.compile(r"^NO-NAME$", re.MULTILINE),
    )

    assert registry.infer("Domain Label: Example.dev") == "Example.dev"
    assert registry.infer("stuff\nNO-NAME\n") == "NO-NAME"


def test_domain_pattern_registry_prefers_named_groups() -> None:
    registry = DomainPatternRegistry()
    registry.regexes = (re.compile(r"(?i)^domain:\s*(?P<domain>[a-z0-9.-]+)$", re.MULTILINE),)

    assert registry.infer("Domain: Named.example") == "Named.example"


def test_domain_pattern_registry_infer_prefix_trims_suffix() -> None:
    registry = DomainPatternRegistry(prefixes=("Domain Name:",), regexes=())
    payload = "Domain Name: trailing.example. \n"

    assert registry.infer(payload) == "trailing.example"


def test_domain_pattern_registry_skips_empty_prefix_lines() -> None:
    registry = DomainPatternRegistry(prefixes=("Domain Name:",), regexes=())
    payload = "Domain Name:\nDomain Name: filled.example\n"

    assert registry.infer(payload) == "filled.example"


def test_domain_pattern_registry_refresh_includes_extend_and_prepend_patterns() -> None:
    registry = DomainPatternRegistry()
    base_fields = {
        "domain_name": {
            "extend_patterns": [FieldPattern.starts_with("Base:")],
        }
    }
    overrides = {
        "demo": {
            "domain_name": {
                "prepend_patterns": [FieldPattern.regex(r"(?i)^demo:\s*(?P<val>[a-z0-9.-]+)$")],
            }
        }
    }

    registry.refresh(base_fields, overrides)

    assert "Base:" in registry.prefixes
    assert any("demo" in pattern.pattern for pattern in registry.regexes)


def test_split_domain_and_normalise_tld_helpers() -> None:
    assert split_domain(None) == []
    assert split_domain(" Sub.Domain.CO.UK. ") == ["sub", "domain", "co", "uk"]
    assert normalise_tld(None) == ""
    assert normalise_tld(".INFO ") == "info"


def test_domain_pattern_registry_returns_none_when_no_match() -> None:
    registry = DomainPatternRegistry(prefixes=("Domain Name:",), regexes=(re.compile(r"(?i)domain:", re.MULTILINE),))

    assert registry.infer("No hits anywhere") is None
