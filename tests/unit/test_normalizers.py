from __future__ import annotations

from collections.abc import Mapping
from typing import Any

import pytest

import structly_whois.normalization as normalization
from structly_whois.normalization import normalize_raw_text
from structly_whois.normalizers.fr import (
    AfnicTextNormalizer,
    _build_afnic_contact_values,
    _extract_afnic_contact_blocks,
    _extract_afnic_handles,
    _has_fr_hint,
)


def test_afnic_helpers_extract_contacts() -> None:
    lines = [
        "holder-c: AA123",
        "admin-c: BB123",
        "tech-c: BB123",
        "nic-hdl: AA123",
        "contact: Holder Org",
        "type: ORGANIZATION",
        "e-mail: holder@example.com",
        "phone: +33.1",
        "source: FRNIC",
        "",
        "nic-hdl: BB123",
        "contact: Admin Person",
        "type: PERSON",
        "source: FRNIC",
    ]
    handles = _extract_afnic_handles(lines)
    assert handles == {"holder": "AA123", "admin": "BB123", "tech": "BB123"}
    blocks = _extract_afnic_contact_blocks(lines)
    values = _build_afnic_contact_values(handles, blocks)
    assert values["registrant_organization"] == "Holder Org"
    assert values["admin_name"] == "Admin Person"


def test_afnic_text_normalizer_appends_contacts(sample_payloads: Mapping[str, str]) -> None:
    AfnicTextNormalizer()
    normalized = normalize_raw_text(sample_payloads["afnic"])

    assert "Registrant Name: AFNIC Test" in normalized
    assert "Admin Name: Admin Contact" in normalized
    assert "Tech Email: admin@example.fr" in normalized


def test_afnic_text_normalizer_uses_tld_hint(sample_payloads: Mapping[str, str]) -> None:
    normalizer = AfnicTextNormalizer()

    assert not normalizer.applicable(sample_payloads["afnic"], tld="com", domain="example.com")


def test_afnic_text_normalizer_accepts_fr_hint() -> None:
    normalizer = AfnicTextNormalizer()
    payload = "Domain Name: sample.fr\nholder-c: TEST-FRNIC\n"

    assert normalizer.applicable(payload, tld="fr", domain=None)


def test_has_fr_hint_variants() -> None:
    assert _has_fr_hint("FR", None)
    assert _has_fr_hint(None, "example.FR")
    assert _has_fr_hint(None, "sub.domain.fr")
    assert not _has_fr_hint(None, "example.com")


def test_afnic_normalizer_returns_original_when_handles_missing() -> None:
    normalizer = AfnicTextNormalizer()
    payload = "Domain Name: example.fr\nnic-hdl: TEST\nsource: FRNIC\n"

    assert normalizer.normalize(payload, None, None) == payload


def test_afnic_normalizer_returns_original_when_blocks_missing() -> None:
    normalizer = AfnicTextNormalizer()
    payload = "% This is the AFNIC Whois server.\nholder-c: AA123\n"

    assert normalizer.normalize(payload, None, None) == payload


def test_custom_normalizer_runs_before_builtins(normalizer_registry: Any) -> None:
    events: list[str] = []

    class RecorderNormalizer:
        def __init__(self, name: str) -> None:
            self.name = name

        def applicable(self, tld: str | None, domain: str | None, parsed: Mapping[str, Any]) -> bool:
            return True

        def normalize(self, parsed: Mapping[str, Any], raw_text: str) -> Mapping[str, Any]:
            events.append(self.name)
            return parsed

    normalizer_registry.clear_normalizers()
    normalizer_registry.register_normalizer(RecorderNormalizer("core"), priority=0)
    normalizer_registry.register_normalizer(RecorderNormalizer("custom"), priority=5)

    normalizer_registry.run_normalizers("fr", "example.fr", {}, "Domain Name: example.fr\n")

    assert events == ["custom", "core"]


def test_normalizer_execution_order_is_deterministic(normalizer_registry: Any) -> None:
    events: list[str] = []

    class RecorderNormalizer:
        def __init__(self, name: str) -> None:
            self.name = name

        def applicable(self, tld: str | None, domain: str | None, parsed: Mapping[str, Any]) -> bool:
            return True

        def normalize(self, parsed: Mapping[str, Any], raw_text: str) -> Mapping[str, Any]:
            events.append(self.name)
            return parsed

    normalizer_registry.clear_normalizers()
    for name in ("first", "second", "third"):
        normalizer_registry.register_normalizer(RecorderNormalizer(name), priority=0)

    normalizer_registry.run_normalizers("com", None, {}, "Domain Name: example.com\n")

    assert events == ["first", "second", "third"]


def test_text_normalizer_priority(normalizer_registry: Any) -> None:
    events: list[str] = []

    class RecorderTextNormalizer:
        def __init__(self, name: str) -> None:
            self.name = name

        def applicable(self, raw_text: str, tld: str | None, domain: str | None) -> bool:
            return True

        def normalize(self, raw_text: str, tld: str | None, domain: str | None) -> str:
            events.append(self.name)
            return raw_text

    normalizer_registry.clear_text_normalizers()
    normalizer_registry.register_text_normalizer(RecorderTextNormalizer("core"), priority=0)
    normalizer_registry.register_text_normalizer(RecorderTextNormalizer("custom"), priority=10)

    normalizer_registry.run_text_normalizers("Domain Name: example.com\n", tld="com", domain=None)

    assert events == ["custom", "core"]


def test_text_normalizer_order_is_stable(normalizer_registry: Any) -> None:
    events: list[str] = []

    class RecorderTextNormalizer:
        def __init__(self, name: str) -> None:
            self.name = name

        def applicable(self, raw_text: str, tld: str | None, domain: str | None) -> bool:
            return True

        def normalize(self, raw_text: str, tld: str | None, domain: str | None) -> str:
            events.append(self.name)
            return raw_text

    normalizer_registry.clear_text_normalizers()
    for name in ("first", "second", "third"):
        normalizer_registry.register_text_normalizer(RecorderTextNormalizer(name), priority=0)

    normalizer_registry.run_text_normalizers("Domain Name: example.com\n", tld="com", domain=None)

    assert events == ["first", "second", "third"]


def test_record_normalizer_lowercases_fields(normalizer_registry: Any) -> None:
    class LowerNormalizer:
        def applicable(self, tld: str | None, domain: str | None, parsed: Mapping[str, Any]) -> bool:
            return True

        def normalize(self, parsed: Mapping[str, Any], raw_text: str) -> Mapping[str, Any]:
            updated = dict(parsed)
            domain_name = updated.get("domain_name")
            if isinstance(domain_name, str):
                updated["domain_name"] = domain_name.lower()
            name_servers = updated.get("name_servers")
            if isinstance(name_servers, list):
                updated["name_servers"] = [entry.lower() if isinstance(entry, str) else entry for entry in name_servers]
            return updated

    normalizer_registry.clear_normalizers()
    normalizer_registry.register_normalizer(LowerNormalizer(), priority=10)
    parsed = {"domain_name": "EXAMPLE.COM", "name_servers": ["NS1.ExAMPLE.COM", "NS2.example.COM"]}

    result = normalizer_registry.run_normalizers("com", "EXAMPLE.COM", parsed, "Domain Name: EXAMPLE.COM\n")

    assert result["domain_name"] == "example.com"
    assert result["name_servers"] == ["ns1.example.com", "ns2.example.com"]


def test_run_normalizers_handles_inplace_mutation(normalizer_registry: Any) -> None:
    class InplaceNormalizer:
        def applicable(self, tld: str | None, domain: str | None, parsed: Mapping[str, Any]) -> bool:
            return True

        def normalize(self, parsed: Mapping[str, Any], raw_text: str) -> Mapping[str, Any]:
            parsed["domain_name"] = parsed["domain_name"].lower()  # type: ignore[index]
            return parsed

    normalizer_registry.clear_normalizers()
    normalizer_registry.register_normalizer(InplaceNormalizer(), priority=0)
    parsed = {"domain_name": "EXAMPLE.COM"}

    result = normalizer_registry.run_normalizers("com", "example.com", parsed, "Domain Name: EXAMPLE.COM\n")

    assert result is parsed
    assert result["domain_name"] == "example.com"


def test_register_normalizer_type_check(normalizer_registry: Any) -> None:
    class NotNormalizer:
        pass

    with pytest.raises(TypeError):
        normalization.register_normalizer(NotNormalizer())  # type: ignore[arg-type]


def test_register_text_normalizer_type_check(normalizer_registry: Any) -> None:
    class NotTextNormalizer:
        pass

    with pytest.raises(TypeError):
        normalization.register_text_normalizer(NotTextNormalizer())  # type: ignore[arg-type]


def test_run_text_normalizers_requires_string(normalizer_registry: Any) -> None:
    class BadTextNormalizer:
        def applicable(self, raw_text: str, tld: str | None, domain: str | None) -> bool:
            return True

        def normalize(self, raw_text: str, tld: str | None, domain: str | None) -> object:
            return 123  # type: ignore[return-value]

    normalization.clear_text_normalizers()
    normalization.register_text_normalizer(BadTextNormalizer())

    with pytest.raises(TypeError):
        normalization.run_text_normalizers("Domain Name: example.com", tld=None, domain=None)
