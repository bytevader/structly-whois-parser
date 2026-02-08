from __future__ import annotations

from structly_whois.normalization import (
    _collapse_wrapped_fields,
    _slice_from_last_domain,
    _slice_latest_section,
    normalize_raw_text,
)


def test_collapse_wrapped_fields_merges_headers() -> None:
    lines = ["Domain Name:", "example.com", "Registrar:", "Example Registrar"]
    collapsed = _collapse_wrapped_fields(lines)
    assert collapsed[0] == "Domain Name: example.com"
    assert collapsed[1] == "Registrar: Example Registrar"


def test_slice_latest_section_prefers_last_marker() -> None:
    payload = "# server.one\nDomain Name: old.example\n# server.two\nDomain Name: new.example\n"
    latest = _slice_latest_section(payload)
    assert "Domain Name: new.example" in latest


def test_slice_latest_section_handles_leading_hash() -> None:
    payload = "# banner\nDomain Name: example.org\n"
    assert _slice_latest_section(payload) == payload


def test_slice_from_last_domain_without_leading_newline() -> None:
    payload = "Domain Name: lone.example\nRegistrar: Example\n"
    result = _slice_from_last_domain(payload)
    assert result.startswith("Domain Name: lone.example")


def test_normalize_raw_text_handles_empty_and_enforces_newline() -> None:
    assert normalize_raw_text("") == ""
    result = normalize_raw_text("Domain Name: example.dev")
    assert result.endswith("\n")


def test_normalize_raw_text_preserves_existing_newline() -> None:
    payload = "Domain Name: foo.example\nRegistrar: Example\n"
    result = normalize_raw_text(payload)
    assert result == payload
