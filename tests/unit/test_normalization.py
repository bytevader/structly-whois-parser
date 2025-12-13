from __future__ import annotations

from structly_whois.normalization import (
    _build_afnic_contact_lines,
    _collapse_wrapped_fields,
    _extract_afnic_contact_blocks,
    _extract_afnic_handles,
    _inject_afnic_contacts,
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


def test_afnic_handle_extraction_and_blocks() -> None:
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
    assert "AA123" in blocks and blocks["AA123"]["contact"] == "Holder Org"


def test_build_afnic_contact_lines_respects_contact_type() -> None:
    org_attrs = {"contact": "Org Name", "type": "ORGANIZATION", "e-mail": "org@example.com"}
    person_attrs = {"contact": "Alice", "type": "PERSON", "phone": "+33.2"}
    default_attrs = {"contact": "Unknown"}
    org_lines = _build_afnic_contact_lines("Registrant", org_attrs)
    assert "Registrant Organization: Org Name" in org_lines
    assert "Registrant Email: org@example.com" in org_lines
    person_lines = _build_afnic_contact_lines("Admin", person_attrs)
    assert person_lines == ["Admin Name: Alice", "Admin Phone: +33.2"]
    default_lines = _build_afnic_contact_lines("Tech", default_attrs)
    assert default_lines == ["Tech Name: Unknown"]


def test_inject_afnic_contacts_appends_contacts() -> None:
    payload = """\
% This is the AFNIC Whois server.
holder-c: AA123
admin-c: BB123
tech-c: BB123

nic-hdl: AA123
type: ORGANIZATION
contact: Holder Org
e-mail: holder@example.com
source: FRNIC

nic-hdl: BB123
type: PERSON
contact: Admin Person
source: FRNIC
"""
    normalized = _inject_afnic_contacts(payload)
    assert "Registrant Organization: Holder Org" in normalized
    assert "Admin Name: Admin Person" in normalized


def test_normalize_raw_text_handles_empty_and_enforces_newline() -> None:
    assert normalize_raw_text("") == ""
    result = normalize_raw_text("Domain Name: example.dev")
    assert result.endswith("\n")
