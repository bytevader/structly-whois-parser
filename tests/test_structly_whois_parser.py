from __future__ import annotations

import json
from pathlib import Path

import pytest

from structly_whois_parser import WhoisParser, normalize_raw_text

PROJECT_ROOT = Path(__file__).resolve().parents[1]
NINO_FIXTURES = PROJECT_ROOT / "vendor" / "ninoseki-whois-parser" / "tests" / "fixtures"
RICHARD_EXPECTED = PROJECT_ROOT / "vendor" / "richardpenman-whois" / "test" / "samples" / "expected"
RICHARD_WHOIS = PROJECT_ROOT / "vendor" / "richardpenman-whois" / "test" / "samples" / "whois"


@pytest.fixture(scope="module")
def whois_parser() -> WhoisParser:
    return WhoisParser()


def test_normalize_raw_text_keeps_last_block() -> None:
    raw = """Domain Name: FIRST-RESULT.COM\n# whois.server.one\nDomain Name: SHOULD-BE-DROPPED\n# whois.server.two\nDomain name:\n    example.co.uk\n"""
    normalized = normalize_raw_text(raw)

    assert "whois.server.one" not in normalized
    assert "# whois.server.two" not in normalized
    assert normalized.startswith("Domain name: example.co.uk")


@pytest.mark.parametrize(
    ("fixture", "domain", "expectations"),
    [
        (
            "google.com.txt",
            "google.com",
            {
                "domain_name": "google.com",
                "registrar": "MarkMonitor, Inc.",
                "creation_date": "1997-09-15T00:00:00-0700",
                "updated_date": "2019-09-09T08:39:04-0700",
                "expiration_date": "2028-09-13T00:00:00-0700",
                "name_servers": [
                    "ns4.google.com",
                    "ns2.google.com",
                    "ns1.google.com",
                    "ns3.google.com",
                ],
                "status": {
                    "clientDeleteProhibited",
                    "clientTransferProhibited",
                    "clientUpdateProhibited",
                    "serverDeleteProhibited",
                    "serverTransferProhibited",
                    "serverUpdateProhibited",
                },
            },
        ),
        (
            "google.co.jp.txt",
            "google.co.jp",
            {
                "domain_name": "GOOGLE.CO.JP",
                "creation_date": "2001/03/22",
                "updated_date": "2021/04/01 01:05:22 (JST)",
                "status": {"Connected (2022/03/31)"},
                "name_servers": [
                    "ns1.google.com",
                    "ns2.google.com",
                    "ns3.google.com",
                    "ns4.google.com",
                ],
            },
        ),
        (
            "google.kr.txt",
            "google.kr",
            {
                "domain_name": "google.kr",
                "creation_date": "2007. 03. 02.",
                "updated_date": "2010. 10. 04.",
                "expiration_date": "2022. 03. 02.",
                "name_servers": [
                    "ns1.google.com",
                    "ns2.google.com",
                ],
            },
        ),
        (
            "google.uk.txt",
            "google.uk",
            {
                "domain_name": "google.uk",
                "registrar": "Markmonitor Inc. t/a MarkMonitor Inc. [Tag = MARKMONITOR]",
                "creation_date": "11-Jun-2014",
                "updated_date": "24-May-2021",
                "expiration_date": "11-Jun-2022",
                "status": {"Registered until expiry date."},
                "name_servers": [
                    "ns1.googledomains.com",
                    "ns2.googledomains.com",
                    "ns3.googledomains.com",
                    "ns4.googledomains.com",
                ],
            },
        ),
    ],
    ids=["com", "jp", "kr", "uk"],
)
def test_parser_extracts_expected_fields(fixture: str, domain: str, expectations: dict[str, object], whois_parser: WhoisParser) -> None:
    raw_text = (NINO_FIXTURES / fixture).read_text(encoding="utf-8")
    parsed = whois_parser.parse(raw_text, domain=domain)

    for field, expected in expectations.items():
        assert field in parsed, f"Field '{field}' was not produced"
        if field == "status":
            actual_statuses = parsed.get(field, [])
            assert all(any(exp in value for value in actual_statuses) for exp in expected)
        elif isinstance(expected, list):
            assert parsed[field][: len(expected)] == expected
        else:
            assert parsed[field] == expected


RICHARD_SAMPLE_DOMAINS = ["google.com", "microsoft.com", "reddit.com"]


def _coerce_list(value: object) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [str(v) for v in value]
    return [str(value)]


@pytest.mark.parametrize("domain", RICHARD_SAMPLE_DOMAINS)
def test_results_align_with_richard_snapshots(domain: str, whois_parser: WhoisParser) -> None:
    raw_text = (RICHARD_WHOIS / domain).read_text(encoding="utf-8")
    expected = json.loads((RICHARD_EXPECTED / domain).read_text(encoding="utf-8"))
    parsed = whois_parser.parse(raw_text, domain=domain)

    expected_domain = expected.get("domain_name")
    if expected_domain:
        assert parsed.get("domain_name", "").upper() == expected_domain.upper()

    expected_statuses = _coerce_list(expected.get("status"))
    actual_statuses = parsed.get("status") or []
    if expected_statuses and actual_statuses:
        actual_lower = [value.lower() for value in actual_statuses]
        for status in expected_statuses:
            token = status.lower().split()[0]
            assert any(token in candidate for candidate in actual_lower)
