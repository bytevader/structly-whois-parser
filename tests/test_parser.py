import ast
from pprint import pprint

from structly_whois_parser import WhoisParser

from tests.sample_utils import EXPECTED_ROOT, SKIPPED_SAMPLES, WHOIS_ROOT


def _read_sample(domain: str) -> str:
    """Load a WHOIS sample payload."""
    path = WHOIS_ROOT / f"{domain}.txt"
    return path.read_text(encoding="utf-8", errors="ignore")

SIMPLE_WHOIS = """Domain Name: example.dev
Registrar: Example Registrar
Creation Date: 2020-01-01T00:00:00Z
Updated Date: 2020-02-01T00:00:00Z
Registry Expiry Date: 2025-01-01T00:00:00Z
Name Server: NS1.EXAMPLE.COM
Name Server: NS2.EXAMPLE.COM
Status: ok
Registrant Name: Example Inc
Registrant Email: contact@example.dev
"""


def test_parse_many_returns_mappings_by_default() -> None:
    parser = WhoisParser(preload_tlds=())

    result = parser.parse_many([SIMPLE_WHOIS])

    assert len(result) == 1
    assert isinstance(result[0], dict)
    assert result[0]["domain_name"] == "example.dev"


def test_parse_many_can_return_records() -> None:
    parser = WhoisParser(preload_tlds=())

    records = parser.parse_many([SIMPLE_WHOIS, SIMPLE_WHOIS], to_records=True, lowercase=True)

    assert len(records) == 2
    assert records[0].domain == "example.dev"
    assert records[0].name_servers == ["ns1.example.com", "ns2.example.com"]


def test_com_br_override_extracts_owner_fields() -> None:
    raw = _read_sample("google.com.br")
    parser = WhoisParser(preload_tlds=("com.br",))

    record = parser.parse_record(raw, domain="google.com.br")

    assert record.domain == "google.com.br"
    assert record.registrant.organization == "Google Brasil Internet Ltda"
    assert record.registrant.name == "Domain Administrator"
    assert record.name_servers[:2] == ["ns1.google.com", "ns2.google.com"]
    assert record.statuses == ["published"]

def test_com_br_override_extracts_owner_fields2() -> None:
    domain = "globo.com.br"
    raw = _read_sample(domain)
    try:
        expected = ast.literal_eval((EXPECTED_ROOT / f"{domain}.txt").read_text(encoding="utf-8"))
    except FileNotFoundError:
        expected = {}
    parser = WhoisParser()
    record = parser.parse_record(raw, domain=domain).to_dict(include_raw_text=False)
    print(record)
    pprint(record, indent=2)
    assert record == expected


def test_all_samples_match_expected() -> None:
    parser = WhoisParser()
    for sample_path in sorted(WHOIS_ROOT.glob("*.txt")):
        domain = sample_path.stem
        if domain in SKIPPED_SAMPLES:
            continue
        raw = sample_path.read_text(encoding="utf-8", errors="ignore")
        expected_path = EXPECTED_ROOT / f"{domain}.txt"
        assert expected_path.exists(), f"missing expected fixture for {domain}"
        expected = ast.literal_eval(expected_path.read_text(encoding="utf-8"))
        record = parser.parse_record(raw, domain=domain).to_dict(include_raw_text=False)
        assert record == expected, f"parsed WHOIS payload for {domain} does not match expected fixture"
