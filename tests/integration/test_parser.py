import ast
from collections import defaultdict
from collections.abc import Iterable
from datetime import datetime

import pytest
from structly import FieldPattern

from structly_whois import WhoisParser
from structly_whois import domain_inference as domain_mod
from structly_whois.normalization import normalize_raw_text
from tests.common.sample_utils import EXPECTED_ROOT, SKIPPED_SAMPLES, WHOIS_ROOT


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

INFO_WHOIS = """Domain Name: INFO
Registrar: Example Registrar
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


def test_parser_supported_tlds_skip_empty_labels() -> None:
    parser = WhoisParser(preload_tlds=("com", "", "info"))

    assert parser.supported_tlds == ("com", "info")


def test_parser_default_date_parser_property() -> None:
    def _hook(value: str) -> datetime:
        return datetime.fromisoformat(value)

    parser = WhoisParser(preload_tlds=(), date_parser=_hook)

    assert parser.default_date_parser is _hook


def test_parse_record_prefers_domain_hint_for_info_tld() -> None:
    parser = WhoisParser(preload_tlds=("info",))

    record = parser.parse_record(INFO_WHOIS, domain="example.info")

    assert record.domain == "example.info"


def test_parser_accepts_extra_tld_overrides() -> None:
    overrides = {
        "demo": {
            "domain_name": {
                "patterns": [FieldPattern.regex(r"(?i)^demo:\s*(?P<val>[a-z0-9._-]+)$")],
            }
        }
    }
    parser = WhoisParser(preload_tlds=(), extra_tld_overrides=overrides)

    result = parser.parse("Demo: custom.demo", tld="demo")

    assert result["domain_name"] == "custom.demo"


def test_apply_domain_hint_preserves_existing_domain() -> None:
    parser = WhoisParser(preload_tlds=("info",))
    parsed = {"domain_name": "actual.info"}

    parser._apply_domain_hint(parsed, domain_hint="example.info", target_tld="info")

    assert parsed["domain_name"] == "actual.info"


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
        if domain.endswith(".info"):
            expected = dict(expected)
            expected["domain"] = domain
        assert record == expected, f"parsed WHOIS payload for {domain} does not match expected fixture"


@pytest.mark.parametrize(
    "domain",
    [
        "abc.xyz",  # base patterns
        "google.com.br",
        "rakuten.co.jp",
        "nav.no",
        "samsung.co.kr",
        "belgium.be",
        "airfrance.fr",
        "allegro.pl",
        "banamex.com.mx",
        "bbc.co.uk",
    ],
)
def test_parse_record_infers_domain_when_missing(domain: str) -> None:
    parser = WhoisParser()
    raw = (WHOIS_ROOT / f"{domain}.txt").read_text(encoding="utf-8", errors="ignore")
    expected = ast.literal_eval((EXPECTED_ROOT / f"{domain}.txt").read_text(encoding="utf-8"))

    record = parser.parse_record(raw).to_dict(include_raw_text=False)

    assert record == expected


def test_parse_many_matches_expected_samples() -> None:
    parser = WhoisParser()
    batches: dict[str, list[tuple[str, str]]] = defaultdict(list)
    for sample_path in sorted(WHOIS_ROOT.glob("*.txt")):
        domain = sample_path.stem
        if domain in SKIPPED_SAMPLES:
            continue
        batches[parser._select_tld(None, domain)].append(  # type: ignore[attr-defined]
            (domain, sample_path.read_text(encoding="utf-8", errors="ignore"))
        )

    for tld, entries in batches.items():
        payloads = [raw for _, raw in entries]
        records = parser.parse_many(payloads, tld=tld or None, to_records=True)
        assert len(records) == len(entries)
        for (domain, _), record in zip(entries, records):
            expected_path = EXPECTED_ROOT / f"{domain}.txt"
            expected = ast.literal_eval(expected_path.read_text(encoding="utf-8"))
            assert record.to_dict(include_raw_text=False) == expected, domain


def test_parse_many_applies_domain_hint_for_info_domains() -> None:
    parser = WhoisParser(preload_tlds=("info",))

    parsed = parser.parse_many([INFO_WHOIS], domain="example.info", tld="info")

    assert parsed[0]["domain_name"] == "example.info"


def test_parse_many_to_records_applies_domain_hint() -> None:
    parser = WhoisParser(preload_tlds=("info",))

    records = parser.parse_many([INFO_WHOIS], domain="example.info", tld="info", to_records=True)

    assert records[0].domain == "example.info"


def test_parse_chunks_apply_domain_hint_for_info_domains() -> None:
    parser = WhoisParser(preload_tlds=("info",))
    chunks = list(parser.parse_chunks([INFO_WHOIS], domain="example.info", tld="info", chunk_size=1))

    assert chunks
    assert chunks[0][0]["domain_name"] == "example.info"


def test_register_tld_requires_label() -> None:
    parser = WhoisParser(preload_tlds=())
    with pytest.raises(ValueError):
        parser.register_tld("", {})


def test_register_tld_preload_false_drops_cached_parser() -> None:
    parser = WhoisParser(preload_tlds=("dev",))
    overrides = {
        "domain_name": {
            "patterns": [FieldPattern.regex(r"(?i)^domain:\s*(?P<val>.+)$")],
        }
    }
    parser.register_tld("dev", overrides, preload=True)
    assert "dev" in parser._parsers  # type: ignore[attr-defined]
    parser.register_tld("dev", overrides, preload=False)
    assert "dev" not in parser._parsers  # type: ignore[attr-defined]


def test_parse_many_detects_mismatched_results(monkeypatch: pytest.MonkeyPatch) -> None:
    parser = WhoisParser(preload_tlds=("com",))

    class StubStructly:
        def parse_many(self, iterable: Iterable[str]) -> list[dict[str, str]]:
            list(iterable)
            return [{}]

    monkeypatch.setattr(parser, "_get_parser_for_tld", lambda _: StubStructly())  # type: ignore[attr-defined]
    with pytest.raises(RuntimeError):
        parser.parse_many([SIMPLE_WHOIS, SIMPLE_WHOIS], tld="com", to_records=True)


def test_infer_domain_from_text_uses_regex() -> None:
    text = "Domain Name: Example.com\n"
    assert domain_mod.infer_domain_from_text(text) == "Example.com"


def test_infer_domain_from_text_fallback_to_prefix(monkeypatch: pytest.MonkeyPatch) -> None:
    registry = domain_mod.get_domain_registry()
    monkeypatch.setattr(registry, "regexes", ())
    monkeypatch.setattr(registry, "prefixes", ("Domain Name:",))
    text = "Domain Name: fallback.example\n"
    assert domain_mod.infer_domain_from_text(text) == "fallback.example"


def test_infer_domain_prefers_domain_label_over_nameservers() -> None:
    raw = _read_sample("belgium.be")
    normalized = normalize_raw_text(raw)

    assert domain_mod.infer_domain_from_text(normalized) == "belgium.be"


def test_parse_record_marks_rate_limited(sample_payloads: dict[str, str]) -> None:
    parser = WhoisParser(preload_tlds=())

    record = parser.parse_record(sample_payloads["rate_limited"], domain="example.com")

    assert record.is_rate_limited is True
    assert record.statuses == []


def test_parse_record_uses_date_parser_hook(sample_payloads: dict[str, str]) -> None:
    def _parser(value: str) -> datetime:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))

    parser = WhoisParser(preload_tlds=("com",), date_parser=_parser)

    record = parser.parse_record(sample_payloads["com"], domain="example.com")

    assert isinstance(record.registered_at, datetime)
    assert record.registered_at.tzinfo is not None


def test_parse_chunks_yields_expected_batch_sizes(sample_payloads: dict[str, str]) -> None:
    parser = WhoisParser(preload_tlds=("com",))
    payloads = [sample_payloads["com"]] * 5

    chunks = list(parser.parse_chunks(payloads, domain="example.com", chunk_size=2))

    assert len(chunks) == 3
    assert [len(chunk) for chunk in chunks] == [2, 2, 1]
