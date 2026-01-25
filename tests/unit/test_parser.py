from __future__ import annotations

import ast

import pytest

from structly_whois import WhoisParser
from tests.common.sample_utils import EXPECTED_ROOT, SKIPPED_SAMPLES, WHOIS_ROOT


def test_all_samples_match_expected_records() -> None:
    parser = WhoisParser()
    for sample_path in sorted(WHOIS_ROOT.glob("*.txt")):
        domain = sample_path.stem
        if domain in SKIPPED_SAMPLES:
            continue

        expected_path = EXPECTED_ROOT / f"{domain}.txt"
        raw_text = sample_path.read_text(encoding="utf-8", errors="ignore")
        expected = ast.literal_eval(expected_path.read_text(encoding="utf-8"))

        record = parser.parse_record(raw_text, domain=domain).to_dict(include_raw_text=False)
        if domain.endswith((".info", ".co.za", ".za", ".live", ".jobs")):
            expected = dict(expected)
            expected["domain"] = domain
        assert record == expected, f"{domain} mismatch"


def test_apply_domain_hint_skips_blank_values() -> None:
    parser = WhoisParser(preload_tlds=("info",))
    parsed: dict[str, str] = {}

    parser._apply_domain_hint(parsed, domain_hint="   ", target_tld="info")

    assert parsed == {}


def test_parse_returns_default_when_inference_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    parser = WhoisParser(preload_tlds=())
    monkeypatch.setattr("structly_whois.parser.infer_domain_from_text", lambda _: None)

    class StubParser:
        def parse(self, _: str) -> dict[str, str]:
            return {"domain_name": "", "registrar": "Example Registrar"}

    parser._default = StubParser()  # type: ignore[assignment]

    result = parser.parse("No domain markers anywhere")

    assert result == {"domain_name": "", "registrar": "Example Registrar"}


def test_parse_many_validates_domain_hint_length() -> None:
    parser = WhoisParser(preload_tlds=("info",))
    payloads = ["Domain Name: INFO"]

    with pytest.raises(ValueError):
        parser.parse_many(payloads, domain=["example.info", "extra.info"], tld="info")
