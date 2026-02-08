from __future__ import annotations

import ast
from typing import Any

import pytest

from structly_whois import WhoisParser
from structly_whois.parser import NormalizerPluginError, _effective_tld_for_domain
from tests.common.sample_utils import EXPECTED_ROOT, SKIPPED_SAMPLES, WHOIS_ROOT


def test_fr_sample_exposes_contact_fields() -> None:
    parser = WhoisParser(preload_tlds=("fr",))
    sample = WHOIS_ROOT / "airfrance.fr.txt"
    raw_text = sample.read_text(encoding="utf-8", errors="ignore")

    parsed = parser.parse(raw_text, domain="airfrance.fr")

    assert parsed["registrant_organization"] == "Air France"
    assert parsed["admin_name"] == "Fabienne Castelli-Maudoux"
    assert parsed["tech_email"] == "afnic@meyer-partenaires.com"


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


def test_effective_tld_prefers_longest_suffix() -> None:
    overrides = {"com", "com.br", "net"}

    assert _effective_tld_for_domain("google.com.br", overrides) == "com.br"
    assert _effective_tld_for_domain("example.net", overrides) == "net"
    assert _effective_tld_for_domain("example.unknown", overrides) == "unknown"


def test_apply_domain_hint_overrides_when_domain_matches_tld() -> None:
    parser = WhoisParser(preload_tlds=("info",))
    parsed = {"domain_name": "info"}

    parser._apply_domain_hint(parsed, domain_hint="Example.info", target_tld="info")  # type: ignore[attr-defined]

    assert parsed["domain_name"] == "Example.info"


def test_finalize_parsed_sequence_materializes_when_requested() -> None:
    parser = WhoisParser(preload_tlds=("com",))
    payloads = [{"domain_name": "example.com"}]
    generator = (entry for entry in payloads)
    normalized = ["Domain Name: example.com\n"]

    materialized = parser._finalize_parsed_sequence(  # type: ignore[attr-defined]
        generator,
        normalized_payloads=normalized,
        target_tld="com",
        domain_hints=None,
        domain_hint_for_selection=None,
        to_records=False,
        lowercase=False,
        date_parser=None,
        raw_payloads=None,
        materialize=True,
    )

    assert isinstance(materialized, list)
    assert materialized[0]["domain_name"] == "example.com"


def test_prepare_domain_inputs_counts_unique_suffixes() -> None:
    parser = WhoisParser(preload_tlds=())

    result = parser._prepare_domain_inputs(["google.com", "google.com.br"])  # type: ignore[attr-defined]

    assert result.effective_tlds == ["com", "com.br"]
    assert result.unique_tld_count == 2


def test_prepare_tld_inputs_flattens_uniform_sequence() -> None:
    parser = WhoisParser(preload_tlds=())

    inputs = parser._prepare_tld_inputs(["com", "com"])  # type: ignore[attr-defined]

    assert inputs.per_row is None
    assert inputs.selection_hint == "com"
    assert inputs.unique_tld_count == 1


def test_prepare_tld_inputs_tracks_multiple_labels() -> None:
    parser = WhoisParser(preload_tlds=())

    inputs = parser._prepare_tld_inputs(["com", "net"])  # type: ignore[attr-defined]

    assert inputs.per_row == ["com", "net"]
    assert inputs.unique_tld_count == 2
    assert inputs.allow_domain_grouping is False


def test_enable_plugins_raises_on_entry_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    class BrokenEntry:
        name = "broken"

        def load(self) -> None:
            raise RuntimeError("boom")

    class StubEntries:
        def select(self, *, group: str) -> list[BrokenEntry]:
            assert group == "structly_whois.normalizers"
            return [BrokenEntry()]

    monkeypatch.setattr("structly_whois.parser.metadata.entry_points", lambda: StubEntries())

    with pytest.raises(NormalizerPluginError):
        WhoisParser(enable_plugins=True)


def test_enable_plugins_registers_text_normalizer(monkeypatch: pytest.MonkeyPatch) -> None:
    registered: list[Any] = []

    def fake_register(normalizer: Any, priority: int = 0) -> None:
        registered.append((normalizer, priority))

    monkeypatch.setattr("structly_whois.parser.register_text_normalizer", fake_register)

    class DummyTextNormalizer:
        def applicable(self, raw_text: str, tld: str | None, domain: str | None) -> bool:
            return True

        def normalize(self, raw_text: str, tld: str | None, domain: str | None) -> str:
            return raw_text

    class StubEntry:
        name = "dummy"

        def load(self) -> DummyTextNormalizer:
            return DummyTextNormalizer()

    class StubEntries:
        def select(self, *, group: str) -> list[StubEntry]:
            assert group == "structly_whois.normalizers"
            return [StubEntry()]

    monkeypatch.setattr("structly_whois.parser.metadata.entry_points", lambda: StubEntries())
    WhoisParser(enable_plugins=True)

    assert len(registered) == 1
    assert isinstance(registered[0][0], DummyTextNormalizer)
