from __future__ import annotations

import ast

from structly_whois import WhoisParser, normalize_raw_text
from tests.common.sample_utils import EXPECTED_ROOT, SKIPPED_SAMPLES, WHOIS_ROOT


def test_normalize_raw_text_keeps_last_block() -> None:
    raw = (
        "Domain Name: FIRST-RESULT.COM\n"
        "# whois.server.one\n"
        "Domain Name: SHOULD-BE-DROPPED\n"
        "# whois.server.two\n"
        "Domain name:\n"
        "    example.co.uk\n"
    )
    normalized = normalize_raw_text(raw)

    assert "whois.server.one" not in normalized
    assert "# whois.server.two" not in normalized
    assert normalized.startswith("Domain name: example.co.uk")


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
        if domain.endswith(".info"):
            expected = dict(expected)
            expected["domain"] = domain
        assert record == expected, f"{domain} mismatch"
