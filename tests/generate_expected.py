#!/usr/bin/env python3
"""Utility to (re)generate WHOIS expected fixtures from the parser output."""
from __future__ import annotations

import argparse
import pprint
import sys
from pathlib import Path
from typing import Iterable

from structly_whois_parser import WhoisParser

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from sample_utils import EXPECTED_ROOT, SKIPPED_SAMPLES, WHOIS_ROOT


def _iter_sample_domains(include_skipped: bool, only: set[str] | None) -> Iterable[str]:
    for path in sorted(WHOIS_ROOT.glob("*.txt")):
        domain = path.stem
        if only and domain not in only:
            continue
        if not include_skipped and domain in SKIPPED_SAMPLES:
            continue
        yield domain


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "domains",
        nargs="*",
        help="Optional sample stems to regenerate (defaults to all non-skipped samples).",
    )
    parser.add_argument(
        "--overwrite",
        action="store_true",
        help="Regenerate fixtures even when they already exist.",
    )
    parser.add_argument(
        "--include-skipped",
        action="store_true",
        help="Regenerate fixtures for the skipped samples as well.",
    )
    args = parser.parse_args()

    EXPECTED_ROOT.mkdir(parents=True, exist_ok=True)
    parser_engine = WhoisParser()
    targets = list(_iter_sample_domains(args.include_skipped, set(args.domains) or None))
    for domain in targets:
        sample_path = WHOIS_ROOT / f"{domain}.txt"
        expected_path = EXPECTED_ROOT / f"{domain}.txt"
        if expected_path.exists() and not args.overwrite:
            continue
        raw = sample_path.read_text(encoding="utf-8", errors="ignore")
        record = parser_engine.parse_record(raw, domain=domain).to_dict(include_raw_text=False)
        payload = pprint.pformat(record, width=120, sort_dicts=True)
        expected_path.write_text(f"{payload}\n", encoding="utf-8")
        print(f"Wrote fixture for {domain} -> {expected_path.relative_to(EXPECTED_ROOT.parent)}")


if __name__ == "__main__":
    main()
