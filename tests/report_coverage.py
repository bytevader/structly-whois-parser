#!/usr/bin/env python3
"""Generate per-TLD field coverage statistics for the WHOIS samples."""
from __future__ import annotations

import argparse
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Callable, Iterable

from structly_whois_parser import WhoisParser

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from tests.sample_utils import SKIPPED_SAMPLES, WHOIS_ROOT

FieldExtractor = Callable[[dict], bool]


FIELD_EXTRACTORS: dict[str, FieldExtractor] = {
    "domain": lambda record: bool(record.get("domain")),
    "registrar": lambda record: bool(record.get("registrar")),
    "registrar_id": lambda record: bool(record.get("registrar_id")),
    "registrar_url": lambda record: bool(record.get("registrar_url")),
    "dnssec": lambda record: bool(record.get("dnssec")),
    "registered_at": lambda record: bool(record.get("registered_at")),
    "updated_at": lambda record: bool(record.get("updated_at")),
    "expires_at": lambda record: bool(record.get("expires_at")),
    "statuses": lambda record: bool(record.get("statuses")),
    "name_servers": lambda record: bool(record.get("name_servers")),
    "registrant.name": lambda record: bool(record["registrant"]["name"]),
    "registrant.organization": lambda record: bool(record["registrant"]["organization"]),
    "registrant.email": lambda record: bool(record["registrant"]["email"]),
    "registrant.telephone": lambda record: bool(record["registrant"]["telephone"]),
    "admin.name": lambda record: bool(record["admin"]["name"]),
    "admin.organization": lambda record: bool(record["admin"]["organization"]),
    "admin.email": lambda record: bool(record["admin"]["email"]),
    "admin.telephone": lambda record: bool(record["admin"]["telephone"]),
    "tech.name": lambda record: bool(record["tech"]["name"]),
    "tech.organization": lambda record: bool(record["tech"]["organization"]),
    "tech.email": lambda record: bool(record["tech"]["email"]),
    "tech.telephone": lambda record: bool(record["tech"]["telephone"]),
    "abuse.email": lambda record: bool(record["abuse"]["email"]),
    "abuse.telephone": lambda record: bool(record["abuse"]["telephone"]),
}


def _iter_samples(include_skipped: bool, only: set[str] | None) -> Iterable[str]:
    for sample_path in sorted(WHOIS_ROOT.glob("*.txt")):
        domain = sample_path.stem
        if only and domain not in only:
            continue
        if not include_skipped and domain in SKIPPED_SAMPLES:
            continue
        yield domain


def format_percentage(value: float) -> str:
    return f"{value * 100:.1f}%"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--domains",
        nargs="*",
        help="Limit the report to specific sample stems.",
    )
    parser.add_argument(
        "--include-skipped",
        action="store_true",
        help="Include the skipped samples in the report.",
    )
    args = parser.parse_args()

    parser_engine = WhoisParser()
    totals: dict[str, int] = Counter()
    hits: dict[str, Counter[str]] = defaultdict(Counter)
    only = set(args.domains) if args.domains else None
    for domain in _iter_samples(args.include_skipped, only):
        raw = (WHOIS_ROOT / f"{domain}.txt").read_text(encoding="utf-8", errors="ignore")
        record = parser_engine.parse_record(raw, domain=domain).to_dict(include_raw_text=False)
        tld = parser_engine._select_tld(None, domain) or "<default>"  # type: ignore[attr-defined]
        totals[tld] += 1
        for field, extractor in FIELD_EXTRACTORS.items():
            if extractor(record):
                hits[tld][field] += 1

    field_names = tuple(FIELD_EXTRACTORS.keys())
    for tld in sorted(totals, key=lambda key: (-totals[key], key)):
        total = totals[tld]
        print(f"{tld or '<unknown>'}: {total} samples")
        field_line = []
        overall = 0.0
        for field in field_names:
            ratio = hits[tld][field] / total
            overall += ratio
            field_line.append(f"{field}={format_percentage(ratio)}")
        overall /= len(field_names)
        print(f"  overall={format_percentage(overall)}")
        print("  " + ", ".join(field_line))


if __name__ == "__main__":
    main()
