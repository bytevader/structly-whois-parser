from __future__ import annotations

import argparse
import importlib
import json
import sys
from pathlib import Path

from .parser import DateParser, WhoisParser


def _load_date_parser(path: str) -> DateParser:
    module_path, _, attr = path.partition(":")
    if not module_path or not attr:
        raise ValueError("date parser must be specified as 'module:callable'")
    module = importlib.import_module(module_path)
    func = getattr(module, attr)
    if not callable(func):
        raise TypeError(f"{path} is not callable")
    return func


def _read_payload(path: str) -> str:
    if path == "-":
        return sys.stdin.read()
    return Path(path).read_text(encoding="utf-8", errors="ignore")


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="structly-whois", description="Parse WHOIS payloads using structly_whois.")
    parser.add_argument("payload", help="Path to the WHOIS payload or '-' for stdin.")
    parser.add_argument("--domain", help="Domain associated with the payload.")
    parser.add_argument("--tld", help="Force parsing with a specific TLD configuration.")
    parser.add_argument("--lowercase", action="store_true", help="Lowercase string fields in the result.")
    parser.add_argument("--record", action="store_true", help="Return a structured WhoisRecord instead of a mapping.")
    parser.add_argument(
        "--date-parser",
        help="Optional dotted path to a callable used for post-processing dates (module:function).",
    )
    parser.add_argument("--json", action="store_true", help="Emit JSON instead of repr output.")
    return parser


def main(argv: list[str] | None = None) -> int:
    cli = build_arg_parser()
    args = cli.parse_args(argv)

    date_parser: DateParser | None = None
    if args.date_parser:
        date_parser = _load_date_parser(args.date_parser)

    parser = WhoisParser(date_parser=date_parser)
    raw = _read_payload(args.payload)

    if args.record:
        record = parser.parse_record(raw, domain=args.domain, tld=args.tld, lowercase=args.lowercase)
        output = record.to_dict()
    else:
        output = parser.parse(raw, domain=args.domain, tld=args.tld)

    if args.json:
        print(json.dumps(output, default=str, indent=2))
    else:
        print(output)
    return 0


if __name__ == "__main__":  # pragma: no cover - CLI entry point
    raise SystemExit(main())
