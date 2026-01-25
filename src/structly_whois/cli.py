from __future__ import annotations

import argparse
import importlib
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from time import perf_counter

from .parser import DateParser, WhoisParser


@dataclass
class _PayloadSpec:
    raw_text: str
    domain: str | None
    tld: str | None
    lowercase: bool
    context: str


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


def _emit_error(message: str) -> None:
    print(message, file=sys.stderr)


def _iter_jsonl_payloads(
    source: str,
    *,
    default_domain: str | None,
    default_tld: str | None,
    default_lowercase: bool,
    fail_fast: bool,
    metrics: dict[str, int],
):
    label = "stdin" if source == "-" else source
    if source == "-":
        iterator = enumerate(sys.stdin, 1)
    else:

        def _line_iter():
            with open(source, encoding="utf-8", errors="ignore") as handle:
                yield from enumerate(handle, 1)

        iterator = _line_iter()

    for line_no, line in iterator:
        stripped = line.strip()
        if not stripped:
            continue
        metrics["processed"] += 1
        try:
            payload = json.loads(stripped)
        except json.JSONDecodeError as exc:
            msg = f"{label}:{line_no}: invalid JSON ({exc})"
            metrics["failed"] += 1
            if fail_fast:
                raise ValueError(msg) from exc
            _emit_error(msg)
            continue
        raw_text = payload.get("raw_text")
        if not isinstance(raw_text, str) or not raw_text.strip():
            msg = f"{label}:{line_no}: missing raw_text field"
            metrics["failed"] += 1
            if fail_fast:
                raise ValueError(msg)
            _emit_error(msg)
            continue
        lowercase = bool(payload.get("lowercase", default_lowercase))
        domain = payload.get("domain", default_domain)
        tld = payload.get("tld", default_tld)
        context = payload.get("id")
        context_label = f"{label}:{line_no}"
        if isinstance(context, str) and context:
            context_label = f"{context_label} ({context})"
        yield _PayloadSpec(
            raw_text=raw_text,
            domain=domain,
            tld=tld,
            lowercase=lowercase,
            context=context_label,
        )


def _iter_payloads(args: argparse.Namespace) -> list[_PayloadSpec] | None:
    if args.input_format == "jsonl":
        return None  # streaming handled separately
    raw = _read_payload(args.payload)
    return [
        _PayloadSpec(
            raw_text=raw,
            domain=args.domain,
            tld=args.tld,
            lowercase=args.lowercase,
            context=args.payload if args.payload != "-" else "stdin",
        )
    ]


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="structly-whois", description="Parse WHOIS payloads using structly_whois.")
    parser.add_argument("payload", nargs="?", default="-", help="Path to the WHOIS payload or '-' for stdin.")
    parser.add_argument("--domain", help="Domain associated with the payload.")
    parser.add_argument("--tld", help="Force parsing with a specific TLD configuration.")
    parser.add_argument("--lowercase", action="store_true", help="Lowercase string fields in the result.")
    parser.add_argument("--record", action="store_true", help="Return a structured WhoisRecord instead of a mapping.")
    parser.add_argument(
        "--input-format",
        choices=("text", "jsonl"),
        default="text",
        help="Treat payload as a raw WHOIS document (default) or newline-delimited JSON stream.",
    )
    parser.add_argument(
        "--date-parser",
        help="Optional dotted path to a callable used for post-processing dates (module:function).",
    )
    parser.add_argument("--json", action="store_true", help="Emit prettified JSON instead of repr output.")
    parser.add_argument("--jsonl", action="store_true", help="Emit newline-delimited JSON objects (one per payload).")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--fail-fast",
        dest="fail_fast",
        action="store_true",
        help="Abort on the first parsing error (default).",
    )
    mode.add_argument(
        "--best-effort",
        dest="fail_fast",
        action="store_false",
        help="Log errors and continue processing subsequent payloads.",
    )
    parser.set_defaults(fail_fast=True)
    parser.add_argument(
        "--metrics",
        action="store_true",
        help="Print a summary of processed/failed payloads to stderr after completion.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    cli = build_arg_parser()
    args = cli.parse_args(argv)

    if args.json and args.jsonl:
        cli.error("--json and --jsonl are mutually exclusive")

    date_parser: DateParser | None = None
    if args.date_parser:
        date_parser = _load_date_parser(args.date_parser)

    parser = WhoisParser(date_parser=date_parser)
    specs = _iter_payloads(args)
    metrics = {"processed": 0, "failed": 0}
    start = perf_counter()

    def _emit_output(result: dict | list | str) -> None:
        if args.jsonl:
            print(json.dumps(result, default=str))
        elif args.json:
            print(json.dumps(result, default=str, indent=2))
        else:
            print(result)

    def _parse_payload(item: _PayloadSpec) -> dict:
        if args.record:
            record = parser.parse_record(
                item.raw_text,
                domain=item.domain,
                tld=item.tld,
                lowercase=item.lowercase,
            )
            return record.to_dict()
        return parser.parse(item.raw_text, domain=item.domain, tld=item.tld)

    try:
        streaming = specs is None
        if not streaming:
            items = specs
        else:
            items = _iter_jsonl_payloads(
                args.payload,
                default_domain=args.domain,
                default_tld=args.tld,
                default_lowercase=args.lowercase,
                fail_fast=args.fail_fast,
                metrics=metrics,
            )
        for spec in items:
            if not streaming:
                metrics["processed"] += 1
            try:
                output = _parse_payload(spec)
            except Exception as exc:  # pragma: no cover - unexpected failures bubble by default
                metrics["failed"] += 1
                message = f"{spec.context}: {exc}"
                if args.fail_fast:
                    raise
                _emit_error(message)
                continue
            _emit_output(output)
    finally:
        duration = perf_counter() - start
        if args.metrics:
            succeeded = metrics["processed"] - metrics["failed"]
            rate = succeeded / duration if duration > 0 else 0.0
            _emit_error(
                f"Processed {metrics['processed']} payload(s); "
                f"{succeeded} succeeded / {metrics['failed']} failed in {duration:.2f}s "
                f"({rate:,.1f} payloads/s)."
            )
    if metrics["failed"] and not args.fail_fast:
        return 1
    return 0


if __name__ == "__main__":  # pragma: no cover - CLI entry point
    raise SystemExit(main())
