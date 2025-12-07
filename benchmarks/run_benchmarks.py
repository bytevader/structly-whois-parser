from __future__ import annotations

import argparse
import importlib
import sys
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from dateparser import parse as dateparser_parse
from dateutil import parser as dateutil_parser

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

DEFAULT_OUTPUT = PROJECT_ROOT / "benchmarks" / "results.md"
ITERATIONS_DEFAULT = 100
DEFAULT_BENCHMARK_DOMAINS = ("google.com", "google.ai", "google.at", "google.com.br", "google.com.pe")

from tests.sample_utils import SKIPPED_SAMPLES, WHOIS_ROOT  # noqa: E402

ParseFunc = Callable[[str, str], object]


@dataclass
class BenchmarkResult:
    backend: str
    iterations: int
    records: int
    elapsed: float

    @property
    def records_per_second(self) -> float:
        return self.records / self.elapsed if self.elapsed else 0.0

    @property
    def latency_ms(self) -> float:
        return (self.elapsed / self.records) * 1000 if self.records else 0.0


def _load_payloads(*, domains: set[str] | None, include_skipped: bool) -> list[tuple[str, str]]:
    payloads: list[tuple[str, str]] = []
    for path in sorted(WHOIS_ROOT.glob("*.txt")):
        domain = path.stem
        if domains and domain not in domains:
            continue
        if not include_skipped and domain in SKIPPED_SAMPLES:
            continue
        payloads.append((domain, path.read_text(encoding="utf-8", errors="ignore")))
    if not payloads:
        raise FileNotFoundError("No WHOIS samples were discovered under tests/samples/whois")
    return payloads


def _load_structly() -> ParseFunc:
    from structly_whois import WhoisParser

    parser = WhoisParser()
    return lambda text, domain: parser.parse_record(text, domain=domain, lowercase=True)


def _load_structly_with_dateutil() -> ParseFunc:
    from structly_whois import WhoisParser

    parser = WhoisParser(date_parser=dateutil_parser.parse)
    return lambda text, domain: parser.parse_record(text, domain=domain, lowercase=True)


def _load_structly_with_dateparser() -> ParseFunc:
    from structly_whois import WhoisParser

    parser = WhoisParser(date_parser=dateparser_parse)
    return lambda text, domain: parser.parse_record(text, domain=domain, lowercase=True)


def _load_whois_parser_backend() -> ParseFunc:
    try:
        module = importlib.import_module("whois_parser")
    except ImportError as exc:
        raise ImportError("whois-parser backend is unavailable (install whois-parser)") from exc
    parser_cls = getattr(module, "WhoisParser", None)
    if parser_cls is None or not hasattr(parser_cls, "parse"):
        raise ImportError("whois-parser backend missing WhoisParser.parse")
    parser = parser_cls()

    def _parse(text: str, domain: str) -> object:
        return parser.parse(text, hostname=domain)

    return _parse


def _load_python_whois_backend() -> ParseFunc:
    try:
        exceptions_mod = importlib.import_module("whois.exceptions")
    except ImportError as exc:
        raise ImportError("python-whois backend is unavailable (pip install python-whois)") from exc
    base_exc = getattr(exceptions_mod, "WhoisException", Exception)
    for missing in ("WhoisDomainNotFoundError", "WhoisUnknownDateFormatError"):
        if not hasattr(exceptions_mod, missing):
            placeholder = type(missing, (base_exc,), {})
            setattr(exceptions_mod, missing, placeholder)
    try:
        parser_mod = importlib.import_module("whois.parser")
    except ImportError as exc:
        raise ImportError("python-whois backend missing parser module") from exc
    entry_cls = getattr(parser_mod, "WhoisEntry", None)
    if entry_cls is None or not hasattr(entry_cls, "load"):
        raise ImportError("python-whois backend missing WhoisEntry.load")

    def _parse(text: str, domain: str) -> object:
        try:
            return entry_cls.load(domain, text)
        except Exception:
            return None

    return _parse


BACKENDS: dict[str, Callable[[], ParseFunc]] = {
    "structly-whois": _load_structly,
    "structly-whois+dateutil": _load_structly_with_dateutil,
    "structly-whois+dateparser": _load_structly_with_dateparser,
    "whois-parser": _load_whois_parser_backend,
    "python-whois": _load_python_whois_backend,
}


def run_backend(name: str, parser_fn: ParseFunc, payloads: list[tuple[str, str]], iterations: int) -> BenchmarkResult:
    start = time.perf_counter()
    count = 0
    for _ in range(iterations):
        for domain, text in payloads:
            parser_fn(text, domain)
            count += 1
    elapsed = time.perf_counter() - start
    return BenchmarkResult(
        backend=name,
        iterations=iterations,
        records=count,
        elapsed=elapsed,
    )


def format_table(results: list[BenchmarkResult]) -> str:
    headers = ("backend", "records", "records/s", "avg latency (ms)")
    rows = [
        (
            result.backend,
            f"{result.records}",
            f"{result.records_per_second:,.0f}",
            f"{result.latency_ms:.3f}",
        )
        for result in results
    ]
    try:
        from tabulate import tabulate

        return tabulate(rows, headers=headers, tablefmt="github")
    except Exception:  # pragma: no cover - tabulate optional
        header_line = " | ".join(headers)
        divider = "-+-".join("-" * len(header) for header in headers)
        body = "\n".join(" | ".join(row) for row in rows)
        return f"{header_line}\n{divider}\n{body}"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Benchmark WHOIS parser throughput across bundled samples.")
    parser.add_argument("--iterations", type=int, default=ITERATIONS_DEFAULT, help="Parse iterations per sample.")
    parser.add_argument(
        "--backends",
        default="structly-whois,structly-whois+dateutil,structly-whois+dateparser,whois-parser,python-whois",
        help="Comma-separated list of backends to run.",
    )
    parser.add_argument(
        "--domains",
        nargs="*",
        help="Optional domain sample stems (defaults to a curated subset; pass 'all' to cover every fixture).",
    )
    parser.add_argument(
        "--include-skipped",
        action="store_true",
        help="Include privacy-blocked or truncated fixtures normally skipped by tests.",
    )
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT, help="Markdown summary destination.")
    args = parser.parse_args(argv)

    if args.domains:
        domain_filter = None if len(args.domains) == 1 and args.domains[0].lower() == "all" else set(args.domains)
    else:
        domain_filter = set(DEFAULT_BENCHMARK_DOMAINS)
    payloads = _load_payloads(domains=domain_filter, include_skipped=args.include_skipped)
    requested = [name.strip() for name in args.backends.split(",") if name.strip()]

    results: list[BenchmarkResult] = []
    for name in requested:
        loader = BACKENDS.get(name)
        if not loader:
            print(f"[skip] unknown backend '{name}'", file=sys.stderr)
            continue
        try:
            parse_fn = loader()
        except ImportError:
            print(f"[skip] backend '{name}' not installed", file=sys.stderr)
            continue
        result = run_backend(name, parse_fn, payloads, args.iterations)
        results.append(result)

    if not results:
        print("No benchmarks were executed.", file=sys.stderr)
        return 1

    table = format_table(results)
    best = max(results, key=lambda r: r.records_per_second)
    print(table)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    summary = (
        "# Benchmark Results\n\n"
        f"- samples: {len(payloads)}\n"
        f"- iterations per sample: {results[0].iterations}\n\n"
        f"{table}\n\n"
        f"Leader: {best.backend} ({best.records_per_second:,.0f} records/s, "
        f"{best.latency_ms:.3f} ms per record)\n"
    )
    args.output.write_text(summary, encoding="utf-8")
    return 0


if __name__ == "__main__":  # pragma: no cover - script entry point
    raise SystemExit(main())
