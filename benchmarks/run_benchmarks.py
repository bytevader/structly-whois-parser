from __future__ import annotations

import argparse
import importlib
import sys
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from pathlib import Path
from types import ModuleType

from dateparser import parse as dateparser_parse
from dateutil import parser as dateutil_parser

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = PROJECT_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))
if str(PROJECT_ROOT) not in sys.path:
    sys.path.append(str(PROJECT_ROOT))

DEFAULT_OUTPUT = PROJECT_ROOT / "benchmarks" / "results.md"
ITERATIONS_DEFAULT = 10
from tests.common.sample_utils import SKIPPED_SAMPLES, WHOIS_ROOT  # noqa: E402

_STRUCTLY_MODULE: ModuleType | None = None


def _structly_module() -> ModuleType:
    """Load the local structly_whois package, evicting any installed version once."""
    global _STRUCTLY_MODULE
    if _STRUCTLY_MODULE is None:
        for key in list(sys.modules):
            if key == "structly_whois" or key.startswith("structly_whois."):
                sys.modules.pop(key)
        _STRUCTLY_MODULE = importlib.import_module("structly_whois")
    return _STRUCTLY_MODULE


ParseFunc = Callable[[str, str], object]
BatchFunc = Callable[[Iterable[str], list[str]], list[object]]


@dataclass(frozen=True)
class BackendSpec:
    loader: Callable[[], ParseFunc | BatchFunc]
    is_batch: bool = False


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


def _structly_parse_record_factory(*, date_parser: Callable[[str], object] | None = None) -> ParseFunc:
    module = _structly_module()
    parser = module.WhoisParser(date_parser=date_parser)

    def _parse(text: str, domain: str) -> object:
        return parser.parse_record(text, domain=domain, lowercase=True)

    return _parse


def _structly_parse_many_factory() -> BatchFunc:
    module = _structly_module()
    parser = module.WhoisParser()

    def _parse_batch(texts: Iterable[str], domains: list[str]) -> list[object]:
        return parser.parse_many(texts, domain=domains, to_records=True)

    return _parse_batch


def _materialize_batch_inputs(payloads: list[tuple[str, str]]) -> tuple[list[str], list[str]]:
    texts = [text for _, text in payloads]
    domains = [domain for domain, _ in payloads]
    return texts, domains


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


BACKENDS: dict[str, BackendSpec] = {
    "structly-whois": BackendSpec(loader=_structly_parse_record_factory),
    "structly-whois+dateutil": BackendSpec(
        loader=lambda: _structly_parse_record_factory(date_parser=dateutil_parser.parse)
    ),
    "structly-whois+dateparser": BackendSpec(
        loader=lambda: _structly_parse_record_factory(date_parser=dateparser_parse)
    ),
    "structly-whois.parse_many": BackendSpec(loader=_structly_parse_many_factory, is_batch=True),
    "whois-parser": BackendSpec(loader=_load_whois_parser_backend),
    "python-whois": BackendSpec(loader=_load_python_whois_backend),
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


def run_batch_backend(
    name: str,
    parser_fn: BatchFunc,
    batch_inputs: tuple[list[str], list[str]],
    iterations: int,
) -> BenchmarkResult:
    texts, domains = batch_inputs
    start = time.perf_counter()
    for _ in range(iterations):
        parser_fn(texts, domains)
    elapsed = time.perf_counter() - start
    total_records = len(texts) * iterations
    return BenchmarkResult(
        backend=name,
        iterations=iterations,
        records=total_records,
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
        default="structly-whois,structly-whois.parse_many,structly-whois+dateutil,structly-whois+dateparser,whois-parser,python-whois",
        help="Comma-separated list of backends to run.",
    )
    parser.add_argument(
        "--domains",
        nargs="*",
        help="Optional domain sample stems (omit or pass 'all' to cover every fixture).",
    )
    parser.add_argument(
        "--include-skipped",
        action="store_true",
        help="Include privacy-blocked or truncated fixtures normally skipped by tests.",
    )
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT, help="Markdown summary destination.")
    parser.add_argument(
        "--save-result",
        action="store_true",
        help="Persist the Markdown summary to --output (defaults to console-only).",
    )
    args = parser.parse_args(argv)

    if args.domains:
        domain_filter = None if len(args.domains) == 1 and args.domains[0].lower() == "all" else set(args.domains)
    else:
        domain_filter = None
    payloads = _load_payloads(domains=domain_filter, include_skipped=args.include_skipped)
    batch_inputs = _materialize_batch_inputs(payloads)
    requested = [name.strip() for name in args.backends.split(",") if name.strip()]

    results: list[BenchmarkResult] = []
    for name in requested:
        spec = BACKENDS.get(name)
        if not spec:
            print(f"[skip] unknown backend '{name}'", file=sys.stderr)
            continue
        try:
            target = spec.loader()
        except ImportError:
            print(f"[skip] backend '{name}' not installed", file=sys.stderr)
            continue
        if spec.is_batch:
            result = run_batch_backend(name, target, batch_inputs, args.iterations)  # type: ignore[arg-type]
        else:
            result = run_backend(name, target, payloads, args.iterations)  # type: ignore[arg-type]
        results.append(result)

    if not results:
        print("No benchmarks were executed.", file=sys.stderr)
        return 1

    table = format_table(results)
    best = max(results, key=lambda r: r.records_per_second)
    print(table)
    if args.save_result:
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
