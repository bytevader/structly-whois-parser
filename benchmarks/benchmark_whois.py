"""Benchmark parsing throughput across WHOIS fixtures."""
from __future__ import annotations

import argparse
import resource
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from structly_whois_parser import WhoisParser

PROJECT_ROOT = Path(__file__).resolve().parents[1]
WHOIS_SAMPLES = PROJECT_ROOT / "tests" / "samples" / "whois"


@dataclass
class BenchmarkResult:
    name: str
    iterations: int
    records: int
    elapsed: float
    records_per_second: float
    cpu_user: float
    cpu_system: float
    rss_delta_kb: float
    rss_peak_kb: float


def _iter_sample_files(files: Iterable[str] | None) -> list[Path]:
    if files:
        selected = [WHOIS_SAMPLES / name for name in files]
    else:
        selected = sorted(p for p in WHOIS_SAMPLES.iterdir() if p.is_file())
    missing = [p for p in selected if not p.exists()]
    if missing:
        joined = ", ".join(str(p) for p in missing)
        raise FileNotFoundError(f"Missing WHOIS samples: {joined}")
    return selected


def benchmark_file(
    parser: WhoisParser,
    path: Path,
    iterations: int,
    method: str,
    batch_size: int,
    record_to_dict: bool,
    parse_many_to_records: bool,
) -> BenchmarkResult:
    raw_text = path.read_text(encoding="utf-8", errors="ignore")
    domain = path.name

    batch = [raw_text] * batch_size if batch_size > 1 else [raw_text]
    total_records = 0

    start_usage = resource.getrusage(resource.RUSAGE_SELF)
    start_time = time.perf_counter()

    for _ in range(iterations):
        if method == "parse":
            parser.parse_record(raw_text, domain=domain)
            total_records += 1
        elif method == "parse_record":
            record = parser.parse_record(raw_text, domain=domain)
            if record_to_dict:
                record.to_dict(include_raw_text=False)
            total_records += 1
        elif method == "parse_many":
            results = parser.parse_many(batch, domain=domain, to_records=parse_many_to_records)
            if record_to_dict and parse_many_to_records:
                for record in results:
                    record.to_dict(include_raw_text=False)
            total_records += len(results)
        elif method == "parse_chunks":
            for _ in parser.parse_chunks(batch, domain=domain, chunk_size=batch_size):
                pass
            total_records += len(batch)
        else:
            raise ValueError(f"Unknown benchmark method '{method}'")

    elapsed = time.perf_counter() - start_time
    end_usage = resource.getrusage(resource.RUSAGE_SELF)

    cpu_user = end_usage.ru_utime - start_usage.ru_utime
    cpu_system = end_usage.ru_stime - start_usage.ru_stime
    rss_delta = max(0, end_usage.ru_maxrss - start_usage.ru_maxrss)
    rps = total_records / elapsed if elapsed else float("inf")

    return BenchmarkResult(
        name=domain,
        iterations=iterations,
        records=total_records,
        elapsed=elapsed,
        records_per_second=rps,
        cpu_user=cpu_user,
        cpu_system=cpu_system,
        rss_delta_kb=rss_delta,
        rss_peak_kb=end_usage.ru_maxrss,
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Benchmark structly WHOIS parser throughput.")
    parser.add_argument(
        "-i",
        "--iterations",
        type=int,
        default=1000,
        help="Number of parse iterations per file (default: 1000).",
    )
    parser.add_argument(
        "-m",
        "--method",
        choices=("parse", "parse_record", "parse_many", "parse_chunks"),
        default="parse",
        help="Which Structly parser API to benchmark (default: parse).",
    )
    parser.add_argument(
        "-b",
        "--batch-size",
        type=int,
        default=1,
        help="Number of duplicated records per iteration for parse_many/parse_chunks (default: 1).",
    )
    parser.add_argument(
        "--parse-many-to-records",
        action="store_true",
        help="When benchmarking parse_many, convert results into WhoisRecord objects.",
    )
    parser.add_argument(
        "--record-to-dict",
        action="store_true",
        help="After parse_record, convert the result to a dict (simulates JSON serialization).",
    )
    parser.add_argument(
        "--rayon-policy",
        choices=("never", "always", "auto"),
        default=None,
        help="Override STRUCTLY_RAYON policy for the benchmark parser.",
    )
    parser.add_argument(
        "files",
        nargs="*",
        help="Optional subset of WHOIS fixture file names (e.g. google.com microsoft.com).",
    )
    args = parser.parse_args()
    if args.record_to_dict and args.method == "parse_many" and not args.parse_many_to_records:
        parser.error("--record-to-dict requires --parse-many-to-records when benchmarking parse_many")

    sample_paths = _iter_sample_files(args.files)
    whois_parser = WhoisParser(rayon_policy=args.rayon_policy)

    print(
        f"{'file':25} {'iters':>7} {'records':>10} {'elapsed(s)':>12} {'records/s':>12} "
        f"{'cpu_user(s)':>12} {'cpu_sys(s)':>12} {'rssΔ(kb)':>10} {'rss_peak(kb)':>13}"
    )
    for path in sample_paths:
        result = benchmark_file(
            whois_parser,
            path,
            args.iterations,
            args.method,
            args.batch_size,
            args.record_to_dict,
            args.parse_many_to_records,
        )
        print(
            f"{result.name:25} {result.iterations:7d} {result.records:10d} {result.elapsed:12.4f} "
            f"{result.records_per_second:12.2f} {result.cpu_user:12.4f} {result.cpu_system:12.4f} "
            f"{result.rss_delta_kb:10.0f} {result.rss_peak_kb:13.0f}"
        )


if __name__ == "__main__":
    main()
