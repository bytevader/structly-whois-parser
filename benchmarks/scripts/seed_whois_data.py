from __future__ import annotations

import argparse
import itertools
import json
import sys
import time
from collections.abc import Iterable, Iterator, Sequence
from pathlib import Path

import snappy
from confluent_kafka import Producer

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from tests.sample_utils import SKIPPED_SAMPLES  # noqa: E402

DEFAULT_SAMPLES_DIR = PROJECT_ROOT / "tests" / "samples" / "whois"
DEFAULT_TOTAL_RECORDS = 1_000_000
DEFAULT_SAMPLE_LIMIT = 105


def _snappy_self_test() -> None:
    probe = snappy.compress(b"health-check")
    snappy.decompress(probe)


def _load_samples(samples_dir: Path, limit: int) -> list[tuple[str, str]]:
    if not samples_dir.exists():
        raise FileNotFoundError(f"Sample directory '{samples_dir}' was not found")
    files = sorted(path for path in samples_dir.iterdir() if path.is_file() and path.stem not in SKIPPED_SAMPLES)
    if len(files) < limit:
        raise RuntimeError(
            f"Requested {limit} samples but only {len(files)} non-skipped files are available ("
            f"SKIPPED_SAMPLES filters {len(SKIPPED_SAMPLES)} entries)."
        )
    selected = files[:limit]
    payloads: list[tuple[str, str]] = []
    for path in selected:
        payloads.append((path.stem, path.read_text(encoding="utf-8", errors="ignore")))
    return payloads


def _iter_messages(samples: Sequence[tuple[str, str]], total: int) -> Iterator[tuple[int, str, str]]:
    cycling = itertools.islice(itertools.cycle(samples), total)
    for idx, (domain, raw_text) in enumerate(cycling, start=1):
        yield idx, domain, raw_text


def _tld_for_domain(domain: str) -> str:
    if "." not in domain:
        return ""
    return domain.rsplit(".", 1)[1]


def _build_producer(bootstrap_servers: str, linger_ms: int, batch_size: int) -> Producer:
    config = {
        "bootstrap.servers": bootstrap_servers,
        "compression.type": "snappy",
        "linger.ms": linger_ms,
        "batch.num.messages": batch_size,
        "acks": "all",
    }
    return Producer(config)


def _parse_args(argv: Iterable[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Replay WHOIS samples into Kafka to create a 1M record workload.")
    parser.add_argument("--bootstrap-servers", default="localhost:29092", help="Kafka bootstrap servers string.")
    parser.add_argument("--topic", default="whois_raw", help="Kafka topic that receives raw WHOIS payloads.")
    parser.add_argument(
        "--samples-path",
        type=Path,
        default=DEFAULT_SAMPLES_DIR,
        help="Directory with WHOIS fixtures.",
    )
    parser.add_argument(
        "--max-files",
        type=int,
        default=DEFAULT_SAMPLE_LIMIT,
        help="Maximum number of fixture files to load (defaults to 105).",
    )
    parser.add_argument(
        "--total-records",
        type=int,
        default=DEFAULT_TOTAL_RECORDS,
        help="Number of records to emit (defaults to 1,000,000).",
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=1000,
        help="Maximum number of messages to buffer before sending (batch.num.messages).",
    )
    parser.add_argument("--linger-ms", type=int, default=5, help="Kafka linger.ms for the producer.")
    parser.add_argument(
        "--report-every",
        type=int,
        default=100_000,
        help="Print progress after this many published records.",
    )
    return parser.parse_args(argv)


def main(argv: Iterable[str] | None = None) -> int:
    args = _parse_args(argv)
    _snappy_self_test()
    samples = _load_samples(args.samples_path, args.max_files)
    print(
        f"Loaded {len(samples)} fixtures from {args.samples_path}, "
        f"publishing {args.total_records:,} records to topic '{args.topic}'."
    )
    producer = _build_producer(args.bootstrap_servers, args.linger_ms, args.batch_size)
    start = time.perf_counter()
    try:
        for idx, domain, raw_text in _iter_messages(samples, args.total_records):
            tld = _tld_for_domain(domain)
            payload = {
                "sequence": idx,
                "domain": domain,
                "tld": tld,
                "raw_text": raw_text,
                "sample_source": f"{domain}.txt",
            }
            key_bytes = domain.encode("utf-8")
            value_bytes = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            while True:
                try:
                    producer.produce(args.topic, key=key_bytes, value=value_bytes)
                    break
                except BufferError:
                    producer.poll(0.5)
            producer.poll(0)
            if idx % args.report_every == 0:
                elapsed = time.perf_counter() - start
                print(f"sent {idx:,}/{args.total_records:,} messages ({idx / elapsed:,.0f} records/sec)")
    finally:
        producer.flush()
    elapsed = time.perf_counter() - start
    print(
        f"Done publishing {args.total_records:,} messages in {elapsed:.2f}s "
        f"({args.total_records / elapsed:,.0f} records/sec)."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
