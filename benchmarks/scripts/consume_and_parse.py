from __future__ import annotations

import argparse
import json
import sys
import time
from collections.abc import Iterable
from pathlib import Path

import snappy
from confluent_kafka import Consumer, KafkaError, KafkaException, Message, Producer

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from structly_whois import WhoisParser  # noqa: E402


def _snappy_self_test() -> None:
    probe = snappy.compress(b"health-check")
    snappy.decompress(probe)


def _build_consumer(args: argparse.Namespace) -> Consumer:
    config = {
        "bootstrap.servers": args.bootstrap_servers,
        "group.id": args.group_id,
        "auto.offset.reset": "earliest",
        "enable.auto.commit": False,
        "max.poll.interval.ms": args.max_poll_interval_ms,
    }
    consumer = Consumer(config)
    consumer.subscribe([args.raw_topic])
    return consumer


def _build_producer(args: argparse.Namespace) -> Producer:
    config = {
        "bootstrap.servers": args.bootstrap_servers,
        "acks": "all",
        "compression.type": "snappy",
        "linger.ms": args.linger_ms,
        "batch.num.messages": args.batch_size,
    }
    return Producer(config)


def _parse_args(argv: Iterable[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Consume WHOIS payloads and publish parsed records.")
    parser.add_argument("--bootstrap-servers", default="kafka:9092", help="Kafka bootstrap servers string.")
    parser.add_argument("--raw-topic", default="whois_raw", help="Topic carrying unparsed WHOIS payloads.")
    parser.add_argument("--parsed-topic", default="whois_parsed", help="Topic for structured records.")
    parser.add_argument("--group-id", default="whois-parser", help="Kafka consumer group id.")
    parser.add_argument("--idle-timeout", type=float, default=15.0, help="Seconds to wait for new data before exiting.")
    parser.add_argument("--linger-ms", type=int, default=5, help="linger.ms for the parsed producer.")
    parser.add_argument(
        "--batch-size",
        type=int,
        default=500,
        help="Maximum number of messages to consume per poll and to buffer in the producer.",
    )
    parser.add_argument("--max-poll-interval-ms", type=int, default=300000, help="Kafka max.poll.interval.ms setting.")
    parser.add_argument(
        "--log-interval",
        type=int,
        default=50000,
        help="Emit progress information after this many processed messages.",
    )
    return parser.parse_args(argv)


def _log_batch(elapsed: float, records: int) -> None:
    rate = records / elapsed if elapsed else 0.0
    print(f"[batch] duration={elapsed:.2f}s records={records:,} rate={rate:,.0f}/s")


def _commit_offset(consumer: Consumer, message: Message | None, synchronous: bool) -> None:
    if message is None:
        return
    try:
        consumer.commit(message=message, asynchronous=not synchronous)
    except KafkaException as exc:  # pragma: no cover - defensive logging
        print(f"[warn] commit failed: {exc}", file=sys.stderr)


def main(argv: Iterable[str] | None = None) -> int:
    args = _parse_args(argv)
    _snappy_self_test()
    parser = WhoisParser()
    consumer = _build_consumer(args)
    producer = _build_producer(args)

    processed = 0
    skipped = 0
    start_time: float | None = None
    last_message_time: float | None = None
    batch_timer_start: float | None = None
    batch_records = 0
    last_message_in_batch: Message | None = None

    try:
        while True:
            messages = consumer.consume(num_messages=args.batch_size, timeout=1.0)
            now = time.monotonic()
            if not messages:
                if batch_timer_start is not None and batch_records:
                    elapsed = now - batch_timer_start
                    _log_batch(elapsed, batch_records)
                    _commit_offset(consumer, last_message_in_batch, synchronous=True)
                    batch_timer_start = None
                    batch_records = 0
                    last_message_in_batch = None
                if last_message_time and now - last_message_time >= args.idle_timeout:
                    break
                continue

            if batch_timer_start is None:
                batch_timer_start = now

            for message in messages:
                if message is None:
                    continue
                if message.error():
                    error = message.error()
                    if error.code() == KafkaError._PARTITION_EOF:
                        continue
                    raise KafkaException(error)

                last_message_time = now
                raw_value = message.value()
                if not raw_value:
                    skipped += 1
                    continue
                try:
                    value = json.loads(raw_value.decode("utf-8"))
                except json.JSONDecodeError as exc:
                    skipped += 1
                    print(f"[warn] invalid JSON payload at offset {message.offset()}: {exc}", file=sys.stderr)
                    continue

                raw_text = value.get("raw_text")
                domain = value.get("domain")
                if not raw_text:
                    skipped += 1
                    continue

                try:
                    parsed_record = parser.parse_record(raw_text, domain=domain)
                except Exception as exc:  # pragma: no cover - defensive logging
                    skipped += 1
                    print(f"[warn] failed to parse payload: {exc}", file=sys.stderr)
                    continue

                parsed_payload = parsed_record.to_dict(include_raw_text=False)
                source_key_bytes = message.key()
                parsed_payload.update({
                    "source_topic": message.topic(),
                    "source_partition": message.partition(),
                    "source_offset": message.offset(),
                    "source_key": source_key_bytes.decode("utf-8") if source_key_bytes else None,
                    "consumed_at": time.time(),
                })
                key = parsed_payload.get("domain") or domain or ""
                key_bytes = key.encode("utf-8") if key else None
                value_bytes = json.dumps(parsed_payload, default=str).encode("utf-8")
                while True:
                    try:
                        producer.produce(args.parsed_topic, key=key_bytes, value=value_bytes)
                        break
                    except BufferError:
                        producer.poll(0.5)
                producer.poll(0)

                processed += 1
                batch_records += 1
                last_message_in_batch = message
                if start_time is None:
                    start_time = now
                if args.log_interval and processed % args.log_interval == 0:
                    elapsed_total = now - start_time
                    rate_total = processed / elapsed_total if elapsed_total else 0
                    print(f"processed {processed:,} messages (skipped={skipped:,}, rate={rate_total:,.0f} records/sec)")

            if batch_records >= args.batch_size and batch_timer_start is not None:
                elapsed = time.monotonic() - batch_timer_start
                _log_batch(elapsed, batch_records)
                _commit_offset(consumer, last_message_in_batch, synchronous=False)
                batch_timer_start = None
                batch_records = 0
                last_message_in_batch = None

    except KeyboardInterrupt:
        print("Interrupted; flushing outstanding records...")
    finally:
        if batch_timer_start is not None and batch_records:
            elapsed = time.monotonic() - batch_timer_start
            _log_batch(elapsed, batch_records)
        _commit_offset(consumer, last_message_in_batch, synchronous=True)
        producer.flush()
        consumer.close()

    duration = last_message_time - start_time if start_time and last_message_time else 0.0
    print(f"Processed {processed:,} messages (skipped={skipped:,}) in {duration:.2f}s between first and last payload.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
