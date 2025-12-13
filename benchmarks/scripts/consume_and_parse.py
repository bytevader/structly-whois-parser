from __future__ import annotations

import argparse
import logging
import socket
import sys
import time
from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import orjson
import snappy
from confluent_kafka import Consumer, KafkaError, KafkaException, Message, Producer

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from structly_whois import WhoisParser  # noqa: E402

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class PendingPayload:
    message: Message
    raw_text: str
    domain: str | None


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


def _wait_for_kafka(bootstrap_servers: str, retry_interval: float = 1.0) -> None:
    """Block until at least one broker endpoint accepts TCP connections."""
    endpoints: list[tuple[str, int]] = []
    for target in bootstrap_servers.split(","):
        target = target.strip()
        if not target:
            continue
        host, sep, port_str = target.rpartition(":")
        if not sep:
            host = target
            port_str = "9092"
        endpoints.append((host, int(port_str)))
    if not endpoints:
        raise ValueError("No Kafka bootstrap servers provided.")
    last_error: Exception | None = None
    while True:
        for host, port in endpoints:
            try:
                with socket.create_connection((host, port), timeout=3):
                    logger.info("Connected to Kafka bootstrap %s:%s", host, port)
                    return
            except OSError as exc:
                last_error = exc
        logger.info("Waiting for Kafka (%s); retrying in %.1fs...", last_error, retry_interval)
        time.sleep(retry_interval)


class ConsumeAndParseApp:
    """Class-based orchestrator for the WHOIS Kafka pipeline."""

    def __init__(self, args: argparse.Namespace) -> None:
        self.args = args
        self.logger = logging.getLogger(f"{__name__}.ConsumeAndParseApp")
        self.consumer = _build_consumer(args)
        self.producer = _build_producer(args)
        self.parser = WhoisParser()
        self.processed = 0
        self.skipped = 0
        self.start_time: float | None = None
        self.last_message_time: float | None = None
        self.batch_timer_start: float | None = None
        self.batch_records = 0
        self.last_message_in_batch: Message | None = None

    def run(self) -> int:
        try:
            while True:
                messages = self.consumer.consume(num_messages=self.args.batch_size, timeout=1.0)
                now = time.monotonic()
                if not messages:
                    if self._handle_idle(now):
                        break
                    continue

                if self.batch_timer_start is None:
                    self.batch_timer_start = now

                grouped, fallback = self._partition_payloads(messages, now)
                self._process_grouped_payloads(grouped, fallback)
                self._process_fallback_payloads(fallback)
                self.producer.poll(0)

                if self.batch_records >= self.args.batch_size:
                    self._flush_batch(synchronous=False)

        except KeyboardInterrupt:
            self.logger.info("Interrupted; flushing outstanding records...")
        finally:
            self._flush_batch(synchronous=True)
            self.producer.flush()
            self.consumer.close()

        duration = self.last_message_time - self.start_time if self.start_time and self.last_message_time else 0.0
        self.logger.info(
            "Processed %s messages (skipped=%s) in %.2fs between first and last payload.",
            f"{self.processed:,}",
            f"{self.skipped:,}",
            duration,
        )
        return 0

    def _handle_idle(self, now: float) -> bool:
        self._flush_batch(synchronous=True, current_time=now)
        if self.last_message_time and now - self.last_message_time >= self.args.idle_timeout:
            self.logger.info("Idle timeout reached after %.2fs. Exiting.", now - self.last_message_time)
            return True
        return False

    def _partition_payloads(
        self,
        messages: list[Message | None],
        now: float,
    ) -> tuple[dict[str, list[PendingPayload]], list[PendingPayload]]:
        grouped_payloads: dict[str, list[PendingPayload]] = defaultdict(list)
        fallback_payloads: list[PendingPayload] = []

        for message in messages:
            if message is None:
                continue
            if message.error():
                error = message.error()
                if error.code() == KafkaError._PARTITION_EOF:
                    continue
                raise KafkaException(error)

            self.last_message_time = now
            raw_value = message.value()
            if not raw_value:
                self.skipped += 1
                continue
            try:
                value: dict[str, Any] = orjson.loads(raw_value)
            except orjson.JSONDecodeError as exc:
                self.skipped += 1
                self.logger.warning("Invalid JSON payload at offset %s: %s", message.offset(), exc)
                continue

            raw_text = value.get("raw_text")
            domain = value.get("domain")
            if not raw_text:
                self.skipped += 1
                continue

            payload = PendingPayload(message=message, raw_text=raw_text, domain=domain)
            if domain:
                tld_hint = self._safe_select_tld(domain)
                if tld_hint:
                    grouped_payloads[tld_hint].append(payload)
                    continue
            fallback_payloads.append(payload)

        return grouped_payloads, fallback_payloads

    def _process_grouped_payloads(
        self,
        grouped: dict[str, list[PendingPayload]],
        fallback_payloads: list[PendingPayload],
    ) -> None:
        for tld_hint, payloads in grouped.items():
            try:
                parsed_records = self.parser.parse_many(
                    (payload.raw_text for payload in payloads),
                    tld=tld_hint,
                    to_records=True,
                )
            except Exception as exc:  # pragma: no cover - defensive logging
                self.logger.warning("parse_many failed for TLD '%s': %s", tld_hint, exc)
                fallback_payloads.extend(payloads)
                continue

            for payload, parsed_record in zip(payloads, parsed_records):
                self._handle_parsed_record(parsed_record, payload)

    def _process_fallback_payloads(self, payloads: list[PendingPayload]) -> None:
        for payload in payloads:
            try:
                parsed_record = self.parser.parse_record(payload.raw_text, domain=payload.domain)
            except Exception as exc:  # pragma: no cover - defensive logging
                self.skipped += 1
                self.logger.warning("Failed to parse payload: %s", exc)
                continue
            self._handle_parsed_record(parsed_record, payload)

    def _handle_parsed_record(self, record: Any, payload: PendingPayload) -> None:
        try:
            self._emit_parsed_record(record, payload)
        except Exception as exc:  # pragma: no cover - defensive logging
            self.skipped += 1
            self.logger.warning("Failed to process payload: %s", exc)
            return

        self.processed += 1
        self.batch_records += 1
        self.last_message_in_batch = payload.message
        if self.start_time is None:
            self.start_time = time.monotonic()
        if self.args.log_interval and self.processed % self.args.log_interval == 0:
            elapsed_total = time.monotonic() - self.start_time
            rate_total = self.processed / elapsed_total if elapsed_total else 0
            self.logger.info(
                "processed %s messages (skipped=%s, rate=%s records/sec)",
                f"{self.processed:,}",
                f"{self.skipped:,}",
                f"{rate_total:,.0f}",
            )

    def _emit_parsed_record(self, record: Any, payload: PendingPayload) -> None:
        parsed_payload = record.to_dict(include_raw_text=False)
        source_key_bytes = payload.message.key()
        parsed_payload.update({
            "source_topic": payload.message.topic(),
            "source_partition": payload.message.partition(),
            "source_offset": payload.message.offset(),
            "source_key": source_key_bytes.decode("utf-8") if source_key_bytes else None,
            "consumed_at": time.time(),
        })
        key = parsed_payload.get("domain") or payload.domain or ""
        key_bytes = key.encode("utf-8") if key else None
        value_bytes = orjson.dumps(parsed_payload, default=str)
        while True:
            try:
                self.producer.produce(self.args.parsed_topic, key=key_bytes, value=value_bytes)
                break
            except BufferError:
                self.producer.poll(0.5)

    def _flush_batch(self, *, synchronous: bool, current_time: float | None = None) -> None:
        if self.batch_timer_start is None or not self.batch_records:
            return
        now = current_time or time.monotonic()
        elapsed = now - self.batch_timer_start
        rate = self.batch_records / elapsed if elapsed else 0.0
        self.logger.info(
            "[batch] duration=%.2fs records=%s rate=%s/s",
            elapsed,
            f"{self.batch_records:,}",
            f"{rate:,.0f}",
        )
        self._commit_offset(synchronous=synchronous)
        self.batch_timer_start = None
        self.batch_records = 0
        self.last_message_in_batch = None

    def _commit_offset(self, *, synchronous: bool) -> None:
        if self.last_message_in_batch is None:
            return
        try:
            self.consumer.commit(message=self.last_message_in_batch, asynchronous=not synchronous)
        except KafkaException as exc:  # pragma: no cover - defensive logging
            self.logger.warning("Commit failed: %s", exc)

    def _safe_select_tld(self, domain: str) -> str:
        try:
            return self.parser._select_tld(None, domain)
        except Exception:  # pragma: no cover - defensive fallback
            return ""


def main(argv: Iterable[str] | None = None) -> int:
    args = _parse_args(argv)
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    _wait_for_kafka(args.bootstrap_servers)
    _snappy_self_test()
    app = ConsumeAndParseApp(args)
    return app.run()


if __name__ == "__main__":
    raise SystemExit(main())
