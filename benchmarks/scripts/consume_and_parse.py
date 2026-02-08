from __future__ import annotations

import logging
import socket
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import orjson
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


class ConsumeAndParseJob:
    BOOTSTRAP_SERVERS = "kafka:9092"
    RAW_TOPIC = "whois_raw"
    PARSED_TOPIC = "whois_parsed"
    GROUP_ID = "whois-parser"
    IDLE_TIMEOUT = 15.0
    LINGER_MS = 5
    BATCH_SIZE = 5000
    MAX_POLL_INTERVAL_MS = 300000

    def __init__(self) -> None:
        self.logger = logging.getLogger(f"{__name__}.ConsumeAndParseJob")
        _wait_for_kafka(self.BOOTSTRAP_SERVERS)

        self.consumer = self._build_consumer()
        self.producer = self._build_producer()
        # To test performance with date parser use
        # WhoisParser(date_parser=dateutil_parser.parse)
        # WhoisParser(date_parser=dateparser_parser)
        self.parser = WhoisParser()
        self.processed = 0
        self.skipped = 0
        self.start_time: float | None = None
        self.last_message_time: float | None = None
        self.batch_timer_start: float | None = None
        self.batch_records = 0
        self.last_message_in_batch: Message | None = None
        now = time.monotonic()
        self.job_start_time = now
        self.progress_log_interval = 10.0
        self.last_progress_log_time = now
        self.idle_log_interval = 10.0
        self.last_idle_log_time = now

    def run(self) -> int:
        try:
            while True:
                messages = self.consumer.consume(num_messages=self.BATCH_SIZE, timeout=1.0)
                now = time.monotonic()
                if not messages:
                    if self._handle_idle(now):
                        break
                    continue

                if self.batch_timer_start is None:
                    self.batch_timer_start = now

                batchable, fallback = self._partition_payloads(messages, now)
                self._process_batch_payloads(batchable, fallback)
                self._process_fallback_payloads(fallback)
                self.producer.poll(0)

                if self.batch_records >= self.BATCH_SIZE:
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
        self._log_progress(current_time=now)
        self._log_idle(now)
        if self.last_message_time and now - self.last_message_time >= self.IDLE_TIMEOUT:
            self.logger.info("Idle timeout reached after %.2fs. Exiting.", now - self.last_message_time)
            return True
        return False

    def _partition_payloads(
        self,
        messages: list[Message | None],
        now: float,
    ) -> tuple[list[PendingPayload], list[PendingPayload]]:
        batchable_payloads: list[PendingPayload] = []
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
                batchable_payloads.append(payload)
            else:
                fallback_payloads.append(payload)

        return batchable_payloads, fallback_payloads

    def _process_batch_payloads(
        self,
        payloads: list[PendingPayload],
        fallback_payloads: list[PendingPayload],
    ) -> None:
        if not payloads:
            return
        try:
            domain_hints = [payload.domain or "" for payload in payloads]
            parsed_records = self.parser.parse_many(
                (payload.raw_text for payload in payloads),
                domain=domain_hints,
                to_records=True,
            )
        except Exception as exc:  # pragma: no cover - defensive logging
            self.logger.warning("parse_many failed for batch: %s", exc)
            fallback_payloads.extend(payloads)
            return

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
        self.last_idle_log_time = time.monotonic()
        if self.start_time is None:
            self.start_time = time.monotonic()
        self._log_progress()

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
        key_bytes = key.lower().encode("utf-8") if key else None
        value_bytes = orjson.dumps(parsed_payload, default=str)
        while True:
            try:
                self.producer.produce(self.PARSED_TOPIC, key=key_bytes, value=value_bytes)
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

    def _build_consumer(self) -> Consumer:
        config = {
            "bootstrap.servers": self.BOOTSTRAP_SERVERS,
            "group.id": self.GROUP_ID,
            "auto.offset.reset": "earliest",
            "enable.auto.commit": False,
            "max.poll.interval.ms": self.MAX_POLL_INTERVAL_MS,
        }
        consumer = Consumer(config)
        consumer.subscribe([self.RAW_TOPIC])
        return consumer

    def _build_producer(self) -> Producer:
        config = {
            "bootstrap.servers": self.BOOTSTRAP_SERVERS,
            "acks": "all",
            "compression.type": "snappy",
            "linger.ms": self.LINGER_MS,
            "batch.num.messages": self.BATCH_SIZE,
        }
        return Producer(config)

    def _log_progress(self, current_time: float | None = None) -> None:
        now = current_time or time.monotonic()
        if now - self.last_progress_log_time < self.progress_log_interval:
            return
        elapsed_total = now - self.job_start_time
        rate_total = self.processed / elapsed_total if elapsed_total else 0.0
        self.logger.info(
            "processed %s messages (skipped=%s, elapsed=%.1fs, rate=%s records/sec)",
            f"{self.processed:,}",
            f"{self.skipped:,}",
            elapsed_total,
            f"{rate_total:,.0f}",
        )
        self.last_progress_log_time = now

    def _log_idle(self, now: float) -> None:
        if now - self.last_idle_log_time < self.idle_log_interval:
            return
        idle_origin = self.last_message_time or self.job_start_time
        idle_for = now - idle_origin
        self.logger.info("No messages received for %.1fs; waiting...", idle_for)
        self.last_idle_log_time = now


def main() -> int:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    app = ConsumeAndParseJob()
    return app.run()


if __name__ == "__main__":
    raise SystemExit(main())
