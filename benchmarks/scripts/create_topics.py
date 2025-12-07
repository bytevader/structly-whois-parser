from __future__ import annotations

import argparse
from collections.abc import Iterable

from confluent_kafka.admin import AdminClient, NewTopic


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Create Kafka topics via confluent-kafka.")
    parser.add_argument(
        "--bootstrap-server",
        default="localhost:9094",
        help="Bootstrap server for the cluster (host:port).",
    )
    parser.add_argument(
        "--replication-factor",
        type=int,
        default=1,
        help="Replication factor for each topic (default: 1).",
    )
    parser.add_argument(
        "--partitions",
        type=int,
        default=1,
        help="Number of partitions for each topic (default: 1).",
    )
    parser.add_argument(
        "topics",
        nargs="+",
        help="One or more topic names to ensure exist.",
    )
    return parser.parse_args()


def create_topics(client: AdminClient, topics: Iterable[str], partitions: int, replication_factor: int) -> None:
    new_topics = [
        NewTopic(topic=topic, num_partitions=partitions, replication_factor=replication_factor) for topic in topics
    ]
    futures = client.create_topics(new_topics, request_timeout=15.0)
    for topic, future in futures.items():
        try:
            future.result()
            print(f"[ok] topic '{topic}' ready")
        except Exception as exc:  # pragma: no cover - admin errors are best-effort
            print(f"[warn] topic '{topic}' not created: {exc}")


def main() -> int:
    args = parse_args()
    client = AdminClient({"bootstrap.servers": args.bootstrap_server})
    create_topics(client, args.topics, args.partitions, args.replication_factor)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
