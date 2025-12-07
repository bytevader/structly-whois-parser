## Benchmarking Environment

Follow these steps to spin up Kafka/Redpanda plus the constrained WHOIS consumer, then publish the 1M-record workload:

1. **Install tooling dependencies (optional outside Docker)**  
   ```bash
   pip install .[benchmarks]
   ```

2. **Build the dedicated parser image**  
   ```bash
   # Docker Desktop
   docker compose -f benchmarks/docker-compose.yml build whois-parser

   # Rancher Desktop / nerdctl
   nerdctl compose -f benchmarks/docker-compose.yml build whois-parser
   ```

3. **Start ZooKeeper, Kafka, Redpanda Console, and the parser**  
   ```bash
   # Docker Desktop
   docker compose -f benchmarks/docker-compose.yml -p whois-bench up -d --remove-orphans

   # Rancher Desktop / nerdctl (containerd). Note: nerdctl ignores depends_on, so ensure ZooKeeper is healthy before
   # manually starting Kafka/console if necessary.
   nerdctl compose -f benchmarks/docker-compose.yml -p whois-bench up -d --remove-orphans
   ```
   - ZooKeeper listens on `localhost:2181`.
   - Kafka listens on `localhost:9094` for host clients and `kafka:9092` inside the Compose network.
   - Redpanda Console is mapped to `http://localhost:8080`; it will show the Kafka topics once the broker is reachable.
   - The consumer container is pinned to `1 CPU / 500 MB` and reads from `whois_raw`, writes to `whois_parsed`.

4. **Create the Kafka topics (whois_raw & whois_parsed)**  
   ```bash
   # Using the helper script (requires confluent-kafka installed locally)
   python benchmarks/scripts/create_topics.py --bootstrap-server localhost:9094 whois_raw whois_parsed

   # Alternatively, run inside the Kafka container (choose docker or nerdctl)
   docker compose -f benchmarks/docker-compose.yml -p whois-bench exec kafka \
     /opt/bitnami/kafka/bin/kafka-topics.sh --create --if-not-exists --bootstrap-server kafka:9092 \
     --replication-factor 1 --partitions 1 --topic whois_raw
   docker compose -f benchmarks/docker-compose.yml -p whois-bench exec kafka \
     /opt/bitnami/kafka/bin/kafka-topics.sh --create --if-not-exists --bootstrap-server kafka:9092 \
     --replication-factor 1 --partitions 1 --topic whois_parsed
   ```
   - Auto-create is enabled, but creating both upfront keeps Kafka and the console aligned.
   - A single partition keeps ordering guarantees and matches the single constrained parser container; raise the partition count only when you scale out consumers.

5. **Seed Kafka with 1M WHOIS records**  
   ```bash
   python benchmarks/scripts/seed_whois_data.py --bootstrap-servers localhost:9094 --total-records 1000000
   ```
   - Uses 105 fixtures from `tests/samples/whois`, loops them until 1M records, and publishes with snappy compression.
   - **Reference throughput:** 1,000,000 messages processed in **146.14 s** on the constrained `whois-parser`
     container (~6,840 records/s ≈ 24.6 M/hour ≈ 591 M/day). Treat this as the baseline when adjusting runtimes.

6. **Monitor the consumer throughput & timing**  
   ```bash
   # Docker Desktop
   docker compose -f benchmarks/docker-compose.yml -p whois-bench logs -f whois-parser

   # Rancher Desktop / nerdctl
   nerdctl compose -f benchmarks/docker-compose.yml -p whois-bench logs -f whois-parser
   ```
   - The script reports the elapsed time between the first and last payload once the topic drains.

7. **Shut everything down when done**  
   ```bash
   # Docker Desktop
   docker compose -f benchmarks/docker-compose.yml -p whois-bench down -v

   # Rancher Desktop / nerdctl
   nerdctl compose -f benchmarks/docker-compose.yml -p whois-bench down -v
   ```
   - Removes containers plus the persisted Kafka/Redpanda volumes.
