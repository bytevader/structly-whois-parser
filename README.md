<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/structly_whois.svg">
    <img src="https://github.com/bytevader/structly-whois-parser/raw/main/docs/structly_whois.svg" alt="structly_whois" width="320">
  </picture>
</p>
<p align="center">
    <em>Structly-powered WHOIS parsing.</em>
</p>
<p align="center">
<a href="https://github.com/bytevader/structly-whois-parser/actions/workflows/ci.yml?query=branch%3Amain" target="_blank">
    <img src="https://github.com/bytevader/structly-whois-parser/actions/workflows/ci.yml/badge.svg?branch=main" alt="Main CI">
</a>
<a href="https://coverage-badge.samuelcolvin.workers.dev/bytevader/structly-whois-parser.svg?branch=main" target="_blank">
    <img src="https://coverage-badge.samuelcolvin.workers.dev/bytevader/structly-whois-parser.svg?branch=main" alt="Coverage">
</a>
<a href="https://pypi.org/project/structly-whois" target="_blank">
    <img src="https://img.shields.io/pypi/v/structly-whois?color=%2334D058&label=pypi%20package" alt="PyPI">
</a>
</p>

> Fast WHOIS parser powered by [structly](https://pypi.org/project/structly/) and [msgspec](https://pypi.org/project/msgspec/).

**structly_whois** wraps Structly's compiled parsers with a modern Python API so you can normalize noisy WHOIS payloads, auto-detect TLD-specific overrides, and emit JSON-ready records without hauling heavy regex DSLs or dateparser into your hot path.

This library parses raw WHOIS text, it does not perform WHOIS lookups. 
Be mindful of data handling obligations (GDPR/ICANN/etc.)

## Highlights

- **Structly speed** – Per-TLD configurations are compiled by Structly, keeping parsing under a millisecond/record even on commodity hardware.
- **Typed surface** – msgspec-based `WhoisRecord` structs, `py.typed` wheels, and a CLI entrypoint (`structly-whois`) for quick inspection.
- **Configurable** – Inject your own Structly configs, register TLD overrides at runtime, or extend the base field definitions without forking.
- **Lean dependencies** – No `dateparser` or required by default. Plug in a `date_parser` callable only when locale-aware coercion is truly needed.
- **Batched & streaming friendly** – `parse_many` and `parse_chunks` let you process millions of payloads from queues, tarballs, or S3 archives without buffering everything in memory.

## Supported TLD coverage

The live matrix of supported TLDs, tiers (Gold/Silver/Experimental), and sample fixtures lives in [docs/supported-tlds.md](docs/supported-tlds.md). \
Regenerate it with `python scripts/supported_tlds/generate_supported_tlds.py`, and run `--check`/`--validate` before committing fixture or tier changes (CI runs those flags automatically). \
See [docs/supported-tlds-generator.md](docs/supported-tlds-generator.md) for optional local-only commands such as generating coverage reports or tier suggestions.

## Schema & stability

`structly-whois` guarantees a stable canonical record schema that you can depend on in downstream systems. Review [docs/schema.md](docs/schema.md) for field definitions, normalization rules, and SemVer-style guarantees. Use `WhoisRecord.schema_version` together with `WhoisParser.field_catalog()` to assert compatibility in your CI pipeline.

## Installation

```bash
pip install structly-whois               # end users
pip install -e '.[dev]'                  # contributors (installs Ruff, pytest, etc.)
# optional: pip install python-dateutil or dateparser if you plan to use a custom date parser hook
```

Python 3.9+ is supported. Wheels ship `py.typed` markers for static analyzers.

## Quickstart

```python
from structly_whois import WhoisParser

parser = WhoisParser()
payload = """
          Domain Name: example.com
          Registrar: Example Registrar LLC
          Creation Date: 2020-01-01T12:00:00Z
          Registry Expiry Date: 2030-01-01T12:00:00Z
          Name Server: NS1.EXAMPLE.COM
          Name Server: NS2.EXAMPLE.COM
          Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited
          Registrant Name: Example DNS
          """

record = parser.parse_record(payload, domain="example.com")
print(record.domain)
print(record.statuses)
print(record.registered_at)
print(record.to_dict())
```

If you omit `domain`, structly_whois inspects the payload to infer the domain/TLD and automatically picks the right Structly configuration.
Need just a mapping instead of a structured record? Use `parse`/`parse_many` directly:

```python
parser = WhoisParser(preload_tlds=("com", "net"))
parsed = parser.parse(payload)  # returns {"domain_name": ..., "registrar": ..., ...}

batch = parser.parse_many(
    [payload_1, payload_2],
    domain=["example.com", "example.net"],
    tld="com",  # optional hint; omit to auto-select per domain
)
for result in batch:
    print(result["domain_name"])
```

## CLI usage

```bash
structly-whois tests/samples/whois/google.com.txt \
  --domain google.com \
  --record --json \
  --date-parser tests.common.helpers:iso_to_datetime
```

The CLI mirrors the Python API: pass `--record` to emit a structured `WhoisRecord`, `--lowercase` to normalize strings, and `--date-parser module:callable` when you want custom date coercion. Stdin is supported out of the box:

```bash
cat tests/samples/whois/google.com.txt | structly-whois - --json
```

Need to process streams? Switch to JSONL mode. Feed newline-delimited objects that contain at least a `raw_text` field (plus optional `domain`, `tld`, or `id`) and emit JSONL on the way out:

```bash
structly-whois payloads.jsonl \
  --input-format jsonl \
  --jsonl \
  --best-effort \
  --metrics
```

`--best-effort` keeps consuming payloads even if some rows fail (while still returning a non-zero exit status), and `--metrics` prints a throughput summary to stderr when the run completes. Drop the `--jsonl` flag to pretty-print JSON instead.

## Advanced usage

### Batched parsing

```python
parser = WhoisParser()
payloads: list[str] = fetch_from_queue()
records = parser.parse_many(payloads, to_records=True, lowercase=True)
for record in records:
    ingest(record)  # bulk insert, emit to Kafka, etc.
```

### Streaming note: `to_records=True` buffers input

`parse_many(..., to_records=True)` yields `WhoisRecord` instances. Building those structs requires both the parsed fields and the original raw payload, so the incoming iterable is materialized into a list. When processing very large streams, chunk the input so memory stays bounded:

```python
from itertools import islice
from structly_whois import WhoisParser

def chunked(iterator, size: int):
    iterator = iter(iterator)
    while True:
        chunk = list(islice(iterator, size))
        if not chunk:
            return
        yield chunk

parser = WhoisParser()

for payload_chunk in chunked(iter_whois_payloads(), 1024):
    records = parser.parse_many(payload_chunk, to_records=True)
    for record in records:
        ingest(record)
```

### Optional date parser hook

`structly_whois` intentionally avoids bundling `dateparser`. If you need locale-specific conversions, pass a callable either when constructing the parser or per method:

```python
from datetime import datetime

def date_hook(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))

parser = WhoisParser(date_parser=date_hook)
record = parser.parse_record(raw_whois, domain="example.dev", date_parser=date_hook)
```

For multilingual registries, the simplest plug-in is [`dateparser.parse`](https://pypi.org/project/dateparser/). 

NOTE: It can cut throughput by more than half.

### Date parsing coverage & fallbacks

We periodically re-run the parser against every sample under `tests/samples/whois`. The latest sweep (193 fixtures / 452 date fields) produced real `datetime` objects for 448 fields (99.12%) using the built-in fast formats alone. Only two TLDs still emit string timestamps:

- `.uk` (3 samples) – they literally return `"before Aug-1996"` for the creation date. No generic parser can infer a timestamp from that prose.
- `.il` (1 sample) – the registry embeds `"registrar AT ns.il 19990605"` inside the updated date. Again, not an actual date-time.

Because those strings are not parseable, hooking in `dateutil`/`dateparser` will not magically fix them. If you ever run into a registry that does return a genuine but locale-specific value, pass a fallback parser explicitly:

```python
from dateutil import parser as dateutil_parser
parser = WhoisParser(date_parser=dateutil_parser.parse)
```

Keep in mind that locale-aware libraries are substantially slower than the Structly fast path. Parsing the 452 raw date strings directly takes roughly `0.40s` with `dateutil` and `2.08s` with `dateparser` on this machine, compared to effectively zero overhead when the builtin formats match. If you only need a fallback for a handful of problematic TLDs, wire it in conditionally rather than enabling it globally.

### Streaming from S3

```python
import boto3
import gzip
import tarfile
from structly_whois import WhoisParser

def iter_whois_payloads(bucket: str, key: str):
    """Stream WHOIS samples from an S3-hosted tar.gz without touching disk."""
    s3 = boto3.client("s3")
    obj = s3.get_object(Bucket=bucket, Key=key)
    with gzip.GzipFile(fileobj=obj["Body"]) as gz:
        with tarfile.open(fileobj=gz, mode="r:") as tar:
            for member in tar:
                if not member.isfile():
                    continue
                raw = tar.extractfile(member).read().decode("utf-8", errors="ignore")
                yield raw

parser = WhoisParser()
payloads = iter_whois_payloads("whois-dumps", "2024-12.tar.gz")

for chunk in parser.parse_chunks(payloads, chunk_size=512):
    process(chunk)  # bulk insert, publish, etc.
```

### Kafka batch ingestion

Need to process live WHOIS feeds? `benchmarks/scripts/consume_and_parse.py` shows how to wire `WhoisParser` into a Kafka consumer, group messages by TLD, and issue `parse_many` calls per bucket. Grouping domains ensures each batch uses the right Structly override and minimizes parser cache churn, so `.com.br` payloads never run through `.com` rules while still keeping throughput high.

### Performance tip: pass `domain=` or `tld=` when you know it

Inference keeps things convenient, but the fastest path is to tell the parser what you already know:

```python
from structly_whois import WhoisParser

parser = WhoisParser()

# Fastest path: you know the exact domain
record = parser.parse_record(raw_text, domain="example.com")

# Fast bulk parsing: you know every payload shares the same TLD
parsed = parser.parse_many(payloads, tld="com")
records = parser.parse_many(payloads, tld="com", to_records=True)
```

If you omit both `domain` and `tld`, `WhoisParser` inspects the payload and picks the right override automatically. That path is still efficient, but providing hints avoids the inference work entirely.

### Custom Structly Config overrides

`structly_whois` is built for easy extensibility—you can extend the bundled Structly configs or replace
  them entirely, so parser behavior stays configurable without forking.

```python
from structly import FieldPattern
from structly_whois import StructlyConfigFactory, WhoisParser

factory = StructlyConfigFactory(
    base_field_definitions={
        "domain_name": {"patterns": [FieldPattern.regex(r"^dn:\s*(?P<val>[a-z0-9.-]+)$")]},
    },
    tld_overrides={},
)
parser = WhoisParser(preload_tlds=("dev",), config_factory=factory)
parser.register_tld(
    "app",
    {
        "domain_name": {
            "extend_patterns": [FieldPattern.starts_with("App Domain:")],
        }
    },
)
```

## API overview

| Component | Description |
| --------- | ----------- |
| `structly_whois.WhoisParser` | High-level parser with batching, record conversion, and optional CLI integration. |
| `structly_whois.StructlyConfigFactory` | Factory that builds Structly configs with base fields + TLD overrides. |
| `structly_whois.records.WhoisRecord` | Typed msgspec struct with `to_dict()` for JSON serialization. |
| `structly_whois.normalize_raw_text` | Fast trimming of noise, privacy banners, and multiline headers. |
| `structly_whois.cli` | Argparse-powered CLI that mirrors the Python API. |

## Benchmarks

`make bench` runs `benchmarks/run_benchmarks.py`, comparing structly_whois against `whois-parser` and `python-whois`. 
Default settings parse all fixtures ×100 iterations on a MacBook Pro (M4, Python 3.14):

| backend                   |   records | records/s   |   avg latency (ms) |
|---------------------------|-----------|-------------|--------------------|
| structly-whois            |     18400 | 7,788       |              0.128 |
| structly-whois+dateutil   |     18400 | 7,130       |              0.14  |
| structly-whois+dateparser |     18400 | 804         |              1.244 |
| whois-parser              |     18400 | 19          |             52.724 |
| python-whois              |     18400 | 368         |              2.718 |

“dateutil” uses `date_parser=dateutil.parser.parse`; “dateparser” uses `date_parser=dateparser.parse`. Both illustrate how heavier date coercion affects throughput.

Example invocations:

```bash
# run every backend on all fixtures (default BENCHMARK_BACKENDS env)
python benchmarks/run_benchmarks.py

# run a custom backend list while keeping all fixtures
BENCHMARK_BACKENDS="structly-whois,structly-whois+date" \
  python benchmarks/run_benchmarks.py --iterations 100 --domains all

# focus on a couple of tricky registries with fewer iterations
python benchmarks/run_benchmarks.py --iterations 10 --domains google.com google.com.br
```

Add `--save-result` to persist the summary to `benchmarks/results.md` (or a custom `--output` path); otherwise runs print results to stdout only.

## Development

```bash
make lint     # Ruff (E/F/W/I/UP/B/SIM)
make fmt      # Ruff formatter across src/tests/benchmarks
make test     # pytest + coverage (Hypothesis fixtures)
make cov      # coverage xml/report (≥90%)
make bench    # compare structly_whois vs whois-parser/python-whois
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for versioning, release, and pull-request guidelines. 
CI (GitHub Actions) runs lint/test/build on every push; pushes to `dev` publish wheels to TestPyPI and tags `vX.Y.Z` publish to PyPI.

## License

MIT © Nikola Stankovic.
