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

> Fast, typed WHOIS parsing powered by [structly](https://pypi.org/project/structly/) and [msgspec](https://pypi.org/project/structly/).

**structly_whois** wraps Structly's compiled parsers with a modern Python API so you can normalize noisy WHOIS payloads, auto-detect TLD-specific overrides, and emit JSON-ready records without hauling heavy regex DSLs or dateparser into your hot path.

## Highlights

- **Structly speed** – Per-TLD configurations are compiled by Structly, keeping parsing under a millisecond/record even on commodity hardware.
- **Typed surface** – msgspec-based `WhoisRecord` structs, `py.typed` wheels, and a CLI entrypoint (`structly-whois`) for quick inspection.
- **Configurable** – Inject your own Structly configs, register TLD overrides at runtime, or extend the base field definitions without forking.
- **Lean dependencies** – No `dateparser` or `requests` required. Plug in a `date_parser` callable only when locale-aware coercion is truly needed.
- **Batched & streaming friendly** – `parse_many` and `parse_chunks` let you process millions of payloads from queues, tarballs, or S3 archives without buffering everything in memory.

## Installation

```bash
pip install structly-whois               # end users
pip install -e '.[dev]'                  # contributors (installs Ruff, pytest, etc.)
```

Python 3.9+ is supported. Wheels ship `py.typed` markers for static analyzers.

## Quickstart

```python
from structly_whois import WhoisParser

parser = WhoisParser()
payload = """\
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

## CLI usage

```bash
structly-whois tests/samples/whois/google.com.txt \
  --domain google.com \
  --record --json \
  --date-parser tests.helpers:iso_to_datetime
```

The CLI mirrors the Python API: pass `--record` to emit a structured `WhoisRecord`, `--lowercase` to normalize strings, and `--date-parser module:callable` when you want custom date coercion.

## Advanced usage

### Batched parsing

```python
parser = WhoisParser()
payloads: list[str] = fetch_from_queue()
records = parser.parse_many(payloads, to_records=True, lowercase=True)
for record in records:
    ingest(record)  # bulk insert, emit to Kafka, etc.
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
Default settings parse all 105 fixtures ×100 iterations on a MacBook Pro (M4, Python 3.14):

| backend                   | records | records/s | avg latency (ms) |
| ------------------------- | ------- | --------- | ---------------- |
| structly-whois            | 10,500  | 7,779     | 0.129            |
| structly-whois + dateutil | 10,500  | 3,236     | 0.309            |
| structly-whois + dateparser | 10,500 | 996      | 1.004            |
| python-whois              | 10,500  | 196       | 5.096            |
| whois-parser              | 10,500  | 17        | 58.229           |

“dateutil” uses `date_parser=dateutil.parser.parse`; “dateparser” uses `date_parser=dateparser.parse`. Both illustrate how heavier date coercion affects throughput.

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
