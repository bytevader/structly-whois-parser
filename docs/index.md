# structly_whois

structly_whois wraps [Structly](https://pypi.org/project/structly/) configs with a typed Python API, giving you deterministic WHOIS parsing without hauling heavy regex DSLs or `dateparser` into your pipelines. Use this page as a quick reference; the [README](../README.md) dives deeper into advanced usage and streaming examples.

## Install

```bash
pip install structly-whois          # runtime usage
pip install -e '.[dev]'             # contributors
```

## Core usage

```python
from structly_whois import WhoisParser

parser = WhoisParser()
record = parser.parse_record(raw_payload, domain="example.com")
print(record.to_dict())
```

CLI entry point:

```bash
structly-whois whois.txt --domain example.com --record --json \
  --date-parser tests.common.helpers:iso_to_datetime
```

## Feature snapshot

- Structly-backed parsers for popular gTLDs/ccTLDs with runtime overrides.
- msgspec `WhoisRecord` structs and `py.typed` wheels for tooling.
- Optional `date_parser` hook (bring your own callable when you need locale-specific conversions).
- Streaming-friendly APIs (`parse_many`, `parse_chunks`) for queues, tarballs, or S3 archives.
- CLI for quick inspection plus a benchmarking harness (`make bench`).

## Tooling & workflows

| Command | Description |
| ------- | ----------- |
| `make lint` | Ruff lint (E/F/W/I/UP/B/SIM) |
| `make fmt` | Ruff formatter |
| `make test` | pytest + coverage (≥90%) |
| `make bench` | Compare structly_whois vs whois-parser / python-whois |

Release automation lives in GitHub Actions: pushes to `dev` publish to TestPyPI and tags `vX.Y.Z` publish to PyPI. See [CONTRIBUTING](../CONTRIBUTING.md) for the full workflow.
