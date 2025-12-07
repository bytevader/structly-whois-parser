# Benchmark methodology

`benchmarks/run_benchmarks.py` compares structly_whois (Structly-backed) with popular Python WHOIS libraries. It measures end-to-end throughput using `time.perf_counter()` while each backend parses every fixture under `tests/samples/whois/` for the configured number of iterations (default: 100). The script prints a GitHub-style table and writes `benchmarks/results.md` so CI pipelines can surface deltas easily.

## Reproducing

```bash
pip install structly-whois[dev]
make bench                                   # structly_whois + optional whois-parser/python-whois across every fixture (100× per sample)
make bench BENCHMARK_BACKENDS=structly-whois,whois-parser,python-whois
python benchmarks/run_benchmarks.py --iterations 250 --domains google.com --output /tmp/results.md
```

Backends that are not installed are skipped with a warning; structly_whois always runs. Pass `--domains` to focus on a smaller slice when you need faster turnaround.

## Sample output (MacBook Pro, M4, Python 3.14)

| backend                   | records | records/s | avg latency (ms) |
| ------------------------- | ------- | --------- | ---------------- |
| structly-whois            | 10,500  | 7,779     | 0.129            |
| structly-whois + dateutil | 10,500  | 3,236     | 0.309            |
| structly-whois + dateparser | 10,500 | 996      | 1.004            |
| python-whois              | 10,500  | 196       | 5.096            |
| whois-parser              | 10,500  | 17        | 58.229           |

The “dateutil” and “dateparser” rows run `WhoisParser` with `date_parser=dateutil.parser.parse` and `dateparser.parse`, respectively, highlighting the cost of heavier date coercion. See the [README](../README.md#benchmarks) for context and the comparison matrix against other libraries.
