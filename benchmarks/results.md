# Benchmark Results

- samples: 1
- iterations per sample: 250

| backend                   |   records | records/s   |   avg latency (ms) |
|---------------------------|-----------|-------------|--------------------|
| structly-whois            |       250 | 7,014       |              0.143 |
| structly-whois+dateutil   |       250 | 7,734       |              0.129 |
| structly-whois+dateparser |       250 | 7,797       |              0.128 |
| whois-parser              |       250 | 7           |            139.802 |
| python-whois              |       250 | 560         |              1.787 |

Leader: structly-whois+dateparser (7,797 records/s, 0.128 ms per record)
