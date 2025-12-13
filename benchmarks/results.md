# Benchmark Results

- samples: 105
- iterations per sample: 100

| backend                   |   records | records/s   |   avg latency (ms) |
|---------------------------|-----------|-------------|--------------------|
| structly-whois            |     10500 | 7,861       |              0.127 |
| structly-whois+dateutil   |     10500 | 8,159       |              0.123 |
| structly-whois+dateparser |     10500 | 998         |              1.002 |
| whois-parser              |     10500 | 17          |             58.147 |
| python-whois              |     10500 | 440         |              2.272 |

Leader: structly-whois+dateutil (8,159 records/s, 0.123 ms per record)
