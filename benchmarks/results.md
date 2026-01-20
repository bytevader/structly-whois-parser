# Benchmark Results

- samples: 146
- iterations per sample: 100

| backend                   |   records | records/s   |   avg latency (ms) |
|---------------------------|-----------|-------------|--------------------|
| structly-whois            |     14600 | 9,085       |              0.11  |
| structly-whois+dateutil   |     14600 | 8,996       |              0.111 |
| structly-whois+dateparser |     14600 | 1,465       |              0.683 |
| whois-parser              |     14600 | 19          |             52.556 |
| python-whois              |     14600 | 323         |              3.1   |

Leader: structly-whois (9,085 records/s, 0.110 ms per record)
