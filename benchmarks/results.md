# Benchmark Results

- samples: 184
- iterations per sample: 100

| backend                   |   records | records/s   |   avg latency (ms) |
|---------------------------|-----------|-------------|--------------------|
| structly-whois            |     18400 | 7,788       |              0.128 |
| structly-whois+dateutil   |     18400 | 7,130       |              0.14  |
| structly-whois+dateparser |     18400 | 804         |              1.244 |
| whois-parser              |     18400 | 19          |             52.724 |
| python-whois              |     18400 | 368         |              2.718 |

Leader: structly-whois (7,788 records/s, 0.128 ms per record)
