# structly-whois-parser

A thin WHOIS parsing layer built on top of [structly](https://github.com/bytevader/structly).
It loads per-TLD structly configurations, pre-compiles parsers, and normalizes raw WHOIS
records so only the latest response (after the last `# server` marker) is processed.

## WHOIS parser configuration

Every `WhoisParser` instance uses a `StructlyConfigFactory` to generate Structly configs.  
By default the parser is preloaded with `DEFAULT_TLDS` and the canned overrides found in
`src/structly_whois_parser/config.py`. If you never pass anything in, each lookup uses that
shared factory and you can treat the parser as a black box.

### Extending the default config

Extend or override the baked-in TLD settings by either providing `extra_tld_overrides`
during construction or calling `register_tld` later:

```python
from structly import FieldPattern
from structly_whois_parser import WhoisParser

parser = WhoisParser(
    extra_tld_overrides={
        "dev": {
            "domain_name": {
                "extend_patterns": [FieldPattern.regex(r"^custom-domain:\s*(?P<val>.+)$")]
            }
        }
    }
)

# add or replace TLD definitions at runtime
parser.register_tld(
    "io",
    {
        "registrar": {
            "patterns": [FieldPattern.regex(r"^Registrar Name:\s*(?P<val>.+)$")],
        }
    },
    replace=False,   # set True to fully replace the previous field spec
    preload=True,    # rebuild the Structly parser immediately
)
```

### Supplying your own factory

If you want to control the base field set (or inject definitions from elsewhere), create
your own `StructlyConfigFactory` and hand it to `WhoisParser`. The factory clones the data
you pass in so you can mutate it freely later.

```python
from structly import FieldPattern
from structly_whois_parser import StructlyConfigFactory, WhoisParser

factory = StructlyConfigFactory(
    base_field_definitions={
        "domain_name": {
            "patterns": [FieldPattern.regex(r"^dn:\s*(?P<val>[a-z0-9._-]+)$")],
        }
    },
    tld_overrides={},  # start empty and register TLDs yourself
)
parser = WhoisParser(preload_tlds=("dev", "app"), config_factory=factory)

# later you can rebuild the default parser after tweaking the factory
factory.extend_base_field("domain_name", extend_patterns=[FieldPattern.starts_with("Domain Name:")])
parser.refresh_default_parser()
```

Under the hood, `WhoisParser` resolves the target TLD, asks the factory for a `StructlyConfig`
and then instantiates (or reuses) a `StructlyParser`. Unknown TLDs fall back to a default
parser built without overrides, so you can always parse something even before registering a TLD.

## Local development

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .[dev]
python -m pytest
```

Test fixtures under `vendor/` come from:

- https://github.com/ninoseki/whois-parser (WHOIS raw samples)
- https://github.com/richardpenman/whois (expected field snapshots)

## Benchmarking

To measure throughput on the historical WHOIS dataset:

```bash
source venv/bin/activate
python benchmarks/benchmark_whois.py            # parses every sample 1000×
python benchmarks/benchmark_whois.py google.com # restrict to one file

# Parse 500 records at a time with rayon policy set to "always"
python benchmarks/benchmark_whois.py \
  --method parse_many \
  --batch-size 500 \
  --rayon-policy always \
  --parse-many-to-records \
  --record-to-dict            # also exercise record.to_dict serialization
```
