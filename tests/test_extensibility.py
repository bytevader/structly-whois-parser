from structly import FieldPattern, Mode, ReturnShape

from structly_whois_parser import StructlyConfigFactory, WhoisParser


def test_custom_base_field_overwrite() -> None:
    factory = StructlyConfigFactory(
        base_field_definitions={
            "domain_name": {
                "patterns": [
                    FieldPattern.regex(r"(?i)^dn:\s*(?P<val>[a-z0-9._-]+)$"),
                ]
            }
        },
        tld_overrides={},
    )
    parser = WhoisParser(preload_tlds=("dev",), config_factory=factory)
    payload = "DN: EXAMPLE.dev"

    result = parser.parse(payload, tld="dev")

    assert result["domain_name"] == "EXAMPLE.dev"


def test_extra_tld_overrides_extend_patterns_without_preload() -> None:
    factory = StructlyConfigFactory(
        base_field_definitions={
            "domain_name": {
                "patterns": [
                    FieldPattern.regex(r"(?i)^domain:\s*(?P<val>[a-z0-9._-]+)$"),
                ]
            }
        },
        tld_overrides={},
    )
    parser = WhoisParser(
        preload_tlds=(),
        config_factory=factory,
        extra_tld_overrides={
            "custom": {
                "domain_name": {
                    "extend_patterns": [
                        FieldPattern.regex(r"(?i)^custom-domain:\s*(?P<val>[a-z0-9._-]+)$"),
                    ]
                }
            }
        },
    )
    payload = "Custom-Domain: sample.dev"

    result = parser.parse(payload, tld="custom")

    assert result["domain_name"] == "sample.dev"


def test_register_tld_with_replace_overrides_patterns() -> None:
    factory = StructlyConfigFactory(
        base_field_definitions={
            "domain_name": {
                "patterns": [FieldPattern.regex(r"(?i)^domain:\s*(?P<val>[a-z0-9._-]+)$")]
            }
        },
        tld_overrides={},
    )
    parser = WhoisParser(preload_tlds=(), config_factory=factory)
    parser.register_tld(
        "custom",
        {
            "domain_name": {
                "patterns": [
                    FieldPattern.regex(r"(?i)^custom-domain:\s*(?P<val>[a-z0-9._-]+)$"),
                ]
            }
        },
        replace=True,
    )
    payload = "Custom-Domain: sample.dev"

    result = parser.parse(payload, tld="custom")

    assert result["domain_name"] == "sample.dev"
