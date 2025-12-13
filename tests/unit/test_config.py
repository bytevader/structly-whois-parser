from __future__ import annotations

import pytest
from structly import FieldPattern, Mode, ReturnShape

from structly_whois import StructlyConfigFactory, WhoisParser
from structly_whois.config import _build_field_spec


def test_structly_config_factory_accepts_custom_patterns() -> None:
    factory = StructlyConfigFactory(
        base_field_definitions={
            "domain_name": {
                "patterns": [FieldPattern.regex(r"(?i)^dn:\s*(?P<val>[a-z0-9._-]+)$")],
            }
        },
        tld_overrides={},
    )
    parser = WhoisParser(preload_tlds=("dev",), config_factory=factory)

    parsed = parser.parse("DN: Example.dev", tld="dev")

    assert parsed["domain_name"] == "Example.dev"


def test_register_tld_replace_overrides_previous_patterns() -> None:
    factory = StructlyConfigFactory(
        base_field_definitions={
            "domain_name": {
                "patterns": [FieldPattern.regex(r"(?i)^domain:\s*(?P<val>[a-z0-9._-]+)$")],
            }
        },
        tld_overrides={},
    )
    parser = WhoisParser(preload_tlds=(), config_factory=factory)
    parser.register_tld(
        "custom",
        {
            "domain_name": {
                "patterns": [FieldPattern.regex(r"(?i)^custom-domain:\s*(?P<val>[a-z0-9._-]+)$")],
            }
        },
        replace=True,
    )

    parsed = parser.parse("Custom-Domain: sample.dev", tld="custom")

    assert parsed["domain_name"] == "sample.dev"


def test_factory_accessors_and_base_field_cloning() -> None:
    factory = StructlyConfigFactory()
    base_fields = factory.base_fields
    assert "domain_name" in base_fields
    assert factory.known_tlds
    original = base_fields["domain_name"]["patterns"]
    clone = factory.get_base_field("domain_name")
    clone["patterns"].append(FieldPattern.regex(r"(?i)^fake:\s*(?P<val>.+)$"))
    assert clone["patterns"] != original

    factory.register_base_field(
        "custom_field",
        {"patterns": [FieldPattern.regex(r"(?i)^custom:\s*(?P<val>.+)$")]},
    )
    factory.extend_base_field(
        "custom_field",
        extend_patterns=[FieldPattern.regex(r"(?i)^custom-extra:\s*(?P<val>.+)$")],
    )
    with pytest.raises(KeyError):
        factory.extend_base_field("missing", extend_patterns=[])


def test_register_tld_merge_and_validation() -> None:
    factory = StructlyConfigFactory(tld_overrides={})
    factory.register_tld(
        "example",
        {"domain_name": {"extend_patterns": [FieldPattern.regex(r"(?i)^example:\s*(?P<val>.+)$")]}},
    )
    factory.register_tld(
        "example",
        {"registrar": {"patterns": [FieldPattern.regex(r"(?i)^registrar:\s*(?P<val>.+)$")]}},
        replace=False,
    )
    assert "registrar" in factory.tld_overrides["example"]
    with pytest.raises(ValueError):
        factory.register_tld("", {})


def test_build_field_spec_respects_override_ordering() -> None:
    base_def = {
        "patterns": [FieldPattern.starts_with("Domain:")],
        "mode": Mode.first,
        "unique": False,
        "return_shape": ReturnShape.scalar,
    }
    override = {
        "prepend_patterns": [FieldPattern.starts_with("Primary:")],
        "extend_patterns": [FieldPattern.starts_with("Extra:")],
        "mode": Mode.all,
        "unique": True,
        "return_shape": ReturnShape.list_,
    }

    spec = _build_field_spec(base_def, override)

    assert spec.mode == Mode.all
    assert spec.unique is True
    assert spec.return_shape == ReturnShape.list_
    assert [p.runtime_value() for p in spec.patterns][0].endswith("Primary:")
