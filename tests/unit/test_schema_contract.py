from __future__ import annotations

import re

import pytest

from structly_whois import WhoisParser
from structly_whois.records import WhoisRecord


def test_schema_version_exposed() -> None:
    assert hasattr(WhoisRecord, "schema_version")
    assert isinstance(WhoisRecord.schema_version, str)
    assert re.match(r"^\d+(\.\d+)*$", WhoisRecord.schema_version)


def test_supported_tlds_returns_set() -> None:
    parser = WhoisParser()
    result = parser.supported_tlds()
    assert isinstance(result, set)
    assert result  # we ship built-in overrides
    assert all(isinstance(item, str) for item in result)


def test_field_catalog_default_surface() -> None:
    parser = WhoisParser()
    catalog = parser.field_catalog()
    assert isinstance(catalog, dict)
    for required in ("domain", "registrar", "statuses", "name_servers"):
        assert required in catalog


def test_field_catalog_surfaces() -> None:
    parser = WhoisParser()
    record_catalog = parser.field_catalog("record")
    dict_catalog = parser.field_catalog("dict")
    both = parser.field_catalog("both")
    assert set(record_catalog).issubset(set(both))
    assert set(dict_catalog).issubset(set(both))
    assert "domain_name" in dict_catalog  # base Structly field
    with pytest.raises(ValueError):
        parser.field_catalog("invalid")  # type: ignore[arg-type]
