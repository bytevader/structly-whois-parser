from __future__ import annotations

import copy
from datetime import datetime, timezone

import pytest

from structly_whois.records import _apply_timezone, _prepare_list, build_whois_record, parse_datetime
from structly_whois.records.utils import _parse_date_field, _tzinfo_from_offset

BASE_PAYLOAD = {
    "admin_email": None,
    "admin_name": None,
    "admin_organization": None,
    "admin_telephone": None,
    "creation_date": "2014-03-20T12:59:17.0Z",
    "dnssec": "unsigned",
    "domain_name": "ABC.XYZ",
    "expiration_date": "2026-03-20T23:59:59.0Z",
    "name_servers": ["NS2.GOOGLE.COM", "NS4.GOOGLE.COM", "NS3.GOOGLE.COM", "NS1.GOOGLE.COM"],
    "registrant_email": None,
    "registrant_name": None,
    "registrant_organization": None,
    "registrant_telephone": None,
    "registrar": "MarkMonitor, Inc (TLDs)",
    "registrar_id": "292",
    "registrar_url": None,
    "status": [
        "clientTransferProhibited",
        "clientUpdateProhibited",
        "clientDeleteProhibited",
    ],
    "tech_email": None,
    "tech_name": None,
    "tech_organization": None,
    "tech_telephone": None,
    "updated_date": "2025-03-10T15:22:23.0Z",
}


@pytest.fixture()
def payload() -> dict[str, object]:
    return copy.deepcopy(BASE_PAYLOAD)


def test_build_whois_record_converts_dates(payload: dict[str, object]) -> None:
    record = build_whois_record("RAW", payload)

    assert record.domain == "ABC.XYZ"
    assert record.registrar_id == "292"
    assert record.dnssec == "unsigned"
    assert record.name_servers == payload["name_servers"]
    assert record.statuses == payload["status"]
    assert isinstance(record.registered_at, datetime)
    assert isinstance(record.updated_at, datetime)
    assert isinstance(record.expires_at, datetime)


def test_build_whois_record_can_lowercase(payload: dict[str, object]) -> None:
    record = build_whois_record("RAW", payload, lowercase=True)

    assert record.domain == "abc.xyz"
    assert record.registrar == "markmonitor, inc (tlds)"
    assert record.name_servers == ["ns2.google.com", "ns4.google.com", "ns3.google.com", "ns1.google.com"]
    assert record.statuses == [
        "clienttransferprohibited",
        "clientupdateprohibited",
        "clientdeleteprohibited",
    ]


def test_build_whois_record_validates_types(payload: dict[str, object]) -> None:
    payload["status"] = "not-a-list"  # type: ignore[assignment]
    with pytest.raises(ValueError):
        build_whois_record("RAW", payload)


def test_build_whois_record_marks_rate_limited(payload: dict[str, object]) -> None:
    raw = "WHOIS LIMIT EXCEEDED"
    record = build_whois_record(raw, payload)
    assert record.is_rate_limited is True


def test_whois_record_to_dict_serializes_contacts(payload: dict[str, object]) -> None:
    record = build_whois_record("RAW", payload)

    data = record.to_dict()

    assert data["domain"] == payload["domain_name"]
    assert isinstance(data["registrant"], dict)
    assert isinstance(data["registered_at"], str)
    assert data["raw_text"] == "RAW"

    trimmed = record.to_dict(include_raw_text=False)
    assert "raw_text" not in trimmed


def test_build_whois_record_handles_date_parser_value_error(payload: dict[str, object]) -> None:
    def flaky_parser(_: str) -> datetime:
        raise ValueError("nope")

    payload["creation_date"] = "mystery date"

    record = build_whois_record("RAW", payload, date_parser=flaky_parser)

    assert record.registered_at == "mystery date"


def test_build_whois_record_raises_for_unexpected_date_parser_exception(payload: dict[str, object]) -> None:
    def bad_parser(_: str) -> datetime:
        raise RuntimeError("boom")

    payload["creation_date"] = "another mystery"

    with pytest.raises(RuntimeError):
        build_whois_record("RAW", payload, date_parser=bad_parser)


def test_parse_datetime_handles_missing_values() -> None:
    assert parse_datetime("") == ""
    assert parse_datetime("   ") == "   "


def test_parse_datetime_applies_known_timezone() -> None:
    result = parse_datetime("2024-01-01 00:00:00 (JST)")
    assert isinstance(result, datetime)
    assert result.tzinfo is not None


def test_apply_timezone_with_numeric_offset() -> None:
    dt = datetime(2024, 1, 1, tzinfo=timezone.utc)
    adjusted = _apply_timezone(dt, "+0900")
    assert adjusted.tzinfo is not None


def test_apply_timezone_returns_original_for_unknown_label() -> None:
    dt = datetime(2024, 1, 1, tzinfo=timezone.utc)
    assert _apply_timezone(dt, "XYZ") is dt


def test_prepare_list_deduplicates_and_lowercases() -> None:
    values = ["NS1.EXAMPLE.COM", None, "ns1.example.com", "NS2.EXAMPLE.COM"]
    prepared = _prepare_list(values, lowercase=True)
    assert prepared == ["ns1.example.com", "ns2.example.com"]


def test_parse_date_field_normalizes_on_value_error() -> None:
    def flaky(_: str) -> datetime:
        raise ValueError("nope")

    result = _parse_date_field("Mystery DATE", lowercase=True, date_parser=flaky)

    assert result == "mystery date"


def test_tzinfo_from_offset_rejects_invalid_values() -> None:
    assert _tzinfo_from_offset("bad") is None
