from __future__ import annotations

import copy
from datetime import datetime

import pytest

from structly_whois_parser.records import build_whois_record


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
