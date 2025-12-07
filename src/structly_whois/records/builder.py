from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Callable, Optional

import msgspec

from .models import Abuse, Admin, DateParser, Registrant, Tech, WhoisPayload, WhoisRecord
from .utils import _build_contact, _lower_if_needed, _parse_date_field, _prepare_list

WHOIS_RATE_LIMIT_MESSAGES: set[str] = {
    "WHOIS LIMIT EXCEEDED - SEE WWW.PIR.ORG/WHOIS FOR DETAILS",
    "Your access is too fast,please try again later.",
    "Your connection limit exceeded.",
    "Number of allowed queries exceeded.",
    "WHOIS LIMIT EXCEEDED",
    "Requests of this client are not permitted.",
    "Too many connection attempts. Please try again in a few seconds.",
    "We are unable to process your request at this time.",
    "HTTP/1.1 400 Bad Request",
    "Closing connections because of Timeout",
    "Access to whois service at whois.isoc.org.il was **DENIED**",
    "IP Address Has Reached Rate Limit",
}


def is_rate_limited_payload(raw_text: str) -> bool:
    return raw_text.strip() in WHOIS_RATE_LIMIT_MESSAGES


ScalarNormalizer = Callable[[Optional[str], bool], Optional[str]]
ListNormalizer = Callable[[Optional[list[str]], bool], list[str]]
DateFieldParser = Callable[[Optional[str], bool, Optional[DateParser]], Optional[Any]]


@dataclass
class RecordBuilder:
    scalar_normalizer: ScalarNormalizer = _lower_if_needed
    list_normalizer: ListNormalizer = _prepare_list
    contact_factory: Callable[..., msgspec.Struct] = _build_contact
    date_field_parser: DateFieldParser = _parse_date_field

    def build(
        self,
        raw_text: str,
        parsed: Mapping[str, Any],
        *,
        lowercase: bool = False,
        date_parser: DateParser | None = None,
    ) -> WhoisRecord:
        try:
            payload = msgspec.convert(parsed, WhoisPayload)
        except msgspec.ValidationError as exc:
            raise ValueError("Invalid WHOIS payload") from exc

        registrant = self.contact_factory(
            Registrant,
            name=payload.registrant_name,
            email=payload.registrant_email,
            organization=payload.registrant_organization,
            telephone=payload.registrant_telephone,
            lowercase=lowercase,
        )
        admin = self.contact_factory(
            Admin,
            name=payload.admin_name,
            email=payload.admin_email,
            organization=payload.admin_organization,
            telephone=payload.admin_telephone,
            lowercase=lowercase,
        )
        tech = self.contact_factory(
            Tech,
            name=payload.tech_name,
            email=payload.tech_email,
            organization=payload.tech_organization,
            telephone=payload.tech_telephone,
            lowercase=lowercase,
        )
        abuse = Abuse(
            email=self.scalar_normalizer(payload.abuse_email, lowercase=lowercase),
            telephone=self.scalar_normalizer(payload.abuse_telephone, lowercase=lowercase),
        )

        statuses = self.list_normalizer(payload.status, lowercase=lowercase)
        name_servers = self.list_normalizer(payload.name_servers, lowercase=lowercase)

        return WhoisRecord(
            raw_text=raw_text,
            registrant=registrant,
            admin=admin,
            tech=tech,
            abuse=abuse,
            statuses=statuses,
            name_servers=name_servers,
            domain=self.scalar_normalizer(payload.domain_name, lowercase=lowercase),
            registrar=self.scalar_normalizer(payload.registrar, lowercase=lowercase),
            registrar_id=self.scalar_normalizer(payload.registrar_id, lowercase=lowercase),
            registrar_url=self.scalar_normalizer(payload.registrar_url, lowercase=lowercase),
            dnssec=self.scalar_normalizer(payload.dnssec, lowercase=lowercase),
            registered_at=self.date_field_parser(
                payload.creation_date,
                lowercase=lowercase,
                date_parser=date_parser,
            ),
            updated_at=self.date_field_parser(
                payload.updated_date,
                lowercase=lowercase,
                date_parser=date_parser,
            ),
            expires_at=self.date_field_parser(
                payload.expiration_date,
                lowercase=lowercase,
                date_parser=date_parser,
            ),
            is_rate_limited=is_rate_limited_payload(raw_text),
        )


_DEFAULT_BUILDER = RecordBuilder()


def build_whois_record(
    raw_text: str,
    parsed: Mapping[str, Any],
    *,
    lowercase: bool = False,
    date_parser: DateParser | None = None,
) -> WhoisRecord:
    return _DEFAULT_BUILDER.build(
        raw_text,
        parsed,
        lowercase=lowercase,
        date_parser=date_parser,
    )


__all__ = ["build_whois_record", "is_rate_limited_payload", "RecordBuilder"]
