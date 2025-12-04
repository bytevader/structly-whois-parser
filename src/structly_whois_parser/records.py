"""Structured WHOIS data models and conversion helpers."""
from __future__ import annotations

import re
import re
from datetime import datetime
from typing import Any, Callable, Mapping, Optional, TypeVar, Union, Set, List
import msgspec

WHOIS_RATE_LIMIT_MESSAGES: Set[str] = {
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
    """Return True when the response matches a known rate-limit banner."""
    return raw_text.strip() in WHOIS_RATE_LIMIT_MESSAGES


class Contact(msgspec.Struct):
    organization: Optional[str] = None
    email: Optional[str] = None
    name: Optional[str] = None
    telephone: Optional[str] = None


class Tech(Contact):
    """Technical contact."""


class Registrant(Contact):
    """Domain registrant contact."""


class Admin(Contact):
    """Administrative contact."""


class Abuse(msgspec.Struct):
    email: Optional[str] = None
    telephone: Optional[str] = None


ParsedDate = Union[datetime, str]


def _strip(value: str) -> str:
    return value.strip()


def _normalize_iso8601(value: str) -> str:
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    if len(text) >= 6 and text[-6] in "+-" and text[-3] == ":":
        text = text[:-3] + text[-2:]
    return text


def _strip_periods(value: str) -> str:
    return value.replace(" ", "")


_TRAILING_PAREN_RE = re.compile(r"\s*\((?P<tz>[^)]+)\)\s*$")


def _strip_trailing_paren(value: str) -> str:
    return _TRAILING_PAREN_RE.sub("", value)


def _extract_trailing_timezone(value: str) -> tuple[str, str | None]:
    match = _TRAILING_PAREN_RE.search(value)
    if not match:
        return value, None
    tz = match.group("tz")
    cleaned = value[: match.start()].strip()
    return cleaned, tz


_FAST_DATETIME_FORMATS: tuple[tuple[str, Callable[[str], str]], ...] = (
    ("%Y-%m-%dT%H:%M:%S.%f%z", _normalize_iso8601),
    ("%Y-%m-%dT%H:%M:%S%z", _normalize_iso8601),
    ("%Y-%m-%dT%H:%M:%S", _strip),
    ("%Y-%m-%d %H:%M:%S.%f", _strip),
    ("%Y-%m-%d %H:%M:%S", _strip),
    ("%Y%m%d %H:%M:%S", _strip),
    ("%Y%m%d", _strip),
    ("%Y-%m-%d", _strip),
    ("%Y/%m/%d", _strip),
    ("%d-%m-%Y", _strip),
    ("%m.%d.%Y %H:%M:%S", _strip),
    ("%m.%d.%Y", _strip),
    ("%d.%m.%Y", _strip),
    ("%Y.%m.%d.", _strip_periods),
    ("%Y.%m.%d %H:%M:%S", _strip),
    ("%d.%m.%Y %H:%M:%S", _strip),
    ("%d-%b-%Y", _strip),
    ("%d-%b-%Y %H:%M:%S", _strip),
    ("%a %b %d %Y", _strip),
    ("%Y/%m/%d %H:%M:%S", _strip_trailing_paren),
)


def _try_fast_datetime_parse(value: str) -> datetime | None:
    for fmt, normalizer in _FAST_DATETIME_FORMATS:
        candidate = normalizer(value)
        try:
            return datetime.strptime(candidate, fmt)
        except ValueError:
            continue
    return None


class WhoisRecord(msgspec.Struct):
    raw_text: str

    registrant: Registrant
    admin: Admin
    tech: Tech
    abuse: Abuse

    statuses: List[str] = msgspec.field(default_factory=List)
    name_servers: List[str] = msgspec.field(default_factory=List)

    domain: Optional[str] = None
    registrar: Optional[str] = None
    registrar_id: Optional[str] = None
    registrar_url: Optional[str] = None
    dnssec: Optional[str] = None

    expires_at: Optional[ParsedDate] = None
    registered_at: Optional[ParsedDate] = None
    updated_at: Optional[ParsedDate] = None

    is_rate_limited: bool = False

    def to_dict(self, *, include_raw_text: bool = True) -> dict[str, Any]:
        """Convert the struct into basic Python types (JSON friendly)."""
        data = msgspec.to_builtins(self)  # converts datetimes/contact structs recursively
        if not include_raw_text:
            data.pop("raw_text", None)
        return data


class _WhoisPayload(msgspec.Struct, forbid_unknown_fields=True):
    domain_name: Optional[str] = None
    registrar: Optional[str] = None
    registrar_id: Optional[str] = None
    registrar_url: Optional[str] = None
    creation_date: Optional[str] = None
    updated_date: Optional[str] = None
    expiration_date: Optional[str] = None
    name_servers: Optional[list[str]] = None
    status: Optional[list[str]] = None
    registrant_name: Optional[str] = None
    registrant_organization: Optional[str] = None
    registrant_email: Optional[str] = None
    registrant_telephone: Optional[str] = None
    admin_name: Optional[str] = None
    admin_organization: Optional[str] = None
    admin_email: Optional[str] = None
    admin_telephone: Optional[str] = None
    tech_name: Optional[str] = None
    tech_organization: Optional[str] = None
    tech_email: Optional[str] = None
    tech_telephone: Optional[str] = None
    dnssec: Optional[str] = None
    abuse_email: Optional[str] = None
    abuse_telephone: Optional[str] = None


def _apply_timezone(value: datetime, tz: str | None) -> datetime:
    if not tz:
        return value
    # Handle basic offsets like +09:00 or +0900
    if tz.startswith(("+", "-")):
        formatted = tz if ":" in tz else f"{tz[:-2]}:{tz[-2:]}"
        try:
            offset = datetime.strptime(formatted, "%z").tzinfo
            return value.replace(tzinfo=offset)
        except ValueError:
            return value
    # Fallback lookup for common abbreviations
    tz_offsets = {
        "JST": "+09:00",
        "UTC": "+00:00",
        "GMT": "+00:00",
    }
    offset = tz_offsets.get(tz.upper())
    if offset:
        try:
            tzinfo = datetime.strptime(offset, "%z").tzinfo
            return value.replace(tzinfo=tzinfo)
        except ValueError:
            return value
    return value


def parse_datetime(date_string: str) -> ParsedDate:
    """
    Parse a WHOIS timestamp using dateparser.

    Falls back to the original string when parsing fails.
    """
    if not date_string:
        return date_string
    stripped, tz = _extract_trailing_timezone(date_string.strip())
    normalized = stripped.replace(" .", "")
    if not normalized:
        return date_string
    fast_parsed = _try_fast_datetime_parse(normalized)
    if fast_parsed is not None:
        return _apply_timezone(fast_parsed, tz)
    return normalized


def _lower_if_needed(value: Optional[str], *, lowercase: bool) -> Optional[str]:
    if value is None or not lowercase:
        return value
    return value.lower()


def _prepare_list(values: Optional[List[str]], *, lowercase: bool) -> List[str]:
    if not values:
        return []
    filtered = [value for value in values if value]
    seen: set[str] = set()
    prepared: List[str] = []
    for value in filtered:
        transformed = value.lower() if lowercase else value
        key = transformed.lower()
        if key in seen:
            continue
        seen.add(key)
        prepared.append(transformed)
    return prepared


def _parse_date_field(value: Optional[str], *, lowercase: bool) -> Optional[ParsedDate]:
    if not value:
        return None
    parsed = parse_datetime(value)
    if isinstance(parsed, str):
        return parsed.lower() if lowercase else parsed
    return parsed


ContactType = TypeVar("ContactType", bound=Contact)


def _build_contact(
    contact_type: type[ContactType],
    *,
    name: Optional[str],
    email: Optional[str],
    organization: Optional[str],
    telephone: Optional[str],
    lowercase: bool,
) -> ContactType:
    return contact_type(
        name=_lower_if_needed(name, lowercase=lowercase),
        email=_lower_if_needed(email, lowercase=lowercase),
        organization=_lower_if_needed(organization, lowercase=lowercase),
        telephone=_lower_if_needed(telephone, lowercase=lowercase),
    )


def build_whois_record(
    raw_text: str,
    parsed: Mapping[str, Any],
    *,
    lowercase: bool = False,
) -> WhoisRecord:
    """
    Validate a parsed WHOIS mapping and convert it into a structured record.
    """
    try:
        payload = msgspec.convert(parsed, _WhoisPayload)
    except msgspec.ValidationError as exc:
        raise ValueError("Invalid WHOIS payload") from exc

    registrant = _build_contact(
        Registrant,
        name=payload.registrant_name,
        email=payload.registrant_email,
        organization=payload.registrant_organization,
        telephone=payload.registrant_telephone,
        lowercase=lowercase,
    )
    admin = _build_contact(
        Admin,
        name=payload.admin_name,
        email=payload.admin_email,
        organization=payload.admin_organization,
        telephone=payload.admin_telephone,
        lowercase=lowercase,
    )
    tech = _build_contact(
        Tech,
        name=payload.tech_name,
        email=payload.tech_email,
        organization=payload.tech_organization,
        telephone=payload.tech_telephone,
        lowercase=lowercase,
    )
    abuse = Abuse(
        email=_lower_if_needed(payload.abuse_email, lowercase=lowercase),
        telephone=_lower_if_needed(payload.abuse_telephone, lowercase=lowercase),
    )

    statuses = _prepare_list(payload.status, lowercase=lowercase)
    name_servers = _prepare_list(payload.name_servers, lowercase=lowercase)

    return WhoisRecord(
        raw_text=raw_text,
        registrant=registrant,
        admin=admin,
        tech=tech,
        abuse=abuse,
        statuses=statuses,
        name_servers=name_servers,
        domain=_lower_if_needed(payload.domain_name, lowercase=lowercase),
        registrar=_lower_if_needed(payload.registrar, lowercase=lowercase),
        registrar_id=_lower_if_needed(payload.registrar_id, lowercase=lowercase),
        registrar_url=_lower_if_needed(payload.registrar_url, lowercase=lowercase),
        dnssec=_lower_if_needed(payload.dnssec, lowercase=lowercase),
        registered_at=_parse_date_field(payload.creation_date, lowercase=lowercase),
        updated_at=_parse_date_field(payload.updated_date, lowercase=lowercase),
        expires_at=_parse_date_field(payload.expiration_date, lowercase=lowercase),
        is_rate_limited=is_rate_limited_payload(raw_text),
    )


__all__ = [
    "Abuse",
    "Admin",
    "Contact",
    "Registrant",
    "Tech",
    "WhoisRecord",
    "build_whois_record",
    "is_rate_limited_payload",
    "parse_datetime",
]
