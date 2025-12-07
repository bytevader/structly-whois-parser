from __future__ import annotations

import re
from datetime import datetime, tzinfo
from typing import TypeVar

import msgspec

from .models import DateParser, ParsedDate

_TRAILING_PAREN_RE = re.compile(r"\s*\((?P<tz>[^)]+)\)\s*$")
_TZ_CACHE: dict[str, tzinfo] = {}


def _normalize_iso8601(value: str) -> str:
    text = value.strip()
    if text.endswith("Z"):
        text = f"{text[:-1]}+00:00"
    if len(text) >= 6 and text[-6] in "+-" and text[-3] == ":":
        text = f"{text[:-3]}{text[-2:]}"
    return text


def _strip_trailing_paren(value: str) -> str:
    return _TRAILING_PAREN_RE.sub("", value)


_FAST_DATETIME_FORMATS: tuple[tuple[str, callable], ...] = (
    ("%Y-%m-%dT%H:%M:%S.%f%z", _normalize_iso8601),
    ("%Y-%m-%dT%H:%M:%S%z", _normalize_iso8601),
    ("%Y-%m-%dT%H:%M:%S", lambda v: v.strip()),
    ("%Y-%m-%d %H:%M:%S.%f", lambda v: v.strip()),
    ("%Y-%m-%d %H:%M:%S", lambda v: v.strip()),
    ("%Y%m%d %H:%M:%S", lambda v: v.strip()),
    ("%Y%m%d", lambda v: v.strip()),
    ("%Y-%m-%d", lambda v: v.strip()),
    ("%Y/%m/%d", lambda v: v.strip()),
    ("%d-%m-%Y", lambda v: v.strip()),
    ("%m.%d.%Y %H:%M:%S", lambda v: v.strip()),
    ("%m.%d.%Y", lambda v: v.strip()),
    ("%d.%m.%Y", lambda v: v.strip()),
    ("%Y.%m.%d.", lambda v: v.replace(" ", "")),
    ("%Y.%m.%d %H:%M:%S", lambda v: v.strip()),
    ("%d.%m.%Y %H:%M:%S", lambda v: v.strip()),
    ("%d-%b-%Y", lambda v: v.strip()),
    ("%d-%b-%Y %H:%M:%S", lambda v: v.strip()),
    ("%a %b %d %Y", lambda v: v.strip()),
    ("%Y/%m/%d %H:%M:%S", _strip_trailing_paren),
)


def _extract_trailing_timezone(value: str) -> tuple[str, str | None]:
    match = _TRAILING_PAREN_RE.search(value)
    if not match:
        return value, None
    tz = match.group("tz")
    cleaned = value[: match.start()].strip()
    return cleaned, tz


def _try_fast_datetime_parse(value: str) -> datetime | None:
    for fmt, normalizer in _FAST_DATETIME_FORMATS:
        candidate = normalizer(value)
        try:
            return datetime.strptime(candidate, fmt)
        except ValueError:
            continue
    return None


def _apply_timezone(value: datetime, tz: str | None) -> datetime:
    if not tz:
        return value
    if tz.startswith(("+", "-")):
        offset_info = _tzinfo_from_offset(tz)
        if offset_info:
            return value.replace(tzinfo=offset_info)
        return value
    tz_offsets = {"JST": "+09:00", "UTC": "+00:00", "GMT": "+00:00"}
    offset = tz_offsets.get(tz.upper())
    if offset:
        offset_info = _tzinfo_from_offset(offset)
        if offset_info:
            return value.replace(tzinfo=offset_info)
    return value


def parse_datetime(date_string: str) -> ParsedDate:
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


def _lower_if_needed(value: str | None, *, lowercase: bool) -> str | None:
    if value is None or not lowercase:
        return value
    return value.lower()


def _prepare_list(values: list[str] | None, *, lowercase: bool) -> list[str]:
    if not values:
        return []
    filtered = [value for value in values if value]
    seen: set[str] = set()
    prepared: list[str] = []
    for value in filtered:
        transformed = value.lower() if lowercase else value
        key = transformed.lower()
        if key in seen:
            continue
        seen.add(key)
        prepared.append(transformed)
    return prepared


def _parse_date_field(
    value: str | None,
    *,
    lowercase: bool,
    date_parser: DateParser | None,
) -> ParsedDate | None:
    if not value:
        return None
    parsed = parse_datetime(value)
    if isinstance(parsed, datetime):
        return parsed
    source = parsed
    normalized = source.lower() if lowercase else source
    if date_parser is None:
        return normalized
    try:
        return date_parser(source)
    except ValueError:
        return normalized
    except Exception as exc:  # pragma: no cover
        raise RuntimeError("date_parser raised an unexpected exception") from exc


ContactType = TypeVar("ContactType", bound=msgspec.Struct)


def _build_contact(
    contact_type: type[ContactType],
    *,
    name: str | None,
    email: str | None,
    organization: str | None,
    telephone: str | None,
    lowercase: bool,
) -> ContactType:
    return contact_type(
        name=_lower_if_needed(name, lowercase=lowercase),
        email=_lower_if_needed(email, lowercase=lowercase),
        organization=_lower_if_needed(organization, lowercase=lowercase),
        telephone=_lower_if_needed(telephone, lowercase=lowercase),
    )


def _tzinfo_from_offset(offset: str) -> tzinfo | None:
    canonical = offset if ":" in offset else f"{offset[:-2]}:{offset[-2:]}"
    cached = _TZ_CACHE.get(canonical)
    if cached:
        return cached
    try:
        tzinfo_obj = datetime.strptime(canonical, "%z").tzinfo
    except ValueError:
        return None
    _TZ_CACHE[canonical] = tzinfo_obj
    return tzinfo_obj


__all__ = [
    "parse_datetime",
    "_apply_timezone",
    "_prepare_list",
    "_build_contact",
    "_parse_date_field",
    "_lower_if_needed",
]
