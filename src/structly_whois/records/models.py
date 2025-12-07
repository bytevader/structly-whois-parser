from __future__ import annotations

from collections.abc import Callable
from datetime import datetime
from typing import Any, Union

import msgspec

DateParser = Callable[[str], datetime]
ParsedDate = Union[datetime, str]


class Contact(msgspec.Struct):
    """Base contact struct shared by registrant/admin/tech."""

    organization: str | None = None
    email: str | None = None
    name: str | None = None
    telephone: str | None = None


class Tech(Contact):
    """Technical contact."""


class Registrant(Contact):
    """Domain registrant contact."""


class Admin(Contact):
    """Administrative contact."""


class Abuse(msgspec.Struct):
    """Abuse contact exposed by the registry."""

    email: str | None = None
    telephone: str | None = None


class WhoisRecord(msgspec.Struct):
    """Validated WHOIS response that can be serialized without post-processing."""

    raw_text: str

    registrant: Registrant
    admin: Admin
    tech: Tech
    abuse: Abuse

    statuses: list[str] = msgspec.field(default_factory=list)
    name_servers: list[str] = msgspec.field(default_factory=list)

    domain: str | None = None
    registrar: str | None = None
    registrar_id: str | None = None
    registrar_url: str | None = None
    dnssec: str | None = None

    expires_at: ParsedDate | None = None
    registered_at: ParsedDate | None = None
    updated_at: ParsedDate | None = None

    is_rate_limited: bool = False

    def to_dict(self, *, include_raw_text: bool = True) -> dict[str, Any]:
        """Convert the struct into basic Python types (JSON friendly)."""
        data = msgspec.to_builtins(self)
        if not include_raw_text:
            data.pop("raw_text", None)
        return data


class WhoisPayload(msgspec.Struct, forbid_unknown_fields=True):
    domain_name: str | None = None
    registrar: str | None = None
    registrar_id: str | None = None
    registrar_url: str | None = None
    creation_date: str | None = None
    updated_date: str | None = None
    expiration_date: str | None = None
    name_servers: list[str] | None = None
    status: list[str] | None = None
    registrant_name: str | None = None
    registrant_organization: str | None = None
    registrant_email: str | None = None
    registrant_telephone: str | None = None
    admin_name: str | None = None
    admin_organization: str | None = None
    admin_email: str | None = None
    admin_telephone: str | None = None
    tech_name: str | None = None
    tech_organization: str | None = None
    tech_email: str | None = None
    tech_telephone: str | None = None
    dnssec: str | None = None
    abuse_email: str | None = None
    abuse_telephone: str | None = None


__all__ = [
    "Abuse",
    "Admin",
    "Contact",
    "Registrant",
    "Tech",
    "WhoisRecord",
    "WhoisPayload",
    "DateParser",
    "ParsedDate",
]
