from __future__ import annotations

from typing import Any

from structly import FieldPattern, Mode, ReturnShape


def sw(literal: str) -> FieldPattern:
    return FieldPattern.starts_with(literal)


def rx(pattern: str) -> FieldPattern:
    return FieldPattern.regex(pattern)


FieldDefinition = dict[str, Any]
FieldOverride = dict[str, Any]

STATUS_SINGLE_TOKEN_PATTERN = rx(r"(?i)^(?:domain\s+status|status)\s*:\s*(?P<val>[^,\s]+)")
BASE_STATUS_PATTERNS = [
    rx(r"(?i)^domain\s+status\s*:\s*(?P<val>[^,\n]+?)(?:\s+\(?https?://\S+\)?)?$"),
    rx(r"(?i)^status\s*:\s*(?P<val>[^,\n]+?)(?:\s+\(?https?://\S+\)?)?$"),
    rx(r"(?i)^registration\s+status\s*:\s*(?P<val>[^,\n]+?)(?:\s+\(?https?://\S+\)?)?$"),
    rx(r"(?i)^state\s*:\s*(?P<val>[^,\n]+?)(?:\s+\(?https?://\S+\)?)?$"),
    STATUS_SINGLE_TOKEN_PATTERN,
    rx(r"(?i)^(?:domain\s+status|status)[^,\n]*,\s*(?P<val>[^,\s]+)"),
    rx(r"(?i)^(?:domain\s+status|status)(?:[^,\n]+,\s*){2}(?P<val>[^,\s]+)"),
    rx(r"(?i)^(?:domain\s+status|status)(?:[^,\n]+,\s*){3}(?P<val>[^,\s]+)"),
    rx(r"(?i)^state\s*:\s*(?P<val>[^,\s]+)"),
    rx(r"(?i)^state[^,\n]*,\s*(?P<val>[^,\s]+)"),
    rx(r"(?i)^state(?:[^,\n]+,\s*){2}(?P<val>[^,\s]+)"),
    rx(r"(?i)^state(?:[^,\n]+,\s*){3}(?P<val>[^,\s]+)"),
]


BASE_FIELD_DEFINITIONS: dict[str, FieldDefinition] = {
    "domain_name": {
        "patterns": [
            sw("Domain Name:"),
            sw("Domain name:"),
            sw("Domain:"),
            sw("domain name:"),
            sw("domain:"),
            rx(r"(?i)^domain\s+name\s*:\s*(?P<val>[a-z0-9._-]+)(?:\s*\(.+\))?$"),
            rx(r"(?i)^domain:\s*(?P<val>[a-z0-9._-]+)$"),
            rx(r"(?i)^domain\s+information\s*:\s*(?P<val>[a-z0-9._-]+)$"),
            rx(r"(?i)^(?P<val>[a-z0-9][a-z0-9.-]+\.[a-z]{2,})$"),
            rx(r"(?i)^domain[.\s]*:\s*(?P<val>[a-z0-9._-]+)$"),
        ]
    },
    "registrar": {
        "patterns": [
            sw("Registrar:"),
            sw("Registrar Name:"),
            sw("registrar:"),
            sw("registrar name:"),
            sw("Sponsoring Registrar:"),
            rx(r"(?i)^registrar\s*:\s*(?P<val>.+)$"),
            rx(r"(?i)^registrar\s+name\s*:\s*(?P<val>.+)$"),
            rx(r"(?i)^name\s*:\s*(?P<val>.+\[Tag = .+\])$"),
            rx(r"(?i)^sponsoring\s+registrar\s*:\s*(?P<val>.+)$"),
        ]
    },
    "registrar_url": {
        "patterns": [
            sw("Registrar URL:"),
            rx(r"(?i)^url:\s*(?P<val>https?://\S+)$"),
            rx(r"(?i)^website:\s*(?P<val>https?://\S+)$"),
        ]
    },
    "registrar_id": {
        "patterns": [
            sw("Registrar IANA ID:"),
            rx(r"(?i)^registrar id:\s*(?P<val>.+)$"),
        ]
    },
    "creation_date": {
        "patterns": [
            sw("Creation Date:"),
            sw("Creation date:"),
            sw("Created On:"),
            sw("created on:"),
            sw("Created date:"),
            sw("Registration Time:"),
            rx(r"(?i)^created\s*(?:on)?\s*:\s*(?P<val>.+)$"),
            rx(r"(?i)^creation\s+date\s*:\s*(?P<val>.+)$"),
            rx(r"(?i)^registered\s*(?:on)?\s*:\s*(?P<val>.+)$"),
            rx(r"(?i)^registered\s+date\s*:\s*(?P<val>.+)$"),
            rx(r"(?i)^registration\s+date\s*:\s*(?P<val>.+)$"),
            rx(r"(?i)^domain registration date\s*:\s*(?P<val>.+)$"),
            rx(r"(?i)^assigned\s*:\s*(?P<val>.+)$"),
            rx(r"(?i)^registered:\s*:\s*(?P<val>.+)$"),
            rx(r"(?i)^domain record activated:\s*(?P<val>.+)$"),
        ]
    },
    "updated_date": {
        "patterns": [
            sw("Updated Date:"),
            sw("Updated date:"),
            sw("Last-Update:"),
            sw("last-update:"),
            sw("Last Updated On:"),
            rx(r"(?i)^last\s+updated\s*:\s*(?P<val>.+)$"),
            rx(r"(?i)^last\s+modified\s*:\s*(?P<val>.+)$"),
            rx(r"(?i)^last\s+updated\s+date\s*:\s*(?P<val>.+)$"),
            rx(r"(?i)^updated\s*(?:on|date)?\s*:\s*(?P<val>.+)$"),
            rx(r"(?i)^changed\s*:\s*(?P<val>.+)$"),
            rx(r"(?i)^modified\s*:\s*(?P<val>.+)$"),
            rx(r"(?i)last\s+updated\s*:\s*(?P<val>.+)$"),
        ]
    },
    "expiration_date": {
        "patterns": [
            sw("Registry Expiry Date:"),
            sw("Expiry date:"),
            sw("Expiry Date:"),
            sw("Exp date:"),
            rx(r"(?i)^expiration\s+date\s*:\s*(?P<val>.+)$"),
            rx(r"(?i)^expiration\s+time\s*:\s*(?P<val>.+)$"),
            rx(r"(?i)^expires\s*on\s*:\s*(?P<val>.+)$"),
            rx(r"(?i)^expire\s+date\s*:\s*(?P<val>.+)$"),
            rx(r"(?i)^paid-till\s*:\s*(?P<val>.+)$"),
            rx(r"(?i)^valid\s+until\s*:\s*(?P<val>.+)$"),
            rx(r"(?i)^validity\s*:\s*(?P<val>.+)$"),
            rx(r"(?i)^expiration\s*:\s*(?P<val>.+)$"),
            rx(r"(?i)^expire\s*:\s*(?P<val>.+)$"),
            rx(r"(?i)^registrar registration expiration date\s*:\s*(?P<val>.+)$"),
            rx(r"(?i)^expires\s*:\s*(?P<val>.+)$"),
            rx(r"(?i)expires\s*:\s*(?P<val>.+)$"),
            rx(r"(?i)^registrar expiration date:\s*(?P<val>.+)$"),
        ]
    },
    "status": {
        "patterns": BASE_STATUS_PATTERNS,
        "mode": Mode.all,
        "unique": True,
        "return_shape": ReturnShape.list_,
    },
    "name_servers": {
        "patterns": [
            rx(r"(?i)^\s*name\s+servers?\s*:\s*(?P<val>[a-z0-9-]+(?:\.[a-z0-9-]+)+)"),
            rx(r"(?i)^\s*nameservers?\s*:\s*(?P<val>[a-z0-9-]+(?:\.[a-z0-9-]+)+)"),
            rx(r"(?i)^\s*nserver\s*:\s*(?P<val>[a-z0-9-]+(?:\.[a-z0-9-]+)+)"),
            rx(r"(?i)^\s*host\s+name\s*:\s*(?P<val>[a-z0-9-]+(?:\.[a-z0-9-]+)+)"),
            rx(r"(?i)^\s*(?:primary|secondary)\s+name\s+server\s*:\s*(?P<val>[a-z0-9-]+(?:\.[a-z0-9-]+)+)"),
            rx(r"(?i)^\s*(?P<val>(?:ns|dns)[0-9a-z-]*(?:\.[a-z0-9-]+)+)$"),
            rx(r"(?i)^\s*(?P<val>[a-z0-9-]+(?:\.[a-z0-9-]+){2,})\s*\.?\s*$"),
            rx(r"(?i)^\s*(?P<val>(?:[a-z0-9-]+\.)+[a-z0-9-]{2,})\.\s+.*$"),
            rx(r"(?i)^\s*(?P<val>[a-z0-9-]+(?:\.[a-z0-9-]+)+)\s+\(.*\)$"),
            rx(r"(?i)^\s*(?P<val>[a-z0-9-]+(?:\.[a-z0-9-]+)+)\s+[0-9a-f:.]+(?:\s+.*)?$"),
            rx(r"(?i)^\s*Hostname:\s*(?P<val>[a-z0-9-]+(?:\.[a-z0-9-]+)+)\s*$"),
        ],
        "mode": Mode.all,
        "unique": True,
        "return_shape": ReturnShape.list_,
    },
    "registrant_name": {
        "patterns": [
            sw("Registrant Name:"),
            sw("Registrant:"),
            rx(r"(?i)^registrant contact name:\s*(?P<val>.+)$"),
            rx(r"(?i)^domain holder:\s*(?P<val>.+)$"),
            rx(r"(?i)^personname:\s*(?P<val>.+)$"),
            rx(r"(?i)^owner name:\s*(?P<val>.+)$"),
            rx(r"(?i)^registrant\s+name\s*:\s*(?P<val>.+)$"),
        ]
    },
    "registrant_organization": {
        "patterns": [
            sw("Registrant Organization:"),
            sw("Domain Holder Organization:"),
            rx(r"(?i)^registrant organisation:\s*(?P<val>.+)$"),
            rx(r"(?i)^registrant contact organisation:\s*(?P<val>.+)$"),
            rx(r"(?i)^organization:\s*(?P<val>.+)$"),
            rx(r"(?i)^org:\s*(?P<val>.+)$"),
        ]
    },
    "registrant_email": {
        "patterns": [
            sw("Registrant Email:"),
            rx(r"(?i)^registrant contact email:\s*(?P<val>.+)$"),
            rx(r"(?i)^registrant email:\s*(?P<val>.+)$"),
            rx(r"(?i)^owner email:\s*(?P<val>.+)$"),
            rx(r"(?i)^e-?mail:\s*(?P<val>.+)$"),
        ]
    },
    "registrant_telephone": {
        "patterns": [
            sw("Registrant Phone:"),
            sw("Registrant Phone Number:"),
            sw("Registrant Contact Phone:"),
            rx(r"(?i)^registrant contact phone:\s*(?P<val>.+)$"),
            rx(r"(?i)^registrant phone(?: number)?\s*:\s*(?P<val>.+)$"),
            rx(r"(?i)^registrant telephone:\s*(?P<val>.+)$"),
        ]
    },
    "admin_name": {
        "patterns": [
            sw("Admin Name:"),
            sw("Admin Contact Name:"),
            sw("Administrative Contact Name:"),
            sw("Administrative Contact:"),
            rx(r"(?i)^admin contact name:\s*(?P<val>.+)$"),
            rx(r"(?i)^administrative contact:\s*(?P<val>.+)$"),
            rx(r"(?i)^administrative contact name:\s*(?P<val>.+)$"),
            rx(r"(?i)^Name:\s*(?P<val>.+)$"),
        ]
    },
    "admin_organization": {
        "patterns": [
            sw("Admin Organization:"),
            sw("Admin Contact Organization:"),
            sw("Administrative Contact Organization:"),
            sw("Administrative Contact Organisation:"),
            rx(r"(?i)^admin contact organisation:\s*(?P<val>.+)$"),
            rx(r"(?i)^admin contact organization:\s*(?P<val>.+)$"),
            rx(r"(?i)^admin organization:\s*(?P<val>.+)$"),
            rx(r"(?i)^administrative contact organisation:\s*(?P<val>.+)$"),
            rx(r"(?i)^administrative contact organization:\s*(?P<val>.+)$"),
            rx(r"(?i)^org:\s*(?P<val>.+)$"),
        ]
    },
    "admin_email": {
        "patterns": [
            sw("Admin Email:"),
            sw("Admin Contact Email:"),
            sw("Administrative Contact Email:"),
            rx(r"(?i)^administrative contact\(ac\)\s*:\s*(?P<val>.+)$"),
            rx(r"(?i)^ac e-mail:\s*(?P<val>.+)$"),
            rx(r"(?i)^admin(?:istrative)?(?:\s+contact)?\s+email:\s*(?P<val>.+)$"),
        ]
    },
    "admin_telephone": {
        "patterns": [
            sw("Admin Phone:"),
            sw("Admin Phone Number:"),
            sw("Administrative Contact Phone:"),
            sw("Administrative Contact Phone Number:"),
            rx(r"(?i)^admin(?:istrative)?\s+contact\s+phone(?: number)?\s*:\s*(?P<val>.+)$"),
            rx(r"(?i)^admin(?:istrative)?\s+contact\s+telephone:\s*(?P<val>.+)$"),
            rx(r"(?i)^ac phone number:\s*(?P<val>.+)$"),
        ]
    },
    "tech_name": {
        "patterns": [
            sw("Tech Name:"),
            sw("Tech Contact Name:"),
            sw("Technical Contact Name:"),
            rx(r"(?i)^technical contact name:\s*(?P<val>.+)$"),
        ]
    },
    "tech_organization": {
        "patterns": [
            sw("Tech Organization:"),
            sw("Tech Contact Organisation:"),
            sw("Tech Contact Organization:"),
            sw("Tech Organization:"),
            rx(r"(?i)^tech contact organisation:\s*(?P<val>.+)$"),
            rx(r"(?i)^technical contact organisation:\s*(?P<val>.+)$"),
            rx(r"(?i)^tech contact organization:\s*(?P<val>.+)$"),
            rx(r"(?i)^technical contact organization:\s*(?P<val>.+)$"),
            rx(r"(?i)^org:\s*(?P<val>.+)$"),
        ]
    },
    "tech_email": {
        "patterns": [
            sw("Tech Email:"),
            sw("Tech Contact Email:"),
            sw("Technical Contact Email:"),
            rx(r"(?i)^tech contact email:\s*(?P<val>.+)$"),
            rx(r"(?i)^technical contact email:\s*(?P<val>.+)$"),
        ]
    },
    "tech_telephone": {
        "patterns": [
            sw("Tech Phone:"),
            sw("Tech Phone Number:"),
            sw("Tech Contact Phone:"),
            rx(r"(?i)^tech(?:nical)?\s+contact\s+phone(?: number)?\s*:\s*(?P<val>.+)$"),
            rx(r"(?i)^tech(?:nical)?\s+contact\s+telephone:\s*(?P<val>.+)$"),
        ]
    },
    "abuse_email": {
        "patterns": [
            sw("Registrar Abuse Contact Email:"),
            sw("Registry Abuse Contact Email:"),
            sw("Abuse Contact Email:"),
            sw("Abuse Contact:"),
            rx(r"(?i)^abuse contact email:\s*(?P<val>.+)$"),
            rx(r"(?i)^registrar abuse contact email:\s*(?P<val>.+)$"),
            rx(r"(?i)^registry abuse contact email:\s*(?P<val>.+)$"),
        ]
    },
    "abuse_telephone": {
        "patterns": [
            sw("Registrar Abuse Contact Phone:"),
            sw("Registry Abuse Contact Phone:"),
            sw("Abuse Contact Phone:"),
            rx(r"(?i)^abuse contact phone:\s*(?P<val>.+)$"),
            rx(r"(?i)^registrar abuse contact phone:\s*(?P<val>.+)$"),
            rx(r"(?i)^registry abuse contact phone:\s*(?P<val>.+)$"),
        ]
    },
    "dnssec": {
        "patterns": [
            sw("DNSSEC:"),
            rx(r"(?i)^dnssec:\s*(?P<val>.+)$"),
            sw("dnssec:"),
        ]
    },
}
