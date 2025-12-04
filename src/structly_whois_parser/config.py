from __future__ import annotations

from types import MappingProxyType
from typing import Any, Dict, Iterable, Mapping, MutableMapping, Tuple

from structly import FieldPattern, FieldSpec, Mode, ReturnShape, StructlyConfig


def sw(literal: str) -> FieldPattern:
    return FieldPattern.starts_with(literal)


def rx(pattern: str) -> FieldPattern:
    return FieldPattern.regex(pattern)


FieldDefinition = Dict[str, Any]
FieldOverride = Dict[str, Any]


BASE_FIELD_DEFINITIONS: Dict[str, FieldDefinition] = {
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
            sw("Registration Time:"),
            rx(r"(?i)^created\s*(?:on)?\s*:\s*(?P<val>.+)$"),
            rx(r"(?i)^creation\s+date\s*:\s*(?P<val>.+)$"),
            rx(r"(?i)^registered\s*(?:on)?\s*:\s*(?P<val>.+)$"),
            rx(r"(?i)^registered\s+date\s*:\s*(?P<val>.+)$"),
            rx(r"(?i)^registration\s+date\s*:\s*(?P<val>.+)$"),
            rx(r"(?i)^domain registration date\s*:\s*(?P<val>.+)$"),
            rx(r"(?i)^assigned\s*:\s*(?P<val>.+)$"),
            rx(r"(?i)^registered:\s*:\s*(?P<val>.+)$"),
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
        ]
    },
    "expiration_date": {
        "patterns": [
            sw("Registry Expiry Date:"),
            sw("Expiry date:"),
            sw("Expiry Date:"),
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
        ]
    },
    "status": {
        "patterns": [
            rx(r"(?i)^domain\s+status\s*:\s*(?P<val>[^,\n]+?)(?:\s+\(?https?://\S+\)?)?$"),
            rx(r"(?i)^status\s*:\s*(?P<val>[^,\n]+?)(?:\s+\(?https?://\S+\)?)?$"),
            rx(r"(?i)^registration\s+status\s*:\s*(?P<val>[^,\n]+?)(?:\s+\(?https?://\S+\)?)?$"),
            rx(r"(?i)^state\s*:\s*(?P<val>[^,\n]+?)(?:\s+\(?https?://\S+\)?)?$"),
            rx(r"(?i)^flags\s*:\s*(?P<val>[^,\n]+?)(?:\s+\(?https?://\S+\)?)?$"),
            rx(r"(?i)^(?:domain\s+status|status)\s*:\s*(?P<val>[^,\s]+)"),
            rx(r"(?i)^(?:domain\s+status|status)[^,\n]*,\s*(?P<val>[^,\s]+)"),
            rx(r"(?i)^(?:domain\s+status|status)(?:[^,\n]+,\s*){2}(?P<val>[^,\s]+)"),
            rx(r"(?i)^(?:domain\s+status|status)(?:[^,\n]+,\s*){3}(?P<val>[^,\s]+)"),
            rx(r"(?i)^state\s*:\s*(?P<val>[^,\s]+)"),
            rx(r"(?i)^state[^,\n]*,\s*(?P<val>[^,\s]+)"),
            rx(r"(?i)^state(?:[^,\n]+,\s*){2}(?P<val>[^,\s]+)"),
            rx(r"(?i)^state(?:[^,\n]+,\s*){3}(?P<val>[^,\s]+)"),
        ],
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
            rx(r"(?i)^\s*(?P<val>[a-z0-9-]+(?:\.[a-z0-9-]+)+)\s*$"),
            rx(r"(?i)^\s*(?P<val>[a-z0-9-]+(?:\.[a-z0-9-]+)+)\.\s+.*$"),
            rx(r"(?i)^\s*(?P<val>[a-z0-9-]+(?:\.[a-z0-9-]+)+)\s+\(.*\)$"),
            rx(r"(?i)^\s*(?P<val>[a-z0-9-]+(?:\.[a-z0-9-]+)+)\s+[0-9a-f:.]+(?:\s+.*)?$"),
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
            rx(r"(?i)^registrant\s+name\s*:\s*(?P<val>.+)$"),
        ]
    },
    "registrant_organization": {
        "patterns": [
            sw("Registrant Organization:"),
            rx(r"(?i)^registrant organisation:\s*(?P<val>.+)$"),
            rx(r"(?i)^registrant contact organisation:\s*(?P<val>.+)$"),
            rx(r"(?i)^organization:\s*(?P<val>.+)$"),
        ]
    },
    "registrant_email": {
        "patterns": [
            sw("Registrant Email:"),
            rx(r"(?i)^registrant contact email:\s*(?P<val>.+)$"),
            rx(r"(?i)^registrant email:\s*(?P<val>.+)$"),
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
            rx(r"(?i)^tech contact organisation:\s*(?P<val>.+)$"),
            rx(r"(?i)^technical contact organisation:\s*(?P<val>.+)$"),
            rx(r"(?i)^tech contact organization:\s*(?P<val>.+)$"),
            rx(r"(?i)^technical contact organization:\s*(?P<val>.+)$"),
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


TLD_OVERRIDES: Dict[str, Dict[str, FieldOverride]] = {
    "com.br": {
        "domain_name": {
            "patterns": [
                sw("domain:"),
            ]
        },
        "registrant_organization": {
            "patterns": [
                sw("owner:"),
            ]
        },
        "registrant_name": {
            "patterns": [
                sw("responsible:"),
                rx(r"(?ims)^owner-c:\s*[^\n]+\s*(?:.*\n)*?nic-hdl-br:\s*[^\n]+\s*person:\s*(?P<val>[^\n]+)"),
            ]
        },
        "registrant_email": {
            "patterns": [
                rx(r"(?ims)^owner-c:\s*[^\n]+\s*(?:.*\n)*?nic-hdl-br:\s*[^\n]+\s*(?:.*\n)*?e-mail:\s*(?P<val>[^\n]+)"),
                rx(r"^e-mail:\s*(?P<val>.+)$"),
            ]
        },
        "creation_date": {
            "patterns": [
                rx(r"^created:\s*(?P<val>\d{8})"),
            ]
        },
        "updated_date": {
            "patterns": [
                rx(r"^changed:\s*(?P<val>\d{8})"),
            ]
        },
        "expiration_date": {
            "patterns": [
                rx(r"^expires:\s*(?P<val>\d{8})"),
            ]
        },
        "name_servers": {
            "patterns": [
                rx(r"(?i)^nserver\s*:\s*(?P<val>[a-z0-9-]+(?:\.[a-z0-9-]+)+)"),
            ]
        },
        "status": {
            "patterns": [
                rx(r"(?i)^status\s*:\s*(?P<val>[^,\n]+)"),
            ],
            "mode": Mode.all,
            "unique": True,
            "return_shape": ReturnShape.list_,
        },
        "tech_name": {
            "patterns": [
                rx(r"(?ims)^tech-c:\s*[^\n]+\s*(?:.*\n)*?nic-hdl-br:\s*[^\n]+\s*person:\s*(?P<val>[^\n]+)"),
            ]
        },
        "tech_email": {
            "patterns": [
                rx(r"(?ims)^tech-c:\s*[^\n]+\s*(?:.*\n)*?nic-hdl-br:\s*[^\n]+\s*(?:.*\n)*?e-mail:\s*(?P<val>[^\n]+)"),
            ]
        },
    },
    "jp": {
        "domain_name": {
            "extend_patterns": [
                rx(r"^a\.\s*\[ドメイン名\]\s*(?P<val>.+)$"),
                rx(r"^\[Domain Name\]\s*(?P<val>.+)$"),
                rx(r"^\[ドメイン名\]\s*(?P<val>.+)$"),
            ]
        },
        "creation_date": {
            "extend_patterns": [
                rx(r"^\[登録年月日\]\s*(?P<val>.+)$"),
            ]
        },
        "expiration_date": {
            "extend_patterns": [
                rx(r"^\[有効期限\]\s*(?P<val>.+)$"),
            ]
        },
        "updated_date": {
            "extend_patterns": [
                rx(r"^\[最終更新\]\s*(?P<val>.+)$"),
            ]
        },
        "status": {
            "extend_patterns": [
                rx(r"^\[状態\]\s*(?P<val>[^\r\n(]+)"),
                rx(r"^\[ロック状態\]\s*(?P<val>[^\r\n(]+)"),
            ]
        },
        "name_servers": {
            "extend_patterns": [
                rx(r"^p\.\s*\[ネームサーバ\]\s*(?P<val>.+)$"),
                rx(r"^\[Name Server\]\s*(?P<val>.+)$"),
                rx(r"^\[ネームサーバ\]\s*(?P<val>.+)$"),
            ]
        },
        "registrant_organization": {
            "patterns": [
                rx(r"^(?:[a-z]\.)?\s*\[Organization\]\s*(?P<val>.+)$"),
                rx(r"^\[Registrant\]\s*(?P<val>.+)$"),
            ]
        },
        "registrant_name": {
            "extend_patterns": [
                rx(r"^\[Name\]\s*(?P<val>.+)$"),
                rx(r"^\[名前\]\s*(?P<val>.+)$"),
            ]
        },
        "registrant_email": {
            "extend_patterns": [
                rx(r"^\[Email\]\s*(?P<val>.+)$"),
            ]
        },
        "registrant_telephone": {
            "extend_patterns": [
                rx(r"^\[電話番号\]\s*(?P<val>.+)$"),
            ]
        },
        "dnssec": {
            "extend_patterns": [
                rx(r"^\[Signing Key\]\s*(?P<val>.+)$"),
            ]
        },
    },
    "no": {
        "domain_name": {
            "patterns": [
                rx(r"(?i)^domain\s+name\.+:\s*(?P<val>\S+)$"),
            ]
        },
        "registrar": {
            "patterns": [
                rx(r"(?i)^registrar\s+handle\.+:\s*(?P<val>\S+)$"),
            ]
        },
        "dnssec": {
            "patterns": [
                rx(r"(?i)^dnssec\.+:\s*(?P<val>.+)$"),
            ]
        },
        "creation_date": {
            "extend_patterns": [
                rx(r"(?i)^created:\s*(?P<val>.+)$"),
            ]
        },
        "updated_date": {
            "extend_patterns": [
                rx(r"(?i)^last\s+updated:\s*(?P<val>.+)$"),
            ]
        },
    },
    "kr": {
        "domain_name": {
            "extend_patterns": [
                rx(r"^도메인이름\s*:\s*(?P<val>.+)$"),
            ]
        },
        "creation_date": {
            "extend_patterns": [
                rx(r"^등록일\s*:\s*(?P<val>.+)$"),
                rx(r"^registered date\s*:\s*(?P<val>.+)$"),
            ]
        },
        "updated_date": {
            "extend_patterns": [
                rx(r"^최근 정보 변경일\s*:\s*(?P<val>.+)$"),
                rx(r"^last updated date\s*:\s*(?P<val>.+)$"),
            ]
        },
        "expiration_date": {
            "extend_patterns": [
                rx(r"^사용 종료일\s*:\s*(?P<val>.+)$"),
                rx(r"^expiration date\s*:\s*(?P<val>.+)$"),
            ]
        },
        "name_servers": {
            "extend_patterns": [
                rx(r"^호스트이름\s*:\s*(?P<val>.+)$"),
            ]
        },
    },
    "be": {
        "status": {
            "extend_patterns": [
                rx(r"(?i)^flags:\s*(?P<val>.+)$"),
                rx(r"(?i)^status:\s*(?P<val>.+)$"),
                rx(r"(?i)^domain status:\s*(?P<val>.+)$"),
            ]
        },
        "registrant_organization": {
            "patterns": [
                rx(r"(?im)^registrant:\s*(?P<val>[^\n]+)$"),
                rx(r"(?im)^registrant:\s*$\n(?P<val>[^\n]+)$"),
            ]
        },
        "registrar": {
            "extend_patterns": [
                rx(r"(?ims)^registrar:\s*\n\s*name:\s*(?P<val>[^\n]+)"),
            ]
        },
        "registrar_url": {
            "extend_patterns": [
                rx(r"(?ims)^registrar:\s*(?:\n.*?)*?\n\s*website:\s*(?P<val>\S+)"),
            ]
        },
        "creation_date": {
            "extend_patterns": [
                rx(r"(?im)^registered:\s*(?P<val>[^\n]+)$"),
            ]
        },
    },
    "fr": {
        "status": {
            "extend_patterns": [
                rx(r"(?i)^eppstatus:\s*(?P<val>.+)$"),
                rx(r"(?i)^hold:\s*(?P<val>YES)$"),
            ]
        },
        "registrant_name": {
            "patterns": [
                sw("Registrant Name:"),
            ]
        },
        "registrant_organization": {
            "patterns": [
                sw("Registrant Organization:"),
            ]
        },
        "registrant_email": {
            "patterns": [
                sw("Registrant Email:"),
            ]
        },
        "registrant_telephone": {
            "patterns": [
                sw("Registrant Phone:"),
            ]
        },
        "admin_name": {
            "patterns": [
                sw("Admin Name:"),
            ]
        },
        "admin_organization": {
            "patterns": [
                sw("Admin Organization:"),
            ]
        },
        "admin_email": {
            "patterns": [
                sw("Admin Email:"),
            ]
        },
        "admin_telephone": {
            "patterns": [
                sw("Admin Phone:"),
            ]
        },
        "tech_name": {
            "patterns": [
                sw("Tech Name:"),
            ]
        },
        "tech_organization": {
            "patterns": [
                sw("Tech Organization:"),
            ]
        },
        "tech_email": {
            "patterns": [
                sw("Tech Email:"),
            ]
        },
        "tech_telephone": {
            "patterns": [
                sw("Tech Phone:"),
            ]
        },
    },
    "pl": {
        "registrar": {
            "extend_patterns": [
                sw("REGISTRAR:"),
            ]
        },
        "expiration_date": {
            "extend_patterns": [
                sw("renewal date:"),
            ]
        },
        "name_servers": {
            "patterns": [
                rx(r"(?i)^nameservers:\s*(?P<val>[a-z0-9-]+(?:\.[a-z0-9-]+)+)\."),
                rx(r"(?i)^\s*(?P<val>[a-z0-9-]+(?:\.[a-z0-9-]+)+)\."),
            ],
            "mode": Mode.all,
            "unique": True,
            "return_shape": ReturnShape.list_,
        },
    },
    "mx": {
        "status": {
            "patterns": [
                rx(r"(?i)^domain status\s*:\s*(?P<val>.+)$"),
            ],
            "mode": Mode.all,
            "unique": True,
            "return_shape": ReturnShape.list_,
        },
        "name_servers": {
            "patterns": [
                rx(r"(?i)^name server\s*:\s*(?P<val>[^\s]+)"),
                rx(r"(?i)^dns:\s*(?P<val>[^\s]+)"),
            ],
            "mode": Mode.all,
            "unique": True,
            "return_shape": ReturnShape.list_,
        },
        "registrant_name": {
            "extend_patterns": [
                rx(r"(?im)^Registrant:\s*\n\s*Name:\s*(?P<val>[^\n]+)"),
            ],
        },
        "admin_name": {
            "extend_patterns": [
                rx(r"(?im)^Administrative Contact:\s*\n\s*Name:\s*(?P<val>[^\n]+)"),
            ],
        },
        "tech_name": {
            "extend_patterns": [
                rx(r"(?im)^Technical Contact:\s*\n\s*Name:\s*(?P<val>[^\n]+)"),
            ],
        },
    },
    "uk": {
        "status": {
            "extend_patterns": [
                rx(r"(?i)^registration status\s*:\s*(?P<val>.+)$"),
            ]
        },
        "name_servers": {
            "extend_patterns": [
                rx(r"(?i)^\s*(?P<val>(?:[a-z0-9-]+\.)+[a-z][a-z0-9-]*)(?:\.)?(?:\s+.*)?$"),
            ]
        },
        "registrant_organization": {
            "extend_patterns": [
                rx(r"(?i)^\s*registrant\s*:\s*(?P<val>.+)$"),
                rx(r"(?im)^registrant:\s*$\n^(?P<val>.+)$"),
            ]
        },
    },
}


def _normalize_tld(value: str | None) -> str:
    if not value:
        return ""
    return value.strip().lstrip(".").lower()


def _clone_field_definition(defn: FieldDefinition) -> FieldDefinition:
    cloned = dict(defn)
    if "patterns" in cloned:
        cloned["patterns"] = list(cloned["patterns"])
    return cloned


def _clone_field_override(override: FieldOverride) -> FieldOverride:
    cloned = dict(override)
    for key in ("patterns", "extend_patterns", "prepend_patterns"):
        if key in cloned:
            cloned[key] = list(cloned[key])
    return cloned


class StructlyConfigFactory:
    """Build StructlyConfig objects with customizable base fields and TLD overrides."""

    def __init__(
        self,
        *,
        base_field_definitions: Mapping[str, FieldDefinition] | None = None,
        tld_overrides: Mapping[str, Dict[str, FieldOverride]] | None = None,
    ) -> None:
        self._base_fields: Dict[str, FieldDefinition] = {
            name: _clone_field_definition(defn)
            for name, defn in (base_field_definitions or BASE_FIELD_DEFINITIONS).items()
        }
        self._tld_overrides: Dict[str, Dict[str, FieldOverride]] = {
            _normalize_tld(tld): {
                field: _clone_field_override(override) for field, override in overrides.items()
            }
            for tld, overrides in (tld_overrides or TLD_OVERRIDES).items()
        }

    @property
    def base_fields(self) -> Mapping[str, FieldDefinition]:
        return MappingProxyType(self._base_fields)

    @property
    def tld_overrides(self) -> Mapping[str, Dict[str, FieldOverride]]:
        return MappingProxyType(self._tld_overrides)

    @property
    def known_tlds(self) -> Tuple[str, ...]:
        return tuple(sorted(self._tld_overrides.keys()))

    def get_base_field(self, name: str) -> FieldDefinition:
        if name not in self._base_fields:
            raise KeyError(f"Unknown base field '{name}'")
        return _clone_field_definition(self._base_fields[name])

    def register_base_field(self, name: str, definition: FieldDefinition) -> None:
        self._base_fields[name] = _clone_field_definition(definition)

    def extend_base_field(self, name: str, *, extend_patterns: Iterable[FieldPattern]) -> None:
        if name not in self._base_fields:
            raise KeyError(f"Unknown base field '{name}'")
        existing = list(self._base_fields[name].get("patterns", []))
        existing.extend(list(extend_patterns))
        self._base_fields[name]["patterns"] = existing

    def register_tld(
        self,
        tld: str,
        overrides: Mapping[str, FieldOverride],
        *,
        replace: bool = False,
    ) -> None:
        normalized = _normalize_tld(tld)
        if not normalized:
            raise ValueError("TLD label cannot be empty")
        sanitized = {name: _clone_field_override(override) for name, override in overrides.items()}
        if replace or normalized not in self._tld_overrides:
            self._tld_overrides[normalized] = sanitized
        else:
            target = self._tld_overrides.setdefault(normalized, {})
            target.update(sanitized)

    def build(self, tld: str | None = None) -> StructlyConfig:
        normalized = _normalize_tld(tld)
        override_map = self._tld_overrides.get(normalized, {})
        fields: MutableMapping[str, FieldSpec] = {}
        for name, defn in self._base_fields.items():
            field_override = override_map.get(name)
            fields[name] = _build_field_spec(defn, field_override)
        return StructlyConfig(fields=dict(fields))


DEFAULT_CONFIG_FACTORY = StructlyConfigFactory()
DEFAULT_TLDS = tuple(sorted(DEFAULT_CONFIG_FACTORY.known_tlds))


def _build_field_spec(defn: FieldDefinition, override: FieldOverride | None = None) -> FieldSpec:
    patterns = list(defn["patterns"])
    mode = defn.get("mode", Mode.first)
    unique = defn.get("unique", False)
    return_shape = defn.get("return_shape", ReturnShape.scalar)

    if override:
        if "patterns" in override:
            patterns = list(override["patterns"])
        elif "prepend_patterns" in override:
            patterns = list(override["prepend_patterns"]) + patterns
        if "extend_patterns" in override:
            patterns.extend(list(override["extend_patterns"]))
        mode = override.get("mode", mode)
        unique = override.get("unique", unique)
        return_shape = override.get("return_shape", return_shape)

    return FieldSpec(
        patterns=patterns,
        mode=mode,
        unique=unique,
        return_shape=return_shape,
    )


def build_structly_config_for_tld(
    tld: str | None = None,
    *,
    factory: StructlyConfigFactory | None = None,
) -> StructlyConfig:
    target_factory = factory or DEFAULT_CONFIG_FACTORY
    return target_factory.build(tld)
