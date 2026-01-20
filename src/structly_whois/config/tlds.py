from __future__ import annotations

from structly import Mode, ReturnShape

from .fields import (
    BASE_STATUS_PATTERNS,
    STATUS_SINGLE_TOKEN_PATTERN,
    FieldOverride,
    rx,
    sw,
)

TLD_OVERRIDES: dict[str, dict[str, FieldOverride]] = {
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
            # Drop the single-token pattern to avoid extracting a stray "NOT" status from lines like
            # "Status: NOT AVAILABLE" that appear in .be WHOIS payloads.
            "patterns": [pattern for pattern in BASE_STATUS_PATTERNS if pattern is not STATUS_SINGLE_TOKEN_PATTERN]
            + [
                rx(r"(?i)^flags:\s*(?P<val>.+)$"),
                rx(r"(?i)^status:\s*(?P<val>.+)$"),
                rx(r"(?i)^domain status:\s*(?P<val>.+)$"),
            ],
            "mode": Mode.all,
            "unique": True,
            "return_shape": ReturnShape.list_,
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
    "fi": {
        "domain_name": {
            "extend_patterns": [
                rx(r"(?i)^domain\.+:\s*(?P<val>[a-z0-9._-]+)$"),
            ]
        },
        "status": {
            "extend_patterns": [
                rx(r"(?i)^status\.+:\s*(?P<val>.+)$"),
            ]
        },
        "creation_date": {
            "extend_patterns": [
                rx(r"(?i)^created\.+:\s*(?P<val>.+)$"),
            ]
        },
        "expiration_date": {
            "extend_patterns": [
                rx(r"(?i)^expires\.+:\s*(?P<val>.+)$"),
            ]
        },
        "updated_date": {
            "extend_patterns": [
                rx(r"(?i)^modified\.+:\s*(?P<val>.+)$"),
            ]
        },
        "name_servers": {
            "extend_patterns": [
                rx(r"(?i)^nserver\.+:\s*(?P<val>[a-z0-9-]+(?:\.[a-z0-9-]+)+)"),
            ]
        },
        "registrant_name": {
            "extend_patterns": [
                rx(r"(?ims)^Holder\s*(?:\n[^\S\r\n]*\S.*)*?\nname\.+:\s*(?P<val>[^\r\n]+)"),
            ]
        },
        "registrant_organization": {
            "extend_patterns": [
                rx(r"(?ims)^Holder\s*(?:\n[^\S\r\n]*\S.*)*?\nname\.+:\s*(?P<val>[^\r\n]+)"),
            ]
        },
        "registrar": {
            "extend_patterns": [
                rx(r"(?i)^registrar\.+:\s*(?P<val>.+)$"),
            ]
        },
        "registrar_url": {
            "extend_patterns": [
                rx(r"(?i)^www\.+:\s*(?P<val>\S+)$"),
            ]
        },
        "dnssec": {
            "extend_patterns": [
                rx(r"(?i)^dnssec\.+:\s*(?P<val>.+)$"),
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
    "pk": {
        "status": {
            "patterns": [pattern for pattern in BASE_STATUS_PATTERNS if pattern is not STATUS_SINGLE_TOKEN_PATTERN],
            "mode": Mode.all,
            "unique": True,
            "return_shape": ReturnShape.list_,
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
    "edu": {
        "registrant_organization": {
            "extend_patterns": [
                rx(r"(?ims)^Registrant:\s*\n\s*(?P<val>[^\n]+)"),
            ]
        },
        "admin_name": {
            "extend_patterns": [
                rx(r"(?ims)^Administrative Contact:\s*\n\s*(?P<val>[^\n]+)"),
            ]
        },
        "admin_organization": {
            "extend_patterns": [
                rx(r"(?ims)^Administrative Contact:\s*\n\s*[^\n]+\n\s*(?P<val>[^\n]+)"),
            ]
        },
        "admin_telephone": {
            "extend_patterns": [
                rx(r"(?ims)^Administrative Contact:\s*(?:\n\s*[^\n]+)*?\n\s*(?P<val>\+?\d[\d().\-\s]*\d)"),
            ]
        },
        "admin_email": {
            "extend_patterns": [
                rx(
                    r"(?ims)^Administrative Contact:\s*(?:\n\s*[^\n]+)*?\n\s*"
                    r"(?P<val>[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,})"
                ),
            ]
        },
        "tech_name": {
            "extend_patterns": [
                rx(r"(?ims)^Technical Contact:\s*\n\s*(?P<val>[^\n]+)"),
            ]
        },
        "tech_organization": {
            "extend_patterns": [
                rx(r"(?ims)^Technical Contact:\s*\n\s*[^\n]+\n\s*(?P<val>[^\n]+)"),
            ]
        },
        "tech_telephone": {
            "extend_patterns": [
                rx(r"(?ims)^Technical Contact:\s*(?:\n\s*[^\n]+)*?\n\s*(?P<val>\+?\d[\d().\-\s]*\d)"),
            ]
        },
        "tech_email": {
            "extend_patterns": [
                rx(r"(?ims)^Technical Contact:\s*(?:\n\s*[^\n]+)*?\n\s*(?P<val>[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,})"),
            ]
        },
    },
    "ve": {
        "registrant_organization": {
            "extend_patterns": [
                rx(r"(?ims)^contact:\s*[^\r\n]+(?:\r?\n)(?:.*?(?:\r?\n))*?^\s*org:\s*(?P<val>[^\r\n]+)"),
            ]
        },
        "admin_organization": {
            "extend_patterns": [
                rx(
                    r"(?ims)^contact:\s*[^\r\n]+(?:\r?\n)(?:.*?(?:\r?\n))*?(?:\r?\n)\s*(?:\r?\n)^contact:\s*[^\r\n]+(?:\r?\n)(?:.*?(?:\r?\n))*?^\s*org:\s*(?P<val>[^\r\n]+)"
                ),
            ]
        },
        "tech_organization": {
            "extend_patterns": [
                rx(
                    r"(?ims)^contact:\s*[^\r\n]+(?:\r?\n)(?:.*?(?:\r?\n))*?(?:\r?\n)\s*(?:\r?\n)^contact:\s*[^\r\n]+(?:\r?\n)(?:.*?(?:\r?\n))*?(?:\r?\n)\s*(?:\r?\n)^contact:\s*[^\r\n]+(?:\r?\n)(?:.*?(?:\r?\n))*?^\s*org:\s*(?P<val>[^\r\n]+)"
                ),
                rx(
                    r"(?ims)^contact:\s*[^\r\n]+(?:\r?\n)(?:.*?(?:\r?\n))*?(?:\r?\n)\s*(?:\r?\n)^contact:\s*[^\r\n]+(?:\r?\n)(?:.*?(?:\r?\n))*?^\s*org:\s*(?P<val>[^\r\n]+)"
                ),
            ]
        },
    },
    "cz": {
        "status": {
            "patterns": [
                rx(r"(?i)^status:\s*(?P<val>.+)$"),
            ],
            "mode": Mode.all,
            "unique": True,
            "return_shape": ReturnShape.list_,
        }
    },
    "gg": {
        "status": {
            "patterns": [
                rx(r"(?i)^(?P<val>Active|Transfer Prohibited by Registrar)\s*$"),
            ],
            "mode": Mode.all,
            "unique": True,
            "return_shape": ReturnShape.list_,
        },
        "registrar": {
            "patterns": [
                rx(r"(?im)^\s*Registrar:\s*(?P<val>.+?)(?:\s*\([^)]*\))?\s*$"),
            ]
        },
        "registrant_name": {
            "patterns": [
                rx(r"(?im)^\s*Registrant:\s*(?P<val>.+?)\s*$"),
            ]
        },
        "name_servers": {
            "patterns": [rx(r"(?i)^(?P<val>[a-z0-9-]+(?:\.[a-z0-9-]+){3,})\.?$")],
            "mode": Mode.all,
            "unique": True,
            "return_shape": ReturnShape.list_,
        },
    },
    "hk": {
        "domain_name": {
            "patterns": [
                sw("Domain Name:"),
                rx(
                    r"(?im)^\s*Domain\s+Name:\s*(?P<val>[A-Z0-9.-]+\.(?:HK|COM\.HK|NET\.HK|ORG\.HK|EDU\.HK|GOV\.HK|IDV\.HK))\s*$"
                ),
            ]
        },
        "registrar": {
            "patterns": [
                rx(r"(?im)^\s*Registrar Name:\s*(?P<val>.+?)\s*$"),
            ]
        },
        "dnssec": {
            "patterns": [
                rx(r"(?im)^\s*DNSSEC:\s*(?P<val>.+?)\s*$"),
            ]
        },
        "expiration_date": {
            "patterns": [
                rx(r"(?im)^\s*Expiry Date:\s*(?P<val>\d{2}-\d{2}-\d{4})\s*$"),
            ]
        },
        "creation_date": {
            "patterns": [
                rx(r"(?im)^\s*Domain Name Commencement Date:\s*(?P<val>\d{2}-\d{2}-\d{4})\s*$"),
            ]
        },
        "status": {
            "patterns": [
                rx(r"(?im)^\s*Domain Status:\s*(?P<val>[^.\r\n-][^\r\n]*)\s*$"),
            ],
            "mode": Mode.all,
            "unique": True,
            "return_shape": ReturnShape.list_,
        },
        "name_servers": {
            "patterns": [
                rx(r"(?im)^\s*(?P<val>[A-Z0-9-]+(?:\.[A-Z0-9-]+){2,})\s*$"),
            ],
            "mode": Mode.all,
            "unique": True,
            "return_shape": ReturnShape.list_,
        },
        "registrant_name": {
            "patterns": [
                rx(r"(?im)^\s*Company English Name.*?:\s*(?P<val>.+?)\s*$"),
            ]
        },
        "registrant_organization": {
            "patterns": [
                rx(r"(?im)^\s*Company English Name.*?:\s*(?P<val>.+?)\s*$"),
            ]
        },
        "registrant_email": {
            "patterns": [
                rx(r"(?im)^\s*Email:\s*(?P<val>\S+@\S+)\s*$"),
            ]
        },
        "admin_name": {
            "patterns": [
                rx(r"(?im)^\s*Given name:\s*(?P<val>.+?)\s*$"),
            ]
        },
        "admin_organization": {
            "patterns": [
                rx(r"(?im)^\s*Company name:\s*(?P<val>.+?)\s*$"),
            ]
        },
        "admin_email": {
            "patterns": [
                rx(r"(?im)^\s*Email:\s*(?P<val>\S+@\S+)\s*$"),
            ]
        },
        "admin_telephone": {
            "patterns": [
                rx(r"(?im)^\s*Phone:\s*(?P<val>.+?)\s*$"),
            ]
        },
        "tech_name": {
            "patterns": [
                rx(r"(?im)^\s*Given name:\s*(?P<val>.+?)\s*$"),
            ]
        },
        "tech_organization": {
            "patterns": [
                rx(r"(?im)^\s*Company name:\s*(?P<val>.+?)\s*$"),
            ]
        },
        "tech_email": {
            "patterns": [
                rx(r"(?im)^\s*Email:\s*(?P<val>\S+@\S+)\s*$"),
            ]
        },
        "tech_telephone": {
            "patterns": [
                rx(r"(?im)^\s*Phone:\s*(?P<val>.+?)\s*$"),
            ]
        },
    },
    "int": {
        "domain_name": {
            "patterns": [
                rx(r"(?im)^\s*domain:\s*(?P<val>[A-Z0-9.-]+)\s*$"),
            ]
        },
        "registrant_organization": {
            "patterns": [
                rx(r"(?im)^\s*organisation:\s*(?P<val>.+?)\s*$"),
            ]
        },
        "creation_date": {
            "patterns": [
                rx(r"(?im)^\s*created:\s*(?P<val>\d{4}-\d{2}-\d{2})\s*$"),
            ]
        },
        "updated_date": {
            "patterns": [
                rx(r"(?im)^\s*changed:\s*(?P<val>\d{4}-\d{2}-\d{2})\s*$"),
            ]
        },
        "name_servers": {
            "patterns": [
                # take only the hostname part before any IPs
                rx(r"(?im)^\s*nserver:\s*(?P<val>[A-Z0-9-]+(?:\.[A-Z0-9-]+)+)\b"),
            ],
            "mode": Mode.all,
            "unique": True,
            "return_shape": ReturnShape.list_,
        },
        "admin_name": {
            "patterns": [
                rx(r"(?ims)^\s*contact:\s*administrative\s*\r?\n(?:.*\r?\n)*?^\s*name:\s*(?P<val>.+?)\s*$"),
            ]
        },
        "admin_email": {
            "patterns": [
                rx(r"(?ims)^\s*contact:\s*administrative\s*\r?\n(?:.*\r?\n)*?^\s*e-mail:\s*(?P<val>\S+@\S+)\s*$"),
            ]
        },
        "admin_telephone": {
            "patterns": [
                rx(r"(?ims)^\s*contact:\s*administrative\s*\r?\n(?:.*\r?\n)*?^\s*phone:\s*(?P<val>.+?)\s*$"),
            ]
        },
        "tech_name": {
            "patterns": [
                rx(r"(?ims)^\s*contact:\s*technical\s*\r?\n(?:.*\r?\n)*?^\s*name:\s*(?P<val>.+?)\s*$"),
            ]
        },
        "tech_email": {
            "patterns": [
                rx(r"(?ims)^\s*contact:\s*technical\s*\r?\n(?:.*\r?\n)*?^\s*e-mail:\s*(?P<val>\S+@\S+)\s*$"),
            ]
        },
        "tech_telephone": {
            "patterns": [
                rx(r"(?ims)^\s*contact:\s*technical\s*\r?\n(?:.*\r?\n)*?^\s*phone:\s*(?P<val>.+?)\s*$"),
            ]
        },
    },
    "tw": {
        "domain_name": {
            "patterns": [
                rx(r"(?im)^\s*Domain Name:\s*(?P<val>[A-Z0-9.-]+)\s*$"),
            ]
        },
        "status": {
            "patterns": [
                rx(r"(?im)^\s*Domain Status:\s*(?P<val>[A-Z0-9_-]+)(?:\s*,\s*[A-Z0-9_-]+)*\s*$"),
                rx(
                    r"(?im)^\s*Domain Status:\s*[A-Z0-9_-]+\s*,\s*(?P<val>[A-Z0-9_-]+)"
                    r"(?:\s*,\s*[A-Z0-9_-]+)*\s*$"
                ),
                rx(
                    r"(?im)^\s*Domain Status:\s*[A-Z0-9_-]+\s*,\s*[A-Z0-9_-]+\s*,\s*(?P<val>[A-Z0-9_-]+)"
                    r"(?:\s*,\s*[A-Z0-9_-]+)*\s*$"
                ),
                rx(
                    r"(?im)^\s*Domain Status:\s*[A-Z0-9_-]+\s*,\s*[A-Z0-9_-]+\s*,\s*[A-Z0-9_-]+\s*,\s*"
                    r"(?P<val>[A-Z0-9_-]+)\s*$"
                ),
            ],
            "mode": Mode.all,
            "unique": True,
            "return_shape": ReturnShape.list_,
        },
        "registrant_organization": {
            "patterns": [
                rx(r"(?ims)^\s*Registrant:\s*\r?\n\s*[^\r\n]*\r?\n\s*(?P<val>[A-Z].+?)\s*$"),
            ]
        },
        "registrant_email": {
            "patterns": [
                rx(
                    r"(?ims)^\s*Registrant:\s*\r?\n(?:.*\r?\n){0,8}?^\s*(?P<val>[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,})\s*$"
                ),
                rx(
                    r"(?ims)^\s*Registrant:\s*\r?\n(?:.*\r?\n){0,8}?^[^\r\n]*\s+(?P<val>[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,})\s*$"
                ),
            ]
        },
        "registrant_name": {
            "patterns": [
                rx(
                    r"(?ims)^\s*Registrant:\s*\r?\n(?:.*\r?\n){0,8}?"
                    r"^\s*(?P<val>[A-Z][A-Z .'-]{2,})\s+[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\s*$"
                ),
            ]
        },
        "registrant_telephone": {
            "patterns": [
                rx(r"(?ims)^\s*Registrant:\s*\r?\n(?:.*\r?\n){0,10}?^\s*(?P<val>\+?\d[\d().\-\s]*\d)\s*$"),
            ]
        },
        "expiration_date": {
            "patterns": [
                rx(r"(?im)^\s*Record expires on\s*(?P<val>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s*\(UTC\+\d+\)\s*$"),
            ]
        },
        "creation_date": {
            "patterns": [
                rx(r"(?im)^\s*Record created on\s*(?P<val>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s*\(UTC\+\d+\)\s*$"),
            ]
        },
        "name_servers": {
            "patterns": [
                rx(r"(?im)^\s*(?P<val>[A-Z0-9-]+(?:\.[A-Z0-9-]+)+)\s*$"),
                rx(r"(?im)^\s*(?P<val>[A-Z0-9-]+(?:\.[A-Z0-9-]+)+)\s+\d{1,3}(?:\.\d{1,3}){3}\s*$"),
                rx(r"(?im)^\s*(?P<val>[A-Z0-9-]+(?:\.[A-Z0-9-]+)+)\s+[0-9A-F:.]+\s*(?:\d{1,3}(?:\.\d{1,3}){3})?\s*$"),
            ],
            "mode": Mode.all,
            "unique": True,
            "return_shape": ReturnShape.list_,
        },
        "registrar": {
            "patterns": [
                rx(r"(?im)^\s*Registration Service Provider:\s*(?P<val>.+?)\s*$"),
            ]
        },
        "registrar_url": {
            "patterns": [
                rx(r"(?im)^\s*Registration Service URL:\s*(?P<val>https?://\S+)\s*$"),
            ]
        },
        "abuse_email": {
            "patterns": [
                rx(r"(?im)^\s*Registrar Abuse Contact Email:\s*(?P<val>[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,})\s*$"),
            ]
        },
    },
    "ua": {
        "domain_name": {
            "patterns": [
                rx(r"(?im)^\s*domain:\s*(?P<val>[a-z0-9.-]+)\s*$"),
            ]
        },
        "registrar": {
            "patterns": [
                rx(r"(?im)^\s*registrar:\s*(?P<val>[^\r\n]+)\s*$"),
            ]
        },
        "registrant_name": {
            "extend_patterns": [
                rx(
                    r"(?ims)^\s*Registrant:\s*\r?\n(?:.*\r?\n){0,6}^\s*(?P<val>[A-Z][A-Z .'-]{2,}?)\s+"
                    r"[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\s*$"
                ),
            ]
        },
        "registrar_url": {
            "patterns": [
                rx(r"(?im)^\s*url:\s*(?P<val>https?://\S+)\s*$"),
            ]
        },
        "abuse_email": {
            "patterns": [
                rx(r"(?im)^\s*abuse-email:\s*(?P<val>[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,})\s*$"),
            ]
        },
        "abuse_telephone": {
            "patterns": [
                rx(r"(?im)^\s*abuse-phone:\s*(?P<val>.+?)\s*$"),
            ]
        },
        "creation_date": {
            "patterns": [
                rx(r"(?im)^\s*created:\s*(?P<val>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\+\d{2})\s*$"),
            ]
        },
        "updated_date": {
            "patterns": [
                rx(r"(?im)^\s*modified:\s*(?P<val>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\+\d{2})\s*$"),
            ]
        },
        "expiration_date": {
            "patterns": [
                rx(r"(?im)^\s*expires:\s*(?P<val>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\+\d{2})\s*$"),
            ]
        },
        "status": {
            "patterns": [
                rx(r"(?im)^\s*status:\s*(?P<val>[^\r\n]+)\s*$"),
            ],
            "mode": Mode.all,
            "unique": True,
            "return_shape": ReturnShape.list_,
        },
        "name_servers": {
            "patterns": [
                rx(r"(?im)^\s*nserver:\s*(?P<val>[A-Z0-9-]+(?:\.[A-Z0-9-]+)+)\s*$"),
            ],
            "mode": Mode.all,
            "unique": True,
            "return_shape": ReturnShape.list_,
        },
    },
}
