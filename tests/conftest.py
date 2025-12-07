from __future__ import annotations

from pathlib import Path

import pytest

RATE_LIMIT = "WHOIS LIMIT EXCEEDED"


@pytest.fixture(scope="session")
def sample_payloads() -> dict[str, str]:
    """Reusable WHOIS payloads that cover a diverse set of registries."""
    com = """\
        # first response should be ignored
        Domain Name: stale.example.com
        # whois.server.one
        Domain Name: example.com
        Registrar: Example Registrar LLC
        Registrar URL: https://registrar.example
        Registrar IANA ID: 1040
        Creation Date: 2020-01-01T12:00:00Z
        Updated Date: 2024-01-02T09:30:00Z
        Registry Expiry Date: 2030-01-01T12:00:00Z
        Name Server: NS1.EXAMPLE.COM
        Name Server: NS2.EXAMPLE.COM
        Name Server: NS1.EXAMPLE.COM
        Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited
        Status: clientUpdateProhibited https://icann.org/epp#clientUpdateProhibited
        Registrant Organization: Example Corp
        Registrant Name: Example DNS
        Registrant Email: ops@example.com
        Registrant Phone: +1.5550000
        Admin Email: admin@example.com
        Tech Email: tech@example.com
        DNSSEC: unsigned
        """
    net_multiline = """\
                    Domain name:
                        example.net
                    Registrar:
                        Example Networks
                    Creation Date: 2019-01-01T00:00:00Z
                    Updated Date: 2022-01-01T00:00:00Z
                    Registry Expiry Date: 2027-01-01T00:00:00Z
                    Name Server: NS.ANY.NET
                    Status: ok
                    """
    org_missing = """\
                Domain Name: privacy-shield.org
                Registrar: Privacy Example Registrar
                Registry Expiry Date: 2028-01-01T00:00:00Z
                Registrant Organization: REDACTED FOR PRIVACY
                Registrant Email: contact@privacyshield.invalid
                """
    com_br = """\
            domain: google.com.br
            owner: Google Brasil Internet Ltda
            responsible: Domain Administrator
            e-mail: registro@google.com
            created: 20050101
            changed: 20230101
            expires: 20260101
            nserver: ns1.google.com
            nserver: ns2.google.com
            status: published
            nic-hdl-br: EXEMP123
            tech-c: EXEMP123
            source: BR-NIC
            nic-hdl-br: EXEMP123
            person: Tech Contact
            e-mail: tech@google.com
            source: BR-NIC
            """
    uk_privacy = (
        "Domain name: example.uk\n"
        "Data validation: Nominet was able to match the registrant's name and address "
        "against a 3rd party data source on 1-Jan-2024\n"
        "Registrar: Example Registrar t/a Example [Tag = EXAMPLE]\n"
        "Registered on: 2014-06-11\n"
        "Expiry date: 2030-06-11\n"
        "Last updated: 2024-05-24\n"
        "Name servers:\n"
        "  ns1.example.uk\n"
        "  ns2.example.uk\n"
    )
    afnic = """\
% This is the AFNIC Whois server.
%%
%% complete response
%%
Domain Name: example.fr
Registrar: AFNIC
Status: ACTIVE
nic-hdl: AA123-FRNIC
type: ORGANIZATION
contact: AFNIC Test
e-mail: hostmaster@example.fr
phone: +33.123456789
source: FRNIC

nic-hdl: BB123-FRNIC
type: PERSON
contact: Admin Contact
e-mail: admin@example.fr
phone: +33.987654321
source: FRNIC

holder-c: AA123-FRNIC
admin-c: BB123-FRNIC
tech-c: BB123-FRNIC
"""
    return {
        "com": com,
        "net_multiline": net_multiline,
        "org_missing": org_missing,
        "com_br": com_br,
        "uk_privacy": uk_privacy,
        "afnic": afnic,
        "rate_limited": RATE_LIMIT,
    }


@pytest.fixture(scope="session")
def tmp_payload(tmp_path_factory: pytest.TempPathFactory) -> Path:
    path = tmp_path_factory.mktemp("whois") / "sample.txt"
    path.write_text(
        "Domain Name: cli.example\nStatus: ok\nCreation Date: 2021-01-01T00:00:00Z\n",
        encoding="utf-8",
    )
    return path
