# Schema contract

## Overview

- `structly-whois` parses raw WHOIS text only. It never performs live WHOIS lookups.
- The library is designed for ingestion pipelines where downstream schemas must remain stable across releases.
- The canonical output surface is a structured record (`WhoisRecord`). Mapping outputs remain available for flexibility but do not carry the same stability guarantees.

## Output surfaces

| Surface | API | Stability |
| --- | --- | --- |
| Mapping (dict) | `parse`, `parse_many` | Keys are derived from Structly field definitions and may vary per TLD. They are best-effort, config-driven, and may include registry-specific fields. |
| Canonical record | `parse_record`, `parse_many(..., to_records=True)` | Produces a typed `WhoisRecord` whose fields, meanings, and normalization rules are versioned. This is the recommended integration surface. |

Use the new `WhoisRecord.schema_version` to detect breaking schema changes, and inspect the field catalog programmatically via `WhoisParser.field_catalog(surface=...)`.

## Canonical fields

| Field | Type | Meaning | Notes |
| --- | --- | --- | --- |
| `schema_version` | `ClassVar[str]` | Schema contract version (`WhoisRecord.schema_version`). | Not serialized; use for compatibility checks. |
| `raw_text` | `str` | Original WHOIS payload that was parsed. | Preserved verbatim for auditing. |
| `registrant`, `admin`, `tech` | `Contact` (`name`, `email`, `organization`, `telephone`) | Contact identities extracted from payload. | Lowercased when `lowercase=True`. Missing fields remain `None`. |
| `abuse` | `Abuse` (`email`, `telephone`) | Registry abuse-contact details. | Lowercased when `lowercase=True`. |
| `statuses` | `list[str]` | Registry/domain status codes. | Preserves discovery order; duplicates removed case-insensitively. |
| `name_servers` | `list[str]` | Name server hostnames. | Deduplicated, optional lowercase normalization. |
| `domain` | `str \| None` | Canonical domain name derived from payload or caller hint. | Lowercased when `lowercase=True`. |
| `registrar` | `str \| None` | Sponsoring registrar name. | Lowercased when `lowercase=True`. |
| `registrar_id` | `str \| None` | Registrar IANA ID (if provided). | Lowercased when `lowercase=True`. |
| `registrar_url` | `str \| None` | Registrar website. | Lowercased when `lowercase=True`. |
| `dnssec` | `str \| None` | DNSSEC status as reported by registry. | Lowercased when `lowercase=True`. |
| `registered_at` | `datetime \| str \| None` | Domain creation time. | See “Type rules and date policy”. |
| `updated_at` | `datetime \| str \| None` | Last update time. | See “Type rules and date policy”. |
| `expires_at` | `datetime \| str \| None` | Expiration time. | See “Type rules and date policy”. |
| `is_rate_limited` | `bool` | True when payload matches known rate-limit banners. | Determined before parsing. |

## Type rules and date policy

- Date fields (`registered_at`, `updated_at`, `expires_at`) default to `datetime` objects when the timestamp matches the built-in fast parsers. When the registry uses an unknown format, the original (optionally lowercased) string is preserved.
- Supplying `date_parser=` when calling `parse_record`/`parse_many(..., to_records=True)` allows callers to coerce remaining strings into datetimes. Failures fall back to the normalized string.
- Contacts and scalar string fields are either `str` or `None`. List fields are always lists (possibly empty).
- Mapping output (`parse`) returns raw Structly extraction results (`creation_date`, `registrant_email`, etc.) without coercing into structured types.

## Normalization rules

- All leading/trailing whitespace is stripped before extraction.
- Passing `lowercase=True` to `parse_record`/`parse_many(to_records=True)` lowercases string scalars, contact values, and list entries. Duplicate list entries are removed case-insensitively while preserving first-seen order.
- Domains and name servers are **not** punycode/IDNA-normalized automatically. Inputs must already be normalized if that behavior is required.
- No additional Unicode folding is performed beyond optional lowercasing.

## Missing vs. redacted values

- Missing: If a field is absent from the payload, the canonical record sets it to `None` (or an empty list). Mapping outputs simply omit the key or set it to `None`, depending on the Structly extractor.
- Redacted: When registries provide redaction-sentinel strings (“REDACTED FOR PRIVACY”), they are preserved verbatim. The library does not attempt to expand or interpret redactions.

## Stability guarantees

The schema follows Semantic Versioning semantics, tracked via `WhoisRecord.schema_version`:

- **Patch releases** do not remove or rename canonical fields. They only include bug fixes or parser quality improvements.
- **Minor releases** may add new optional canonical fields but will not remove or rename existing ones.
- **Major releases** may introduce breaking schema changes. The schema version will advance accordingly.

These guarantees apply to `WhoisRecord` (and therefore `parse_record` / `parse_many(..., to_records=True)`). Mapping outputs remain best-effort and may emit registry-specific keys tied to Structly configurations. Downstream systems that require stability should consume canonical records or use `WhoisParser.field_catalog(surface="record")` to introspect available fields programmatically.
