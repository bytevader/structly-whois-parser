from __future__ import annotations

from collections.abc import Callable, Iterable, Iterator, Mapping, MutableMapping
from datetime import datetime
from typing import Any

from structly import StructlyParser

from .config import (
    DEFAULT_CONFIG_FACTORY,
    DEFAULT_TLDS,
    FieldOverride,
    StructlyConfigFactory,
    build_structly_config_for_tld,
)
from .domain_inference import (
    infer_domain_from_text,
    normalise_tld,
    refresh_domain_markers,
    split_domain,
)
from .normalization import normalize_raw_text
from .records import RecordBuilder, WhoisRecord, is_rate_limited_payload

refresh_domain_markers(DEFAULT_CONFIG_FACTORY.base_fields, DEFAULT_CONFIG_FACTORY.tld_overrides)

DateParser = Callable[[str], datetime]


class WhoisParser:
    """High-level WHOIS parser built on top of Structly."""

    def __init__(
        self,
        *,
        preload_tlds: Iterable[str] | None = None,
        rayon_policy: str | None = None,
        config_factory: StructlyConfigFactory | None = None,
        extra_tld_overrides: Mapping[str, Mapping[str, FieldOverride]] | None = None,
        date_parser: DateParser | None = None,
        record_builder: RecordBuilder | None = None,
    ) -> None:
        self._config_factory = config_factory or StructlyConfigFactory()
        if extra_tld_overrides:
            for tld, overrides in extra_tld_overrides.items():
                self._config_factory.register_tld(tld, overrides, replace=False)
        base_tlds = DEFAULT_TLDS if preload_tlds is None else preload_tlds
        wanted = set(normalise_tld(tld) for tld in base_tlds)
        if extra_tld_overrides:
            wanted.update(normalise_tld(tld) for tld in extra_tld_overrides)
        self._parsers: dict[str, StructlyParser] = {}
        self._rayon_policy = rayon_policy
        self._date_parser = date_parser
        self._record_builder = record_builder or RecordBuilder()
        for tld in sorted(wanted):
            if not tld:
                continue
            self._parsers[tld] = self._build_structly_parser(tld)
        self._default = self._build_structly_parser(None)
        refresh_domain_markers(self._config_factory.base_fields, self._config_factory.tld_overrides)

    @property
    def supported_tlds(self) -> tuple[str, ...]:
        return tuple(sorted(self._parsers.keys()))

    @property
    def default_date_parser(self) -> DateParser | None:
        """Return the callable used for date post-processing, if any."""
        return self._date_parser

    def _select_tld(self, explicit_tld: str | None, domain: str | None) -> str:
        target = normalise_tld(explicit_tld)
        if target:
            return target

        labels = split_domain(domain)
        if not labels:
            return ""

        for start in range(len(labels)):
            candidate = ".".join(labels[start:])
            if candidate in self._parsers:
                return candidate
        return labels[-1]

    def _build_structly_parser(self, tld: str | None) -> StructlyParser:
        return StructlyParser(
            build_structly_config_for_tld(tld, factory=self._config_factory),
            rayon_policy=self._rayon_policy,
        )

    def _get_parser_for_tld(self, tld: str) -> StructlyParser:
        if not tld:
            return self._default
        if tld not in self._parsers:
            self._parsers[tld] = self._build_structly_parser(tld)
        return self._parsers[tld]

    def register_tld(
        self,
        tld: str,
        overrides: Mapping[str, FieldOverride],
        *,
        replace: bool = False,
        preload: bool = True,
    ) -> None:
        """Register or update a TLD-specific parser override."""
        normalized = normalise_tld(tld)
        if not normalized:
            raise ValueError("TLD label cannot be empty")
        self._config_factory.register_tld(normalized, overrides, replace=replace)
        if preload:
            self._parsers[normalized] = self._build_structly_parser(normalized)
        elif normalized in self._parsers:
            del self._parsers[normalized]
        refresh_domain_markers(self._config_factory.base_fields, self._config_factory.tld_overrides)

    def refresh_default_parser(self) -> None:
        """Rebuild the default Structly parser."""
        self._default = self._build_structly_parser(None)

    def parse(
        self,
        raw_text: str,
        *,
        domain: str | None = None,
        tld: str | None = None,
    ) -> MutableMapping[str, str]:
        """Parse a WHOIS payload into a mapping of canonical fields."""
        text = normalize_raw_text(raw_text)
        inferred_domain = domain
        default_parsed: MutableMapping[str, str] | None = None
        if not inferred_domain and not tld:
            inferred_domain = infer_domain_from_text(text)
            if not inferred_domain:
                default_parsed = self._default.parse(text)
                candidate = default_parsed.get("domain_name")
                if isinstance(candidate, str) and candidate.strip():
                    inferred_domain = candidate.strip()
        target_tld = self._select_tld(tld, inferred_domain)
        parser = self._get_parser_for_tld(target_tld)
        if target_tld == "" and default_parsed is not None:
            return default_parsed
        return parser.parse(text)

    def parse_record(
        self,
        raw_text: str,
        *,
        domain: str | None = None,
        tld: str | None = None,
        lowercase: bool = False,
        date_parser: DateParser | None = None,
    ) -> WhoisRecord:
        """Parse a WHOIS payload and return a validated WhoisRecord."""
        if is_rate_limited_payload(raw_text):
            return self._record_builder.build(
                raw_text,
                {},
                lowercase=lowercase,
                date_parser=date_parser or self._date_parser,
            )
        parsed = self.parse(raw_text, domain=domain, tld=tld)
        return self._record_builder.build(
            raw_text,
            parsed,
            lowercase=lowercase,
            date_parser=date_parser or self._date_parser,
        )

    def parse_many(
        self,
        payloads: Iterable[str],
        *,
        domain: str | None = None,
        tld: str | None = None,
        to_records: bool = False,
        lowercase: bool = False,
        date_parser: DateParser | None = None,
    ) -> list[MutableMapping[str, str]] | list[WhoisRecord]:
        target_tld = self._select_tld(tld, domain)
        parser = self._get_parser_for_tld(target_tld)
        parser_input: Iterable[str]
        if to_records:
            raw_payloads = list(payloads)
            parser_input = (normalize_raw_text(text) for text in raw_payloads)
        else:
            raw_payloads = None
            parser_input = (normalize_raw_text(text) for text in payloads)
        parsed_payloads = parser.parse_many(parser_input)
        if not to_records:
            return parsed_payloads
        records: list[WhoisRecord] = []
        if raw_payloads is None:
            return records
        parsed_list = list(parsed_payloads)
        if len(parsed_list) != len(raw_payloads):
            raise RuntimeError("Structly returned an unexpected number of results")
        for raw_text, parsed in zip(raw_payloads, parsed_list):
            records.append(
                self._record_builder.build(
                    raw_text,
                    parsed,
                    lowercase=lowercase,
                    date_parser=date_parser or self._date_parser,
                )
            )
        return records

    def parse_chunks(
        self,
        payloads: Iterable[str],
        *,
        domain: str | None = None,
        tld: str | None = None,
        chunk_size: int = 512,
    ) -> Iterator[list[MutableMapping[str, Any]]]:
        target_tld = self._select_tld(tld, domain)
        parser = self._get_parser_for_tld(target_tld)
        return parser.parse_chunks(
            (normalize_raw_text(text) for text in payloads),
            chunk_size=chunk_size,
        )
