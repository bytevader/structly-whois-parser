from __future__ import annotations

from typing import Dict, Iterable, MutableMapping, Optional, List, Tuple, Any, Iterator, Mapping, Union

from structly import StructlyParser

from .config import (
    DEFAULT_TLDS,
    FieldOverride,
    StructlyConfigFactory,
    build_structly_config_for_tld,
)
from .normalization import normalize_raw_text
from .records import WhoisRecord, build_whois_record, is_rate_limited_payload


def _normalise_tld(label: Optional[str]) -> str:
    if not label:
        return ""
    return label.strip().lstrip(".").lower()


def _split_domain(domain: Optional[str]) -> List[str]:
    if not domain:
        return []
    stripped = domain.strip().strip(".").lower()
    return [segment for segment in stripped.split(".") if segment]


class WhoisParser:
    """Compile structly parsers for multiple TLDs and route inputs appropriately."""

    def __init__(
        self,
        *,
        preload_tlds: Iterable[str] | None = None,
        rayon_policy: Optional[str] = None,
        config_factory: StructlyConfigFactory | None = None,
        extra_tld_overrides: Mapping[str, Dict[str, FieldOverride]] | None = None,
    ) -> None:
        self._config_factory = config_factory or StructlyConfigFactory()
        if extra_tld_overrides:
            for tld, overrides in extra_tld_overrides.items():
                self._config_factory.register_tld(tld, overrides, replace=False)
        base_tlds = DEFAULT_TLDS if preload_tlds is None else preload_tlds
        wanted = set(_normalise_tld(tld) for tld in base_tlds)
        if extra_tld_overrides:
            wanted.update(_normalise_tld(tld) for tld in extra_tld_overrides.keys())
        self._parsers: Dict[str, StructlyParser] = {}
        self._rayon_policy = rayon_policy
        for tld in sorted(wanted):
            if not tld:
                continue
            self._parsers[tld] = self._build_structly_parser(tld)
        self._default = self._build_structly_parser(None)

    @property
    def supported_tlds(self) -> Tuple[str, ...]:
        return tuple(sorted(self._parsers.keys()))

    def _select_tld(self, explicit_tld: Optional[str], domain: Optional[str]) -> str:
        target = _normalise_tld(explicit_tld)
        if target:
            return target

        labels = _split_domain(domain)
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
        normalized = _normalise_tld(tld)
        if not normalized:
            raise ValueError("TLD label cannot be empty")
        self._config_factory.register_tld(normalized, overrides, replace=replace)
        if preload:
            self._parsers[normalized] = self._build_structly_parser(normalized)
        elif normalized in self._parsers:
            del self._parsers[normalized]

    def refresh_default_parser(self) -> None:
        """Rebuild the default Structly parser."""
        self._default = self._build_structly_parser(None)

    def parse(self, raw_text: str, *, domain: Optional[str] = None, tld: Optional[str] = None) -> MutableMapping[str, str]:
        text = normalize_raw_text(raw_text)
        target_tld = self._select_tld(tld, domain)
        parser = self._get_parser_for_tld(target_tld)
        return parser.parse(text)

    def parse_record(
        self,
        raw_text: str,
        *,
        domain: Optional[str] = None,
        tld: Optional[str] = None,
        lowercase: bool = False,
    ) -> WhoisRecord:
        """Parse a WHOIS payload and return a validated WhoisRecord."""
        if is_rate_limited_payload(raw_text):
            return build_whois_record(raw_text, {}, lowercase=lowercase)
        parsed = self.parse(raw_text, domain=domain, tld=tld)
        return build_whois_record(raw_text, parsed, lowercase=lowercase)

    def parse_many(
        self,
        payloads: Iterable[str],
        *,
        domain: Optional[str] = None,
        tld: Optional[str] = None,
        to_records: bool = False,
        lowercase: bool = False,
    ) -> Union[List[MutableMapping[str, str]], List[WhoisRecord]]:
        target_tld = self._select_tld(tld, domain)
        parser = self._get_parser_for_tld(target_tld)
        if to_records:
            raw_payloads = list(payloads)
            normalized_iter = (normalize_raw_text(text) for text in raw_payloads)
        else:
            raw_payloads = None
            normalized_iter = (normalize_raw_text(text) for text in payloads)
        parsed_payloads = parser.parse_many(normalized_iter)
        if not to_records:
            return parsed_payloads
        records: List[WhoisRecord] = []
        for raw_text, parsed in zip(raw_payloads or [], parsed_payloads):
            records.append(build_whois_record(raw_text, parsed, lowercase=lowercase))
        return records

    def parse_chunks(
        self,
        payloads: Iterable[str],
        *,
        domain: Optional[str] = None,
        tld: Optional[str] = None,
        chunk_size: int = 512,
    ) -> Iterator[List[MutableMapping[str, Any]]]:
        target_tld = self._select_tld(tld, domain)
        parser = self._get_parser_for_tld(target_tld)
        return parser.parse_chunks(
            (normalize_raw_text(text) for text in payloads),
            chunk_size=chunk_size,
        )
