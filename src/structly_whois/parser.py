from __future__ import annotations

from collections.abc import Callable, Collection, Iterable, Iterator, Mapping, MutableMapping
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Literal, get_type_hints

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

TLDS_REQUIRING_DOMAIN_HINT = frozenset({"info", "za", "jobs", "live"})


def _effective_tld_for_domain(domain: str | None, known_tlds: Collection[str]) -> str:
    """Return the longest matching override TLD for a domain (fallback to final label)."""
    labels = split_domain(domain)
    if not labels:
        return ""
    for start in range(len(labels)):
        candidate = ".".join(labels[start:])
        if candidate in known_tlds:
            return candidate
    return labels[-1]


refresh_domain_markers(DEFAULT_CONFIG_FACTORY.base_fields, DEFAULT_CONFIG_FACTORY.tld_overrides)

DateParser = Callable[[str], datetime]


@dataclass(frozen=True)
class _DomainInputs:
    selection_hint: str | None
    hints: list[str] | None
    effective_tlds: list[str] | None
    unique_tld_count: int


@dataclass(frozen=True)
class _TldInputs:
    selection_hint: str | None
    per_row: list[str] | None
    unique_tld_count: int
    allow_domain_grouping: bool


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
        self._known_tld_suffixes: set[str] = set(self._config_factory.known_tlds)

    @property
    def default_date_parser(self) -> DateParser | None:
        """Return the callable used for date post-processing, if any."""
        return self._date_parser

    def supported_tlds(self) -> list[str]:
        """Return supported TLDs as a deterministic, sorted list."""
        configured = {tld for tld in self._parsers if tld}
        configured.update(self._config_factory.known_tlds)
        return sorted({tld for tld in configured if tld})

    def field_catalog(self, surface: Literal["record", "dict", "both"] = "record") -> dict[str, Any]:
        """Return a deterministic mapping of known fields and their types."""
        record_catalog = self._record_field_catalog()
        dict_catalog = self._dict_field_catalog()
        if surface == "record":
            return record_catalog
        if surface == "dict":
            return dict_catalog
        if surface == "both":
            merged: dict[str, Any] = dict(dict_catalog)
            merged.update(record_catalog)
            return dict(sorted(merged.items()))
        raise ValueError("surface must be one of: record, dict, both")

    @staticmethod
    def _record_field_catalog() -> dict[str, Any]:
        """Return Record surface metadata derived from WhoisRecord annotations."""
        hints = get_type_hints(WhoisRecord, include_extras=True)
        entries: list[tuple[str, Any]] = []
        for field_name, annotation in WhoisRecord.__annotations__.items():
            if field_name == "schema_version":
                continue
            field_type = hints.get(field_name, annotation)
            entries.append((field_name, field_type))
        return dict(sorted(entries))

    def _dict_field_catalog(self) -> dict[str, Any]:
        """Return the dictionary field catalog derived from Structly overrides."""
        names = set(self._config_factory.base_fields.keys())
        for overrides in self._config_factory.tld_overrides.values():
            names.update(overrides.keys())
        return {name: Any for name in sorted(names)}

    def _select_tld(self, explicit_tld: str | None, domain: str | None) -> str:
        """Return the normalized TLD override to use based on hints and known parsers."""
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
        """Instantiate a Structly parser for the requested TLD."""
        return StructlyParser(
            build_structly_config_for_tld(tld, factory=self._config_factory),
            rayon_policy=self._rayon_policy,
        )

    def _get_parser_for_tld(self, tld: str) -> StructlyParser:
        """Return a cached Structly parser, creating it lazily when needed."""
        if not tld:
            return self._default
        if tld not in self._parsers:
            self._parsers[tld] = self._build_structly_parser(tld)
        return self._parsers[tld]

    @staticmethod
    def _apply_domain_hint(
        parsed: MutableMapping[str, Any],
        *,
        domain_hint: str | None,
        target_tld: str,
    ) -> None:
        """Ensure problematic TLDs keep the user-provided domain name."""
        if target_tld not in TLDS_REQUIRING_DOMAIN_HINT or not domain_hint:
            return
        cleaned_hint = domain_hint.strip()
        if not cleaned_hint:
            return
        parsed_domain = parsed.get("domain_name")
        if isinstance(parsed_domain, str):
            normalized = parsed_domain.strip().strip(".").lower()
            if normalized and normalized != target_tld:
                return
        parsed["domain_name"] = cleaned_hint

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
        self._known_tld_suffixes.add(normalized)
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
    ) -> MutableMapping[str, Any]:
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
        parsed = parser.parse(text)
        self._apply_domain_hint(parsed, domain_hint=domain, target_tld=target_tld)
        return parsed

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

    @staticmethod
    def _materialize_payloads(
        payloads: Iterable[str],
        *,
        to_records: bool,
    ) -> tuple[list[str], list[str] | None]:
        """Normalize payload strings and optionally capture their original form."""
        normalized_payloads: list[str] = []
        raw_payloads: list[str] | None = [] if to_records else None
        for text in payloads:
            normalized_payloads.append(normalize_raw_text(text))
            if raw_payloads is not None:
                raw_payloads.append(text)
        return normalized_payloads, raw_payloads

    @staticmethod
    def _build_parser_input(
        payloads: Iterable[str],
        *,
        to_records: bool,
    ) -> tuple[Iterable[str], list[str] | None]:
        """Yield normalized payloads plus the optional raw list for record building."""
        if to_records:
            raw_payloads = list(payloads)
            return (normalize_raw_text(text) for text in raw_payloads), raw_payloads
        return (normalize_raw_text(text) for text in payloads), None

    def _apply_domain_hints_if_required(
        self,
        parsed_results: list[MutableMapping[str, Any]],
        *,
        domain_hints: list[str] | None,
        domain_hint_for_selection: str | None,
        target_tld: str,
    ) -> None:
        """Mutate parsed mappings so domain_name honors user hints for special TLDs."""
        if target_tld not in TLDS_REQUIRING_DOMAIN_HINT:
            return
        if domain_hints is not None:
            if len(parsed_results) != len(domain_hints):
                raise ValueError("domain hint count does not match payload count")
            for parsed, hint in zip(parsed_results, domain_hints):
                self._apply_domain_hint(parsed, domain_hint=hint, target_tld=target_tld)
            return
        if domain_hint_for_selection:
            for parsed in parsed_results:
                self._apply_domain_hint(parsed, domain_hint=domain_hint_for_selection, target_tld=target_tld)

    @staticmethod
    def _slice_domain_hints(domain_hints: list[str] | None, indices: Iterable[int]) -> list[str] | None:
        """Return a new list containing domain hints that align with group indices."""
        if domain_hints is None:
            return None
        return [domain_hints[index] for index in indices]

    def _build_records_from_parsed(
        self,
        raw_payloads: list[str] | None,
        parsed_list: list[MutableMapping[str, Any]],
        *,
        lowercase: bool,
        date_parser: DateParser | None,
    ) -> list[WhoisRecord]:
        if raw_payloads is None:
            return []
        if len(parsed_list) != len(raw_payloads):
            raise RuntimeError("Structly returned an unexpected number of results")
        records: list[WhoisRecord] = []
        for raw_text, parsed in zip(raw_payloads, parsed_list):
            records.append(
                self._record_builder.build(
                    raw_text,
                    parsed,
                    lowercase=lowercase,
                    date_parser=date_parser,
                )
            )
        return records

    def _finalize_parsed_sequence(
        self,
        parsed_iterable: Iterable[MutableMapping[str, str]],
        *,
        target_tld: str,
        domain_hints: list[str] | None,
        domain_hint_for_selection: str | None,
        to_records: bool,
        lowercase: bool,
        date_parser: DateParser | None,
        raw_payloads: list[str] | None,
        materialize: bool = False,
    ) -> Iterable[MutableMapping[str, str]] | list[WhoisRecord]:
        """Finalize Structly output, optionally applying hints and building WhoisRecord objects."""
        parsed_sequence: Iterable[MutableMapping[str, str]] = parsed_iterable
        needs_hint = target_tld in TLDS_REQUIRING_DOMAIN_HINT and (
            domain_hints is not None or domain_hint_for_selection
        )
        parsed_list: list[MutableMapping[str, Any]] | None = None
        if needs_hint:
            parsed_list = list(parsed_sequence)
            self._apply_domain_hints_if_required(
                parsed_list,
                domain_hints=domain_hints,
                domain_hint_for_selection=domain_hint_for_selection,
                target_tld=target_tld,
            )
            parsed_sequence = parsed_list
        if not to_records:
            if materialize:
                if isinstance(parsed_sequence, list):
                    return parsed_sequence
                return list(parsed_sequence)
            return parsed_sequence
        if raw_payloads is None:
            return []
        parsed_list = list(parsed_sequence)
        return self._build_records_from_parsed(
            raw_payloads,
            parsed_list,
            lowercase=lowercase,
            date_parser=date_parser,
        )

    def _prepare_domain_inputs(self, domain: str | Iterable[str] | None) -> _DomainInputs:
        """Build per-row domain hints and statistics used for grouping decisions."""
        if isinstance(domain, str) or domain is None:
            return _DomainInputs(
                selection_hint=domain,
                hints=None,
                effective_tlds=None,
                unique_tld_count=0,
            )
        domain_hints = list(domain)
        effective_tlds = [_effective_tld_for_domain(hint, self._known_tld_suffixes) for hint in domain_hints]
        unique_count = len(set(effective_tlds)) if effective_tlds else 0
        return _DomainInputs(
            selection_hint=domain_hints[0] if domain_hints else None,
            hints=domain_hints,
            effective_tlds=effective_tlds,
            unique_tld_count=unique_count,
        )

    @staticmethod
    def _prepare_tld_inputs(tld: str | Iterable[str] | None) -> _TldInputs:
        """Build per-row TLD hints and statistics used for grouping decisions."""
        if isinstance(tld, str) or tld is None:
            return _TldInputs(
                selection_hint=tld,
                per_row=None,
                unique_tld_count=1 if isinstance(tld, str) and tld else 0,
                allow_domain_grouping=tld is None,
            )
        tld_sequence = [normalise_tld(entry) for entry in tld]
        unique_values = set(tld_sequence)
        selection = tld_sequence[0] if tld_sequence else None
        if len(unique_values) <= 1:
            scalar = next(iter(unique_values), None)
            return _TldInputs(
                selection_hint=scalar or selection,
                per_row=None,
                unique_tld_count=len(unique_values),
                allow_domain_grouping=False,
            )
        return _TldInputs(
            selection_hint=selection,
            per_row=tld_sequence,
            unique_tld_count=len(unique_values),
            allow_domain_grouping=False,
        )

    @staticmethod
    def _should_group_batches(domain_info: _DomainInputs, tld_inputs: _TldInputs) -> bool:
        if tld_inputs.per_row is not None:
            return tld_inputs.unique_tld_count > 1
        if tld_inputs.allow_domain_grouping:
            return domain_info.unique_tld_count > 1
        return False

    def _parse_grouped_payloads(
        self,
        normalized_payloads: list[str],
        *,
        domain_info: _DomainInputs,
        tld_inputs: _TldInputs,
    ) -> list[MutableMapping[str, str]] | None:
        total = len(normalized_payloads)
        if total == 0:
            return []
        row_tlds = self._resolve_row_tlds(total, domain_info=domain_info, tld_inputs=tld_inputs)
        if row_tlds is None:
            return None
        unique_tlds = set(row_tlds)
        if len(unique_tlds) == 1:
            return self._parse_single_group(
                normalized_payloads,
                target_tld=row_tlds[0],
                domain_info=domain_info,
            )
        return self._parse_multi_group(
            normalized_payloads,
            row_tlds=row_tlds,
            domain_info=domain_info,
        )

    @staticmethod
    def _resolve_row_tlds(
        total_rows: int,
        *,
        domain_info: _DomainInputs,
        tld_inputs: _TldInputs,
    ) -> list[str] | None:
        if tld_inputs.per_row is not None:
            if len(tld_inputs.per_row) != total_rows:
                return None
            return tld_inputs.per_row
        if tld_inputs.allow_domain_grouping and domain_info.effective_tlds is not None:
            if len(domain_info.effective_tlds) != total_rows:
                return None
            return domain_info.effective_tlds
        return None

    def _parse_single_group(
        self,
        normalized_payloads: list[str],
        *,
        target_tld: str,
        domain_info: _DomainInputs,
    ) -> list[MutableMapping[str, str]]:
        parser = self._get_parser_for_tld(target_tld)
        parsed_iter = parser.parse_many(iter(normalized_payloads))
        parsed_list = list(parsed_iter)
        self._apply_domain_hints_if_required(
            parsed_list,
            domain_hints=domain_info.hints,
            domain_hint_for_selection=domain_info.selection_hint,
            target_tld=target_tld,
        )
        return parsed_list

    def _parse_multi_group(
        self,
        normalized_payloads: list[str],
        *,
        row_tlds: list[str],
        domain_info: _DomainInputs,
    ) -> list[MutableMapping[str, str]]:
        buckets: dict[str, list[int]] = {}
        for idx, tld_value in enumerate(row_tlds):
            buckets.setdefault(tld_value, []).append(idx)
        ordered_results: list[MutableMapping[str, str] | None] = [None] * len(normalized_payloads)
        for target_tld, indices in buckets.items():
            bucket_payloads = [normalized_payloads[i] for i in indices]
            parser = self._get_parser_for_tld(target_tld)
            parsed_iter = parser.parse_many(bucket_payloads)
            bucket_results = list(parsed_iter)
            if len(bucket_results) != len(indices):
                raise RuntimeError("Structly returned an unexpected number of results")
            bucket_domain_hints = self._slice_domain_hints(domain_info.hints, indices)
            self._apply_domain_hints_if_required(
                bucket_results,
                domain_hints=bucket_domain_hints,
                domain_hint_for_selection=domain_info.selection_hint,
                target_tld=target_tld,
            )
            for position, parsed in zip(indices, bucket_results):
                ordered_results[position] = parsed
        finalized_results: list[MutableMapping[str, str]] = []
        for parsed in ordered_results:
            if parsed is None:
                raise RuntimeError("Structly returned an unexpected number of results")
            finalized_results.append(parsed)
        return finalized_results

    def parse_many(
        self,
        payloads: Iterable[str],
        *,
        domain: str | Iterable[str] | None = None,
        tld: str | Iterable[str] | None = None,
        to_records: bool = False,
        lowercase: bool = False,
        date_parser: DateParser | None = None,
    ) -> Iterable[MutableMapping[str, str]] | list[WhoisRecord]:
        """Parse an iterable of WHOIS payloads, optionally returning WhoisRecord objects."""
        domain_info = self._prepare_domain_inputs(domain)
        tld_inputs = self._prepare_tld_inputs(tld)
        selected_date_parser = date_parser or self._date_parser
        if self._should_group_batches(domain_info, tld_inputs):
            normalized_payloads, raw_payloads = self._materialize_payloads(payloads, to_records=to_records)
            grouped_result = self._parse_grouped_payloads(
                normalized_payloads,
                domain_info=domain_info,
                tld_inputs=tld_inputs,
            )
            if grouped_result is not None:
                if not to_records:
                    return grouped_result
                return self._build_records_from_parsed(
                    raw_payloads,
                    grouped_result,
                    lowercase=lowercase,
                    date_parser=selected_date_parser,
                )
            target_tld = self._select_tld(tld_inputs.selection_hint, domain_info.selection_hint)
            parser = self._get_parser_for_tld(target_tld)
            return self._finalize_parsed_sequence(
                parser.parse_many(iter(normalized_payloads)),
                target_tld=target_tld,
                domain_hints=domain_info.hints,
                domain_hint_for_selection=domain_info.selection_hint,
                to_records=to_records,
                lowercase=lowercase,
                date_parser=selected_date_parser,
                raw_payloads=raw_payloads,
                materialize=True,
            )
        target_tld = self._select_tld(tld_inputs.selection_hint, domain_info.selection_hint)
        parser = self._get_parser_for_tld(target_tld)
        parser_input, raw_payloads = self._build_parser_input(payloads, to_records=to_records)
        return self._finalize_parsed_sequence(
            parser.parse_many(parser_input),
            target_tld=target_tld,
            domain_hints=domain_info.hints,
            domain_hint_for_selection=domain_info.selection_hint,
            to_records=to_records,
            lowercase=lowercase,
            date_parser=selected_date_parser,
            raw_payloads=raw_payloads,
        )

    def parse_chunks(
        self,
        payloads: Iterable[str],
        *,
        domain: str | None = None,
        tld: str | None = None,
        chunk_size: int = 512,
    ) -> Iterator[list[MutableMapping[str, Any]]]:
        """Yield parsed WHOIS payloads in chunks, applying domain hints when required."""
        target_tld = self._select_tld(tld, domain)
        parser = self._get_parser_for_tld(target_tld)
        normalized_inputs = (normalize_raw_text(text) for text in payloads)
        chunks = parser.parse_chunks(normalized_inputs, chunk_size=chunk_size)
        if not domain or target_tld not in TLDS_REQUIRING_DOMAIN_HINT:
            return chunks

        def _apply_hint() -> Iterator[list[MutableMapping[str, Any]]]:
            for chunk in chunks:
                for parsed in chunk:
                    self._apply_domain_hint(parsed, domain_hint=domain, target_tld=target_tld)
                yield chunk

        return _apply_hint()
