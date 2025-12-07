from __future__ import annotations

import re
from collections.abc import Mapping, MutableMapping
from dataclasses import dataclass, field
from threading import RLock
from typing import Any

from structly import FieldPatternType


@dataclass
class DomainPatternRegistry:
    prefixes: tuple[str, ...] = ()
    regexes: tuple[re.Pattern[str], ...] = ()
    _lock: RLock = field(default_factory=RLock, init=False, repr=False)

    def refresh(
        self,
        base_fields: Mapping[str, MutableMapping[str, Any]],
        overrides: Mapping[str, Mapping[str, MutableMapping[str, Any]]],
    ) -> None:
        prefixes: set[str] = set()
        regexes: set[str] = set()

        def _add_patterns(field_def: MutableMapping[str, Any] | None) -> None:
            if not field_def:
                return
            for key in ("patterns", "extend_patterns", "prepend_patterns"):
                patterns = field_def.get(key)
                if not patterns:
                    continue
                for pattern in patterns:
                    if pattern.pattern_type == FieldPatternType.STARTS_WITH:
                        prefixes.add(pattern.pattern)
                    elif pattern.pattern_type == FieldPatternType.REGEX:
                        regexes.add(pattern.pattern)

        _add_patterns(base_fields.get("domain_name"))
        for domain_overrides in overrides.values():
            _add_patterns(domain_overrides.get("domain_name"))

        compiled = tuple(re.compile(p, re.MULTILINE) for p in regexes)
        with self._lock:
            self.prefixes = tuple(prefixes)
            self.regexes = compiled

    def infer(self, text: str) -> str | None:
        for pattern in self.regexes:
            match = pattern.search(text)
            if not match:
                continue
            group_dict = match.groupdict()
            for key in ("domain", "val", "value"):
                candidate = group_dict.get(key)
                if candidate:
                    return candidate.strip()
            if match.lastindex:
                candidate = match.group(match.lastindex)
                if candidate:
                    return candidate.strip()
            candidate = match.group(0).strip()
            if candidate:
                return candidate
        for line in text.splitlines():
            for prefix in self.prefixes:
                if line.startswith(prefix):
                    remainder = line[len(prefix) :].strip()
                    if not remainder:
                        continue
                    candidate = remainder.split()[0].strip(" .")
                    if candidate:
                        return candidate
        return None


_REGISTRY = DomainPatternRegistry()


def refresh_domain_markers(
    base_fields: Mapping[str, MutableMapping[str, Any]],
    overrides: Mapping[str, Mapping[str, MutableMapping[str, Any]]],
) -> None:
    _REGISTRY.refresh(base_fields, overrides)


def normalise_tld(label: str | None) -> str:
    if not label:
        return ""
    return label.strip().lstrip(".").lower()


def split_domain(domain: str | None) -> list[str]:
    if not domain:
        return []
    stripped = domain.strip().strip(".").lower()
    return [segment for segment in stripped.split(".") if segment]


def infer_domain_from_text(text: str) -> str | None:
    return _REGISTRY.infer(text)


def get_domain_registry() -> DomainPatternRegistry:
    return _REGISTRY


__all__ = [
    "infer_domain_from_text",
    "normalise_tld",
    "split_domain",
    "DomainPatternRegistry",
    "refresh_domain_markers",
    "get_domain_registry",
]
