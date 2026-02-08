from __future__ import annotations

import re
from collections.abc import Iterable, MutableMapping
from typing import Any

from .normalizers import CORE_NORMALIZERS, CORE_TEXT_NORMALIZERS, Normalizer, TextNormalizer


class NormalizerPluginError(RuntimeError):
    """Raised when plugin discovery fails or returns invalid normalizers."""


_COLLAPSIBLE_HEADERS = {
    "domain name:",
    "registrar:",
    "registered on:",
    "registration status:",
    "expiry date:",
    "expiration date:",
    "last updated:",
    "updated date:",
    "abuse contact:",
    "flags:",
}

_DOMAIN_HEADER_RE = re.compile(r"(?im)^(domain\s+name:\s*)", re.MULTILINE)


def _slice_latest_section(raw_text: str) -> str:
    """Return the substring that starts at the last '#'-prefixed marker."""
    anchor = raw_text.rfind("\n#")
    if anchor != -1:
        return raw_text[anchor + 1 :]
    if raw_text.startswith("#"):
        return raw_text
    return raw_text


def _collapse_wrapped_fields(lines: Iterable[str]) -> list[str]:
    """Collapse "header" lines whose value sits on the next line."""
    collapsed: list[str] = []
    buffer = list(lines)
    idx = 0
    total = len(buffer)
    while idx < total:
        line = buffer[idx]
        lower = line.lower()
        if lower in _COLLAPSIBLE_HEADERS and idx + 1 < total:
            next_line = buffer[idx + 1]
            if next_line and ":" not in next_line:
                collapsed.append(f"{line} {next_line}")
                idx += 2
                continue
        collapsed.append(line)
        idx += 1
    return collapsed


def _slice_from_last_domain(text: str) -> str:
    """Fallback for registries that do not include hash markers."""
    last_start: int | None = None
    for match in _DOMAIN_HEADER_RE.finditer(text):
        last_start = match.start()
    if last_start is None:
        return text
    return text[last_start:]


def normalize_raw_text(raw_text: str, *, domain: str | None = None, tld: str | None = None) -> str:
    """Fast path for trimming WHOIS chatter and keeping the latest response only."""
    if not raw_text:
        return ""

    latest = _slice_latest_section(raw_text)
    lines = [line.strip() for line in latest.splitlines()]
    collapsed = _collapse_wrapped_fields(lines)
    collapsed_text = "\n".join(collapsed).strip()
    sliced = _slice_from_last_domain(collapsed_text)
    if not sliced.endswith("\n"):
        sliced = f"{sliced}\n"
    return run_text_normalizers(sliced, domain=domain, tld=tld)


_RegistryEntry = tuple[int, int, Normalizer]
_normalizer_registry: list[_RegistryEntry] = []
_insertion_counter = 0
_TextRegistryEntry = tuple[int, int, TextNormalizer]
_text_normalizer_registry: list[_TextRegistryEntry] = []
_text_insertion_counter = 0


def register_normalizer(normalizer: Normalizer, priority: int = 0) -> None:
    """Register a Normalizer that runs after Structly parses the payload."""
    if not isinstance(normalizer, Normalizer):
        raise TypeError("normalizer must implement the Normalizer protocol")
    global _insertion_counter
    entry = (priority, _insertion_counter, normalizer)
    _normalizer_registry.append(entry)
    _normalizer_registry.sort(key=lambda item: (-item[0], item[1]))
    _insertion_counter += 1


def clear_normalizers() -> None:
    """Remove all registered normalizers (used in tests)."""
    global _normalizer_registry, _insertion_counter
    _normalizer_registry = []
    _insertion_counter = 0


def register_text_normalizer(normalizer: TextNormalizer, priority: int = 0) -> None:
    """Register a raw-text normalizer that runs before Structly parses the payload."""
    if not isinstance(normalizer, TextNormalizer):
        raise TypeError("text normalizer must implement the TextNormalizer protocol")
    global _text_insertion_counter
    entry = (priority, _text_insertion_counter, normalizer)
    _text_normalizer_registry.append(entry)
    _text_normalizer_registry.sort(key=lambda item: (-item[0], item[1]))
    _text_insertion_counter += 1


def clear_text_normalizers() -> None:
    """Remove all registered text normalizers (used in tests)."""
    global _text_normalizer_registry, _text_insertion_counter
    _text_normalizer_registry = []
    _text_insertion_counter = 0


def run_normalizers(
    tld: str | None,
    domain: str | None,
    parsed: MutableMapping[str, Any],
    raw_text: str,
) -> MutableMapping[str, Any]:
    """Apply registered post-parse normalizers deterministically."""
    current: MutableMapping[str, Any] = parsed
    for _priority, _, normalizer in _normalizer_registry:
        if not normalizer.applicable(tld, domain, current):
            continue
        updated = normalizer.normalize(current, raw_text)
        if updated is current:
            continue
        current = updated if isinstance(updated, MutableMapping) else dict(updated)
    return current


def run_text_normalizers(raw_text: str, *, tld: str | None, domain: str | None) -> str:
    """Apply registered pre-parse text normalizers deterministically."""
    current = raw_text
    for _priority, _, normalizer in _text_normalizer_registry:
        if not normalizer.applicable(current, tld, domain):
            continue
        updated = normalizer.normalize(current, tld, domain)
        if not isinstance(updated, str):
            raise TypeError("text normalizer must return a string")
        current = updated
    return current


def _initialize_core_normalizers() -> None:
    for core in CORE_NORMALIZERS:
        register_normalizer(core)


def _initialize_core_text_normalizers() -> None:
    for core in CORE_TEXT_NORMALIZERS:
        register_text_normalizer(core)


_initialize_core_normalizers()
_initialize_core_text_normalizers()


__all__ = [
    "NormalizerPluginError",
    "normalize_raw_text",
    "register_normalizer",
    "clear_normalizers",
    "run_normalizers",
    "register_text_normalizer",
    "clear_text_normalizers",
    "run_text_normalizers",
]
