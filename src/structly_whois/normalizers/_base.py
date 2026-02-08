from __future__ import annotations

from collections.abc import Mapping
from typing import Any, Protocol, runtime_checkable


@runtime_checkable
class Normalizer(Protocol):
    """Runs *after* Structly parses the WHOIS payload (operates on parsed mappings)."""

    def applicable(self, tld: str | None, domain: str | None, parsed: Mapping[str, Any]) -> bool:
        """Return True when this normalizer should run for the given payload."""

    def normalize(self, parsed: Mapping[str, Any], raw_text: str) -> Mapping[str, Any]:
        """Return a possibly mutated mapping after applying TLD-specific fixes."""


@runtime_checkable
class TextNormalizer(Protocol):
    """Runs *before* Structly parses the WHOIS payload (operates on raw text)."""

    def applicable(self, raw_text: str, tld: str | None, domain: str | None) -> bool:
        """Return True when this normalizer should run for the given payload."""

    def normalize(self, raw_text: str, tld: str | None, domain: str | None) -> str:
        """Return the normalized text (can be the same object)."""


__all__ = ["Normalizer", "TextNormalizer"]
