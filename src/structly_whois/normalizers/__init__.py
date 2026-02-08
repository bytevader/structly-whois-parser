from __future__ import annotations

from ._base import Normalizer, TextNormalizer
from .fr import FR_TEXT_NORMALIZER

CORE_NORMALIZERS: list[Normalizer] = []
CORE_TEXT_NORMALIZERS: list[TextNormalizer] = [FR_TEXT_NORMALIZER]

__all__ = ["CORE_NORMALIZERS", "CORE_TEXT_NORMALIZERS", "Normalizer", "TextNormalizer"]
