from __future__ import annotations

from collections.abc import Iterable, Mapping, MutableMapping
from types import MappingProxyType

from structly import FieldPattern, FieldSpec, Mode, ReturnShape, StructlyConfig

from .fields import BASE_FIELD_DEFINITIONS, FieldDefinition, FieldOverride
from .tlds import TLD_OVERRIDES


def _normalize_tld(value: str | None) -> str:
    if not value:
        return ""
    return value.strip().lstrip(".").lower()


def _clone_field_definition(defn: FieldDefinition) -> FieldDefinition:
    cloned = dict(defn)
    if "patterns" in cloned:
        cloned["patterns"] = list(cloned["patterns"])
    return cloned


def _clone_field_override(override: FieldOverride) -> FieldOverride:
    cloned = dict(override)
    for key in ("patterns", "extend_patterns", "prepend_patterns"):
        if key in cloned:
            cloned[key] = list(cloned[key])
    return cloned


class StructlyConfigFactory:
    """Build StructlyConfig objects with customizable base fields and TLD overrides."""

    def __init__(
        self,
        *,
        base_field_definitions: Mapping[str, FieldDefinition] | None = None,
        tld_overrides: Mapping[str, dict[str, FieldOverride]] | None = None,
    ) -> None:
        self._base_fields: dict[str, FieldDefinition] = {
            name: _clone_field_definition(defn)
            for name, defn in (base_field_definitions or BASE_FIELD_DEFINITIONS).items()
        }
        self._tld_overrides: dict[str, dict[str, FieldOverride]] = {
            _normalize_tld(tld): {field: _clone_field_override(override) for field, override in overrides.items()}
            for tld, overrides in (tld_overrides or TLD_OVERRIDES).items()
        }

    @property
    def base_fields(self) -> Mapping[str, FieldDefinition]:
        return MappingProxyType(self._base_fields)

    @property
    def tld_overrides(self) -> Mapping[str, dict[str, FieldOverride]]:
        return MappingProxyType(self._tld_overrides)

    @property
    def known_tlds(self) -> tuple[str, ...]:
        return tuple(sorted(self._tld_overrides.keys()))

    def get_base_field(self, name: str) -> FieldDefinition:
        if name not in self._base_fields:
            raise KeyError(f"Unknown base field '{name}'")
        return _clone_field_definition(self._base_fields[name])

    def register_base_field(self, name: str, definition: FieldDefinition) -> None:
        self._base_fields[name] = _clone_field_definition(definition)

    def extend_base_field(self, name: str, *, extend_patterns: Iterable[FieldPattern]) -> None:
        if name not in self._base_fields:
            raise KeyError(f"Unknown base field '{name}'")
        existing = list(self._base_fields[name].get("patterns", []))
        existing.extend(list(extend_patterns))
        self._base_fields[name]["patterns"] = existing

    def register_tld(
        self,
        tld: str,
        overrides: Mapping[str, FieldOverride],
        *,
        replace: bool = False,
    ) -> None:
        normalized = _normalize_tld(tld)
        if not normalized:
            raise ValueError("TLD label cannot be empty")
        sanitized = {name: _clone_field_override(override) for name, override in overrides.items()}
        if replace or normalized not in self._tld_overrides:
            self._tld_overrides[normalized] = sanitized
        else:
            target = self._tld_overrides.setdefault(normalized, {})
            target.update(sanitized)

    def build(self, tld: str | None = None) -> StructlyConfig:
        normalized = _normalize_tld(tld)
        override_map = self._tld_overrides.get(normalized, {})
        fields: MutableMapping[str, FieldSpec] = {}
        for name, defn in self._base_fields.items():
            field_override = override_map.get(name)
            fields[name] = _build_field_spec(defn, field_override)
        return StructlyConfig(fields=dict(fields))


DEFAULT_CONFIG_FACTORY = StructlyConfigFactory()
DEFAULT_TLDS = tuple(sorted(DEFAULT_CONFIG_FACTORY.known_tlds))


def _build_field_spec(defn: FieldDefinition, override: FieldOverride | None = None) -> FieldSpec:
    patterns = list(defn["patterns"])
    mode = defn.get("mode", Mode.first)
    unique = defn.get("unique", False)
    return_shape = defn.get("return_shape", ReturnShape.scalar)

    if override:
        if "patterns" in override:
            patterns = list(override["patterns"])
        elif "prepend_patterns" in override:
            patterns = list(override["prepend_patterns"]) + patterns
        if "extend_patterns" in override:
            patterns.extend(list(override["extend_patterns"]))
        mode = override.get("mode", mode)
        unique = override.get("unique", unique)
        return_shape = override.get("return_shape", return_shape)

    return FieldSpec(
        patterns=patterns,
        mode=mode,
        unique=unique,
        return_shape=return_shape,
    )


def build_structly_config_for_tld(
    tld: str | None = None,
    *,
    factory: StructlyConfigFactory | None = None,
) -> StructlyConfig:
    target_factory = factory or DEFAULT_CONFIG_FACTORY
    return target_factory.build(tld)
