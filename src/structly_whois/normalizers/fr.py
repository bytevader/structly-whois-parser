from __future__ import annotations

from collections.abc import Mapping

from ._base import TextNormalizer

_AFNIC_MARKER = "this is the afnic whois server"


class AfnicTextNormalizer(TextNormalizer):
    """Append canonical contact labels for AFNIC payloads before parsing."""

    def applicable(self, raw_text: str, tld: str | None, domain: str | None) -> bool:
        if _has_fr_hint(tld, domain):
            return _is_afnic_payload(raw_text.splitlines())
        if tld or domain:
            return False
        return _is_afnic_payload(raw_text.splitlines())

    def normalize(self, raw_text: str, tld: str | None, domain: str | None) -> str:
        lines = raw_text.splitlines()
        handles = _extract_afnic_handles(lines)
        if not handles:
            return raw_text
        blocks = _extract_afnic_contact_blocks(lines)
        role_labels = {
            "holder": "Registrant",
            "admin": "Admin",
            "tech": "Tech",
        }
        extras: list[str] = []
        for role, label in role_labels.items():
            handle = handles.get(role)
            if not handle:
                continue
            attrs = blocks.get(handle)
            if not attrs:
                continue
            extras.extend(_build_afnic_contact_lines(label, attrs))
        if not extras:
            return raw_text
        extra_text = "\n".join(extras)
        suffix = "" if raw_text.endswith("\n") else "\n"
        return f"{raw_text}{suffix}\n{extra_text}\n"


def _is_afnic_payload(lines: list[str]) -> bool:
    """Detect AFNIC WHOIS payloads that need contact normalization."""
    marker_lower = _AFNIC_MARKER.lower()
    for line in lines:
        lower = line.lower()
        if marker_lower in lower:
            return True
        if lower.startswith("holder-c:"):
            return True
        if "frnic" in lower:
            return True
    return False


def _extract_afnic_handles(lines: list[str]) -> dict[str, str]:
    """Collect holder/admin/tech handles from the header section."""
    handles: dict[str, str] = {}
    for line in lines:
        lower = line.lower()
        if lower.startswith("holder-c:"):
            handles["holder"] = line.split(":", 1)[1].strip()
        elif lower.startswith("admin-c:"):
            handles["admin"] = line.split(":", 1)[1].strip()
        elif lower.startswith("tech-c:"):
            handles["tech"] = line.split(":", 1)[1].strip()
    return handles


def _extract_afnic_contact_blocks(lines: list[str]) -> dict[str, dict[str, str]]:
    """Parse nic-hdl sections into a mapping keyed by handle."""
    blocks: dict[str, dict[str, str]] = {}
    total = len(lines)
    idx = 0
    while idx < total:
        line = lines[idx]
        lower = line.lower()
        if not lower.startswith("nic-hdl:"):
            idx += 1
            continue
        handle = line.split(":", 1)[1].strip()
        idx += 1
        idx, attrs = _parse_afnic_block(lines, idx)
        blocks[handle] = attrs
    return blocks


def _parse_afnic_block(lines: list[str], start: int) -> tuple[int, dict[str, str]]:
    """Scan attribute lines until the next nic-hdl marker or EOF."""
    attrs: dict[str, str] = {}
    idx = start
    total = len(lines)
    while idx < total:
        current = lines[idx]
        current_lower = current.lower()
        if not current:
            idx += 1
            continue
        if current_lower.startswith("nic-hdl:"):
            break
        parts = current.split(":", 1)
        if len(parts) == 2:
            key = parts[0].strip().lower()
            value = parts[1].strip()
            attrs.setdefault(key, value)
        idx += 1
        if current_lower.startswith("source:"):
            break
    return idx, attrs


def _build_afnic_contact_lines(label: str, attrs: Mapping[str, str]) -> list[str]:
    """Produce canonical contact lines (Registrant/Admin/Tech) from a block."""
    lines: list[str] = []
    contact = attrs.get("contact")
    contact_type = (attrs.get("type") or "").lower()
    if contact:
        if contact_type == "organization":
            lines.append(f"{label} Organization: {contact}")
            lines.append(f"{label} Name: {contact}")
        else:
            lines.append(f"{label} Name: {contact}")
    email = attrs.get("e-mail")
    if email:
        lines.append(f"{label} Email: {email}")
    phone = attrs.get("phone")
    if phone:
        lines.append(f"{label} Phone: {phone}")
    return lines


def _build_afnic_contact_values(
    handles: Mapping[str, str],
    blocks: Mapping[str, Mapping[str, str]],
) -> dict[str, str]:
    """Produce canonical contact mappings (Registrant/Admin/Tech) from handle blocks."""
    updates: dict[str, str] = {}
    role_labels = {
        "holder": "registrant",
        "admin": "admin",
        "tech": "tech",
    }
    for role, prefix in role_labels.items():
        handle = handles.get(role)
        if not handle:
            continue
        attrs = blocks.get(handle)
        if not attrs:
            continue
        updates.update(_map_attrs_to_fields(prefix, attrs))
    return updates


def _map_attrs_to_fields(prefix: str, attrs: Mapping[str, str]) -> dict[str, str]:
    contact = attrs.get("contact")
    contact_type = (attrs.get("type") or "").lower()
    mapped: dict[str, str] = {}
    if contact:
        if contact_type == "organization":
            mapped[f"{prefix}_organization"] = contact
            mapped[f"{prefix}_name"] = contact
        else:
            mapped[f"{prefix}_name"] = contact
    email = attrs.get("e-mail")
    if email:
        mapped[f"{prefix}_email"] = email
    phone = attrs.get("phone")
    if phone:
        mapped[f"{prefix}_telephone"] = phone
    return mapped


FR_TEXT_NORMALIZER = AfnicTextNormalizer()


def _has_fr_hint(tld: str | None, domain: str | None) -> bool:
    normalized_tld = (tld or "").strip().lower()
    if normalized_tld:
        return normalized_tld == "fr"
    if domain:
        labels = [part for part in domain.strip().lower().split(".") if part]
        if labels:
            return labels[-1] == "fr"
    return False


__all__ = [
    "AfnicTextNormalizer",
    "FR_TEXT_NORMALIZER",
    "_build_afnic_contact_lines",
    "_build_afnic_contact_values",
    "_extract_afnic_contact_blocks",
    "_extract_afnic_handles",
]
