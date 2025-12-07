from __future__ import annotations

from collections.abc import Iterable, Mapping

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
    lowered = text.lower()
    token = "domain name:"
    idx = lowered.rfind(token)
    if idx == -1:
        return text
    start = text.rfind("\n", 0, idx)
    if start == -1:
        return text[idx:]
    return text[start + 1 :]


def normalize_raw_text(raw_text: str) -> str:
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
    return _inject_afnic_contacts(sliced)


def _is_afnic_payload(lines: list[str]) -> bool:
    """Detect AFNIC WHOIS payloads that need contact normalization."""
    marker = "this is the afnic whois server"
    return any(marker in line.lower() for line in lines)


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
    idx = 0
    total = len(lines)
    while idx < total:
        line = lines[idx]
        lower = line.lower()
        if lower.startswith("nic-hdl:"):
            handle = line.split(":", 1)[1].strip()
            idx += 1
            attrs: dict[str, str] = {}
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
                if current_lower.startswith("source:"):
                    idx += 1
                    break
                idx += 1
            blocks[handle] = attrs
            continue
        idx += 1
    return blocks


def _build_afnic_contact_lines(label: str, attrs: Mapping[str, str]) -> list[str]:
    """Produce canonical contact lines (Registrant/Admin/Tech) from a block."""
    lines: list[str] = []
    contact = attrs.get("contact")
    contact_type = (attrs.get("type") or "").lower()
    if contact:
        if contact_type == "organization":
            lines.append(f"{label} Organization: {contact}")
            lines.append(f"{label} Name: {contact}")
        elif contact_type == "person":
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


def _inject_afnic_contacts(text: str) -> str:
    """Append canonical contact labels for AFNIC payloads."""
    lines = text.splitlines()
    if not _is_afnic_payload(lines):
        return text
    handles = _extract_afnic_handles(lines)
    if not handles:
        return text
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
        return text
    extra_text = "\n".join(extras)
    return f"{text}\n{extra_text}\n"
