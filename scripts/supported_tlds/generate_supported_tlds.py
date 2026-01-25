#!/usr/bin/env python3
"""Generate supported TLD docs plus policy-driven coverage reports and suggestions."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Mapping, MutableMapping, Sequence, Tuple

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT_DIR = Path(__file__).resolve().parent
FIXTURES_DIR = REPO_ROOT / "tests" / "samples" / "whois"
DOC_PATH = REPO_ROOT / "docs" / "supported-tlds.md"
TIERS_PATH = SCRIPT_DIR / "supported-tlds.tiers.json"
POLICY_PATH = SCRIPT_DIR / "supported-tlds.policy.json"
REPORT_PATH = SCRIPT_DIR / "supported-tlds.report.json"
GOLDEN_ROOT = REPO_ROOT / "tests" / "golden" / "whois"

if str(REPO_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "src"))

WHOIS_DOMAIN_PATTERNS = [
    re.compile(r"^\s*Domain Name:\s*(\S+)", re.IGNORECASE | re.MULTILINE),
    re.compile(r"^\s*domain:\s*(\S+)", re.IGNORECASE | re.MULTILINE),
    re.compile(r"^\s*Domain:\s*(\S+)", re.IGNORECASE | re.MULTILINE),
]

THRESHOLD_SPECS = {
    "min_fixtures": ("fixture_count", ">="),
    "min_parse_success_rate": ("parse_success_rate", ">="),
    "min_core_field_score": ("core_field_score", ">="),
    "min_golden_coverage": ("golden_coverage", ">="),
}


@dataclass
class TierIssues:
    missing: List[str]
    invalid_values: Dict[str, str]
    extras: List[str]

    @property
    def has_errors(self) -> bool:
        return bool(self.missing or self.invalid_values)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Generate docs/supported-tlds.md and policy-driven tier reports."
    )
    parser.add_argument(
        "--check", action="store_true", help="Check docs/supported-tlds.md is current"
    )
    parser.add_argument(
        "--validate",
        action="store_true",
        help="Validate tiers coverage and allowed values",
    )
    parser.add_argument(
        "--report",
        action="store_true",
        help="Write scripts/supported_tlds/supported-tlds.report.json with coverage metrics",
    )
    parser.add_argument(
        "--suggest-tiers",
        action="store_true",
        help="Print promotion suggestions based on the current policy",
    )
    parser.add_argument(
        "--apply-suggested-tiers",
        action="store_true",
        help="Update scripts/supported_tlds/supported-tlds.tiers.json using recommended tiers",
    )
    parser.add_argument(
        "--only-promote",
        dest="only_promote",
        action="store_true",
        default=True,
        help="Restrict tier changes to promotions (default behavior)",
    )
    parser.add_argument(
        "--allow-demote",
        dest="only_promote",
        action="store_false",
        help="Allow automatic demotions when applying suggested tiers",
    )
    args = parser.parse_args(argv)

    policy = load_policy(POLICY_PATH)
    valid_tiers = set(policy["tier_order"])
    fixtures = discover_fixtures(FIXTURES_DIR)
    tiers = load_tiers(TIERS_PATH)
    issues = analyze_tiers(fixtures, tiers, valid_tiers)

    if args.validate:
        exit_code = report_validation(issues)
        if exit_code:
            return exit_code
    elif issues.has_errors:
        return report_validation(issues)

    report_data = None
    if args.report or args.suggest_tiers or args.apply_suggested_tiers:
        report_data = build_report(fixtures, tiers, policy)
        write_json(REPORT_PATH, report_data)

    if args.suggest_tiers:
        suggestions = collect_suggestions(
            report_data, policy, only_promote=args.only_promote
        )
        if suggestions:
            heading = (
                "Proposed tier promotions (promotion-only):"
                if args.only_promote
                else "Proposed tier changes:"
            )
            print(heading)
            for tld, current, recommended, reasons in suggestions:
                reason_text = "; ".join(reasons) if reasons else "no reasons recorded"
                print(f"  - {tld}: {current} -> {recommended} ({reason_text})")
            return 2
        print("No tier promotions proposed.")
        return 0

    if args.apply_suggested_tiers:
        suggestions = collect_suggestions(
            report_data, policy, only_promote=args.only_promote
        )
        if suggestions:
            tiers = apply_suggestions(suggestions, tiers)
            write_tiers(tiers)
        return 0

    doc_needed = not (args.report or args.suggest_tiers or args.apply_suggested_tiers)
    if doc_needed or args.check:
        document = render_document(fixtures, tiers)
    else:
        document = None

    if args.check:
        return check_docs(document or "")

    if not doc_needed:
        return 0

    write_doc(document or "")
    return 0


def load_policy(path: Path) -> dict:
    if not path.exists():
        raise SystemExit(f"Tier policy missing: {path}")
    with path.open(encoding="utf-8") as handle:
        data = json.load(handle)
    required = {"tier_order", "core_fields", "thresholds"}
    missing = required - set(data)
    if missing:
        raise SystemExit(
            f"Tier policy missing keys: {', '.join(sorted(missing))}"
        )
    return data


def write_json(path: Path, payload: Mapping[str, object]) -> None:
    path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def write_tiers(tiers: Mapping[str, str]) -> None:
    ordered = {key: tiers[key] for key in sorted(tiers)}
    write_json(TIERS_PATH, ordered)


def write_doc(text: str) -> None:
    DOC_PATH.write_text(text, encoding="utf-8")


def check_docs(generated: str) -> int:
    existing = DOC_PATH.read_text(encoding="utf-8") if DOC_PATH.exists() else ""
    if generated != existing:
        print(
            "docs/supported-tlds.md is out of date. Run python scripts/supported_tlds/generate_supported_tlds.py to regenerate it.",
            file=sys.stderr,
        )
        return 1
    return 0


def discover_fixtures(fixtures_dir: Path) -> Dict[str, List[Path]]:
    if not fixtures_dir.exists():
        raise SystemExit(f"Fixture directory not found: {fixtures_dir}")

    grouped: Dict[str, List[Path]] = {}
    for path in sorted(p for p in fixtures_dir.rglob("*") if p.is_file()):
        tld = infer_tld(path)
        grouped.setdefault(tld, []).append(path)
    for paths in grouped.values():
        paths.sort()
    return grouped


def load_tiers(tiers_path: Path) -> Dict[str, str]:
    if not tiers_path.exists():
        raise SystemExit(f"Tiers mapping missing: {tiers_path}")
    with tiers_path.open(encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, dict):
        raise SystemExit("Tier mapping must be a JSON object.")
    normalized = {str(key).lower(): str(value) for key, value in data.items()}
    return normalized


def analyze_tiers(
    fixtures: Dict[str, List[Path]],
    tiers: Dict[str, str],
    valid_tiers: set[str],
) -> TierIssues:
    fixture_tlds = sorted(fixtures.keys())
    missing = [tld for tld in fixture_tlds if tld not in tiers]
    invalid_values = {tld: tier for tld, tier in tiers.items() if tier not in valid_tiers}
    extras = sorted(set(tiers.keys()) - set(fixture_tlds))
    return TierIssues(missing=missing, invalid_values=invalid_values, extras=extras)


def report_validation(issues: TierIssues) -> int:
    exit_code = 0
    if issues.missing:
        exit_code = 1
        missing = ", ".join(issues.missing)
        print(f"Missing tier entries for: {missing}", file=sys.stderr)
    if issues.invalid_values:
        exit_code = 1
        invalid = ", ".join(
            f"{tld}={tier}" for tld, tier in sorted(issues.invalid_values.items())
        )
        print(
            "Invalid tier values (expected policy tier_order entries): " f"{invalid}",
            file=sys.stderr,
        )
    if issues.extras:
        extras = ", ".join(issues.extras)
        print(
            f"Warning: tiers file lists TLDs without fixtures: {extras}",
            file=sys.stderr,
        )
    return exit_code


def infer_tld(path: Path) -> str:
    name = path.name
    domain_candidate = strip_extension(name)
    if looks_like_domain(domain_candidate):
        return extract_tld(domain_candidate)
    domain_from_file = extract_domain_from_file(path)
    if domain_from_file:
        return extract_tld(domain_from_file)
    return "unknown"


def strip_extension(filename: str) -> str:
    parts = filename.split(".")
    return ".".join(parts[:-1]) if len(parts) > 1 else filename


def looks_like_domain(candidate: str) -> bool:
    return "." in candidate and " " not in candidate


def extract_tld(domain: str) -> str:
    cleaned = domain.strip().lower().rstrip(".")
    if "." not in cleaned:
        return "unknown"
    return cleaned.split(".", 1)[1]


def extract_domain_from_text(text: str) -> str | None:
    for pattern in WHOIS_DOMAIN_PATTERNS:
        match = pattern.search(text)
        if match:
            candidate = match.group(1).strip()
            if looks_like_domain(candidate):
                return candidate
    return None


def extract_domain_from_file(path: Path) -> str | None:
    text = read_fixture_text(path)
    return extract_domain_from_text(text)


def read_fixture_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return path.read_text(encoding="latin-1", errors="ignore")


def render_document(fixtures: Dict[str, List[Path]], tiers: Dict[str, str]) -> str:
    lines: List[str] = []
    lines.append("# Supported TLDs")
    lines.append("")
    lines.append(
        "_This document is generated by `python scripts/supported_tlds/generate_supported_tlds.py`. "
        "Do not edit manually._"
    )
    lines.append("")
    lines.append("We classify TLD parsing confidence into three tiers:")
    lines.append("")
    lines.append("- **Gold** – High confidence parsing powered by robust fixtures.")
    lines.append("- **Silver** – Reasonable coverage with minor edge cases pending.")
    lines.append("- **Experimental** – Early support that may change without notice.")
    lines.append("")
    lines.append("| TLD | Tier | Fixtures |")
    lines.append("| --- | --- | --- |")
    for tld in sorted(fixtures.keys()):
        tier = tiers.get(tld)
        if tier is None:
            raise SystemExit(
                f"No tier configured for TLD '{tld}'. Update scripts/supported_tlds/supported-tlds.tiers.json."
            )
        fixtures_cell = format_fixture_links(fixtures[tld])
        lines.append(f"| {tld} | {tier} | {fixtures_cell} |")
    lines.append("")
    return "\n".join(lines)


def format_fixture_links(paths: Iterable[Path]) -> str:
    links: List[str] = []
    for path in paths:
        rel = path.relative_to(REPO_ROOT).as_posix()
        target = (Path("..") / rel).as_posix()
        links.append(f"[{rel}]({target})")
    return "<br>".join(links)


def build_report(
    fixtures: Dict[str, List[Path]],
    tiers: Dict[str, str],
    policy: Mapping[str, object],
) -> Dict[str, object]:
    parser = create_whois_parser()
    tier_order = policy["tier_order"]
    core_fields: Mapping[str, List[str]] = policy["core_fields"]
    tld_entries: Dict[str, Dict[str, object]] = {}
    domain_aliases = core_fields.get("domain", ["domain", "domain_name"])

    for tld in sorted(fixtures.keys()):
        paths = fixtures[tld]
        tier_current = tiers.get(tld)
        if tier_current is None:
            raise SystemExit(
                f"No tier configured for TLD '{tld}'. Update scripts/supported_tlds/supported-tlds.tiers.json."
            )
        entry = evaluate_tld_metrics(
            parser,
            tld,
            paths,
            tier_current,
            core_fields,
            domain_aliases,
            policy,
        )
        tld_entries[tld] = entry

    now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
    return {
        "generated_at": now.isoformat().replace("+00:00", "Z"),
        "fixture_root": FIXTURES_DIR.relative_to(REPO_ROOT).as_posix(),
        "policy_path": POLICY_PATH.relative_to(REPO_ROOT).as_posix(),
        "tlds": tld_entries,
    }


def create_whois_parser() -> object:
    try:
        from structly_whois import WhoisParser  # noqa: WPS433 (import within function)
    except ImportError as exc:  # pragma: no cover - import guard
        raise SystemExit(
            "structly_whois import failed. Install the project (pip install -e .) "
            "before using reporting or tier automation flags."
        ) from exc
    return WhoisParser()


def evaluate_tld_metrics(
    parser: object,
    tld: str,
    paths: List[Path],
    tier_current: str,
    core_fields: Mapping[str, List[str]],
    domain_aliases: List[str],
    policy: Mapping[str, object],
) -> Dict[str, object]:
    fixture_paths = [path.relative_to(REPO_ROOT).as_posix() for path in sorted(paths)]
    fixture_count = len(paths)
    parse_success_count = 0
    golden_count = 0
    core_hits: Dict[str, int] = {field: 0 for field in core_fields}

    for path in sorted(paths):
        text = read_fixture_text(path)
        domain_hint = infer_domain_from_path_and_text(path, text)
        tld_hint = tld if tld != "unknown" else None
        parsed: MutableMapping[str, object] | None = None
        try:
            parsed = parser.parse(text, domain=domain_hint, tld=tld_hint)
        except Exception:
            parsed = None
        success = is_parse_success(parsed, domain_aliases)
        if success:
            parse_success_count += 1
        for field, aliases in core_fields.items():
            if success and parsed is not None and has_core_field(parsed, aliases):
                core_hits[field] += 1
        golden_path = golden_path_for_fixture(path)
        if golden_path.exists():
            golden_count += 1

    metrics = assemble_metrics(
        fixture_count,
        parse_success_count,
        golden_count,
        core_hits,
        core_fields,
    )
    recommended, reasons = recommend_tier(metrics, policy)
    entry = {
        "tier_current": tier_current,
        "fixture_count": fixture_count,
        "fixture_paths": fixture_paths,
        "golden_count": golden_count,
        "golden_coverage": metrics["golden_coverage"],
        "parse_success_count": parse_success_count,
        "parse_success_rate": metrics["parse_success_rate"],
        "core_field_presence": metrics["core_field_presence"],
        "core_field_score": metrics["core_field_score"],
        "recommended_tier": recommended,
        "recommendation_reasons": reasons,
    }
    return entry


def infer_domain_from_path_and_text(path: Path, text: str) -> str | None:
    candidate = strip_extension(path.name)
    if looks_like_domain(candidate):
        return candidate
    return extract_domain_from_text(text)


def golden_path_for_fixture(path: Path) -> Path:
    relative = path.relative_to(FIXTURES_DIR)
    return (GOLDEN_ROOT / relative).with_suffix(".json")


def is_parse_success(parsed: MutableMapping[str, object] | None, aliases: List[str]) -> bool:
    if parsed is None or not isinstance(parsed, MutableMapping):
        return False
    if bool(parsed):
        return True
    for alias in aliases:
        value = parsed.get(alias)
        if isinstance(value, str) and value.strip():
            return True
    return False


def has_core_field(parsed: MutableMapping[str, object], aliases: Iterable[str]) -> bool:
    for alias in aliases:
        value = parsed.get(alias)
        if is_non_empty_value(value):
            return True
    return False


def is_non_empty_value(value: object) -> bool:
    if value is None:
        return False
    if isinstance(value, str):
        return bool(value.strip())
    if isinstance(value, (list, tuple, set)):
        return bool(value)
    return bool(value)


def assemble_metrics(
    fixture_count: int,
    parse_success_count: int,
    golden_count: int,
    core_hits: Mapping[str, int],
    core_fields: Mapping[str, List[str]],
) -> Dict[str, object]:
    denominator = fixture_count or 1
    parse_success_rate = round(parse_success_count / denominator, 4)
    golden_coverage = round(golden_count / denominator, 4)
    presence: Dict[str, float] = {}
    for field in sorted(core_fields.keys()):
        presence[field] = round(core_hits[field] / denominator, 4)
    if presence:
        core_field_score = round(sum(presence.values()) / len(presence), 4)
    else:
        core_field_score = 0.0
    return {
        "fixture_count": fixture_count,
        "parse_success_rate": parse_success_rate,
        "golden_coverage": golden_coverage,
        "core_field_presence": presence,
        "core_field_score": core_field_score,
    }


def recommend_tier(
    metrics: Mapping[str, object],
    policy: Mapping[str, object],
) -> Tuple[str, List[str]]:
    tier_order: List[str] = policy["tier_order"]
    base_tier = tier_order[0]
    thresholds: Mapping[str, Mapping[str, float]] = policy["thresholds"]
    reasons: List[str] = []

    for tier in reversed(tier_order[1:]):
        tier_thresholds = thresholds.get(tier)
        if not tier_thresholds:
            continue
        meets, failures = evaluate_thresholds(tier, tier_thresholds, metrics)
        if meets:
            reasons.append(f"{tier} requirements satisfied.")
            reasons.extend(failures)
            return tier, reasons
        reasons.extend(failures)

    reasons.append(f"Defaulting to {base_tier} due to unmet higher-tier thresholds.")
    return base_tier, reasons


def evaluate_thresholds(
    tier: str,
    tier_thresholds: Mapping[str, float],
    metrics: Mapping[str, object],
) -> Tuple[bool, List[str]]:
    failures: List[str] = []
    meets = True
    for name, required in sorted(tier_thresholds.items()):
        metric_spec = THRESHOLD_SPECS.get(name)
        if not metric_spec:
            continue
        metric_name, comparator = metric_spec
        actual = metrics.get(metric_name)
        if actual is None:
            meets = False
            failures.append(
                f"{tier} threshold {name} missing metric '{metric_name}'."
            )
            continue
        passes = actual >= required if comparator == ">=" else actual <= required
        if not passes:
            meets = False
            failures.append(
                f"{tier} blocked: {metric_name} {format_metric(actual)} < {format_metric(required)}"
            )
        else:
            failures.append(
                f"{tier} metric met: {metric_name} {format_metric(actual)} >= {format_metric(required)}"
            )
    return meets, failures


def format_metric(value: object) -> str:
    if isinstance(value, float):
        return f"{value:.4f}"
    return str(value)


def collect_suggestions(
    report_data: Mapping[str, object] | None,
    policy: Mapping[str, object],
    *,
    only_promote: bool,
) -> List[Tuple[str, str, str, List[str]]]:
    if report_data is None:
        return []
    tier_order: List[str] = policy["tier_order"]
    ranks = {tier: idx for idx, tier in enumerate(tier_order)}
    suggestions: List[Tuple[str, str, str, List[str]]] = []
    tlds: Mapping[str, object] = report_data.get("tlds", {})
    for tld in sorted(tlds.keys()):
        data = tlds[tld]
        current = data.get("tier_current")
        recommended = data.get("recommended_tier")
        if not current or not recommended or current == recommended:
            continue
        if only_promote and ranks.get(recommended, -1) <= ranks.get(current, -1):
            continue
        reasons = data.get("recommendation_reasons") or []
        suggestions.append((tld, current, recommended, list(reasons)))
    return suggestions


def apply_suggestions(
    suggestions: List[Tuple[str, str, str, List[str]]],
    tiers: Dict[str, str],
) -> Dict[str, str]:
    updated = dict(tiers)
    for tld, _current, recommended, _reasons in suggestions:
        updated[tld] = recommended
    return updated


if __name__ == "__main__":
    raise SystemExit(main())
