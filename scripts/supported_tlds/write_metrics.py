#!/usr/bin/env python3
"""Convert the supported TLD report into GitLab-friendly metrics."""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
REPORT_PATH = SCRIPT_DIR / "supported-tlds.report.json"
METRICS_PATH = SCRIPT_DIR / "supported-tlds.metrics.json"


def main() -> int:
    if not REPORT_PATH.exists():
        raise SystemExit(
            f"Report not found at {REPORT_PATH}. Run the generator with --report first."
        )
    data = json.loads(REPORT_PATH.read_text(encoding="utf-8"))
    tlds = data.get("tlds", {})
    counter = Counter()
    promotions = 0
    for entry in tlds.values():
        tier_current = str(entry.get("tier_current", "unknown"))
        recommended = str(entry.get("recommended_tier", tier_current))
        counter[tier_current] += 1
        if recommended != tier_current:
            promotions += 1
    metrics = {
        "metrics": [
            {"name": "supported_tlds_total", "value": len(tlds), "unit": "tlds"},
        ]
    }
    for tier in sorted(counter):
        metrics["metrics"].append(
            {
                "name": f"supported_tlds_{tier.lower()}",
                "value": counter[tier],
                "unit": "tlds",
            }
        )
    metrics["metrics"].append(
        {
            "name": "supported_tlds_recommendations",
            "value": promotions,
            "unit": "tlds",
        }
    )
    METRICS_PATH.write_text(json.dumps(metrics, indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
