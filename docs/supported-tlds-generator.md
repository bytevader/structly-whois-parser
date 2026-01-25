# Supported TLD automation

`python scripts/supported_tlds/generate_supported_tlds.py` is the single entry point for keeping the Supported TLD matrix, tiers, and policy-driven report in sync. The script only uses the Python standard library and can run from a clean checkout once dependencies are installed (`pip install -e .` if you need parser-backed metrics).

## Common tasks

| Goal | Command |
| --- | --- |
| Regenerate `docs/supported-tlds.md` from fixtures + tiers | `python scripts/supported_tlds/generate_supported_tlds.py` |
| Verify the markdown is up to date (CI uses this) | `python scripts/supported_tlds/generate_supported_tlds.py --check` |
| Ensure every fixture-derived TLD exists in `scripts/supported_tlds/supported-tlds.tiers.json` and the tiers match the policy | `python scripts/supported_tlds/generate_supported_tlds.py --validate` |
| Produce the evidence report at `scripts/supported_tlds/supported-tlds.report.json` | `python scripts/supported_tlds/generate_supported_tlds.py --report` |
| Print promotion suggestions without changing files (exit code 2 when promotions are available) | `python scripts/supported_tlds/generate_supported_tlds.py --suggest-tiers` |
| Apply recommended promotions to `scripts/supported_tlds/supported-tlds.tiers.json` (promotion-only) | `python scripts/supported_tlds/generate_supported_tlds.py --apply-suggested-tiers --only-promote` |

After applying promotions, rerun the generator without flags so `docs/supported-tlds.md` reflects the new tiers.

## CLI flags

- `--check`: Compare freshly generated markdown to the file on disk and exit 1 if they differ.
- `--validate`: Fail fast when a fixture’s TLD is missing from `scripts/supported_tlds/supported-tlds.tiers.json` or has a tier not listed in `scripts/supported_tlds/supported-tlds.policy.json`’s `tier_order`.
- `--report`: Parse every WHOIS fixture with `WhoisParser`, compute coverage metrics using the policy thresholds, and write `scripts/supported_tlds/supported-tlds.report.json`. Useful before making manual tier decisions.
- `--suggest-tiers`: Implies `--report`; prints deterministic promotion suggestions and exits with code 2 if at least one TLD should be promoted under the policy. Use `--allow-demote` if you explicitly want to see demotion recommendations.
- `--apply-suggested-tiers`: Implies `--report`; rewrites `scripts/supported_tlds/supported-tlds.tiers.json` based on the recommendations. By default only promotions are applied (`--only-promote`). Add `--allow-demote` to permit demotions (rare).

### Policy knobs

`scripts/supported_tlds/supported-tlds.policy.json` describes:

- `tier_order`: Ranking used by the validator and promotion logic.
- `core_fields`: Aliases grouped under semantic fields when measuring record quality.
- `thresholds`: Numeric cutoffs for Silver/Gold (fixtures required, parse success rate, core field score, golden coverage). Adjust these before running `--suggest-tiers`/`--apply-suggested-tiers` if you want stricter or more lenient promotions.

### Tiers source of truth

`scripts/supported_tlds/supported-tlds.tiers.json` remains the canonical mapping of `<tld> -> <tier>`. All doc generation and policy checks reference this file, so updates should always go through the generator script (either manual edits followed by `--check`/`--validate` or via `--apply-suggested-tiers`).
