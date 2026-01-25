# Supported TLD automation

`python scripts/supported_tlds/generate_supported_tlds.py` keeps the Supported TLD matrix (`docs/supported-tlds.md`) in sync with the fixtures under `tests/samples/whois/` and the tier mapping stored in `scripts/supported_tlds/supported-tlds.tiers.json`. The script is stdlib-only and runs on every PR via CI.

## Core workflow

| Goal | Command |
| --- | --- |
| Regenerate `docs/supported-tlds.md` from fixtures + tiers | `python scripts/supported_tlds/generate_supported_tlds.py` |
| Verify the markdown is up to date (same check CI runs) | `python scripts/supported_tlds/generate_supported_tlds.py --check` |
| Ensure every fixture-derived TLD exists in `scripts/supported_tlds/supported-tlds.tiers.json` and carries a valid tier | `python scripts/supported_tlds/generate_supported_tlds.py --validate` |

`--check` and `--validate` are executed automatically in `.github/workflows/ci.yml`; run them locally if you touch fixtures or tier metadata so CI stays green.

## Advanced / local-only helpers

The generator also exposes convenience flags for contributors who want deeper insight into tier coverage, promotions, or custom reports. These **are not** executed in CI and only run when you invoke them explicitly:

- `--report`: Parse every WHOIS fixture with `WhoisParser`, compute coverage metrics using the policy thresholds, and write `scripts/supported_tlds/supported-tlds.report.json`. The report is `.gitignore`d so it never lands in commits unless you add it manually.
- `--suggest-tiers`: Implies `--report`; prints promotion suggestions (exit code 2 when promotions are recommended). Use `--allow-demote` to view potential demotions.
- `--apply-suggested-tiers`: Implies `--report`; rewrites `scripts/supported_tlds/supported-tlds.tiers.json` based on recommendations. The default `--only-promote` guard prevents automatic demotions unless you explicitly pass `--allow-demote`.

After applying promotions locally, rerun the generator without flags so `docs/supported-tlds.md` reflects the updated tiers, then include both files in your PR.

### Tier metadata

- `scripts/supported_tlds/supported-tlds.tiers.json` is the canonical `<tld> -> tier` mapping. All doc generation and validation flows reference this file.
- `scripts/supported_tlds/supported-tlds.policy.json` describes tier ordering, core-field aliases, and the numeric thresholds used when you run `--report`/`--suggest-tiers`. Adjust it if you want stricter or more lenient promotion criteria before generating a report locally.
