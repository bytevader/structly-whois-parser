# Changelog

All notable changes to this project will be documented here. This project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.0] - 2026-01-25

### Added

- **Schema contract documentation**: added `docs/schema.md` describing canonical `WhoisRecord` fields, type rules (including date policy), normalization behavior, and missing vs. redacted handling.
- **Schema introspection**:
  - `WhoisRecord.schema_version` to allow downstream compatibility checks.
  - `WhoisParser.field_catalog(surface=...)` to enumerate available fields for record/dict/both surfaces.
- **Supported TLD transparency**:
  - Added/generated `docs/supported-tlds.md` matrix and generator tooling.
  - CI checks to ensure the matrix stays up to date and that fixture-derived TLDs are represented in tiers mapping.

### Changed

- Improved `supported_tlds` reporting so it reflects **available configurations/overrides** (capability) rather than only currently-instantiated parsers, and filters empty labels.

### Notes

- The stability guarantees in `docs/schema.md` apply to the canonical `WhoisRecord` output surface (`parse_record`, `parse_many(..., to_records=True)`). Mapping output remains best-effort and may include registry-specific keys derived from Structly configurations.

## [1.0.1] - 2026-01-21

### Added

- Documented streaming considerations (`to_records=True` buffering) and performance hints for `domain`/`tld` hints in the README.
- GitHub Actions now publishes JUnit test reports and coverage summaries directly in the Checks UI, making CI results easier to audit.

### Changed

- `parse_many(..., to_records=True)` guidance now includes chunked-processing helpers to keep memory bounded.

### Fixed

- Rate-limit detection uses layered heuristics (exact match, line-level, substrings, regex) to catch more registry throttling responses without misclassifying real payloads.

### 1.0.0 baseline

### Added

- Structly-powered parser core with normalization, domain inference, record building, and the `WhoisParser` API (`src/structly_whois`).
- CLI entry point (`structly-whois`), optional date-parser hooks, and typed `WhoisRecord` structs built on msgspec.
- Extensive TLD overrides, WHOIS fixtures, and pytest suites (unit + integration) so every bundled registry is regression tested.
- Developer tooling: Ruff config, Makefile targets, GitHub Actions CI, benchmark harness/scripts, documentation site, and README walkthroughs.

### Packaging

- `pyproject.toml` metadata, SemVer policy, `py.typed`, and contribution guidelines to publish wheels/sdists to PyPI/TestPyPI.
