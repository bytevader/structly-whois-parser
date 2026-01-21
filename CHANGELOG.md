# Changelog

All notable changes to this project will be documented here. This project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-01-21

### Added

- Structly-powered parser core with normalization, domain inference, record building, and the `WhoisParser` API (`src/structly_whois`).
- CLI entry point (`structly-whois`), optional date-parser hooks, and typed `WhoisRecord` structs built on msgspec.
- Extensive TLD overrides, WHOIS fixtures, and pytest suites (unit + integration) so every bundled registry is regression tested.
- Developer tooling: Ruff config, Makefile targets, GitHub Actions CI, benchmark harness/scripts, documentation site, and README walkthroughs.

### Packaging

- `pyproject.toml` metadata, SemVer policy, `py.typed`, and contribution guidelines to publish wheels/sdists to PyPI/TestPyPI.
