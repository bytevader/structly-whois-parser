# Changelog

All notable changes to this project will be documented here. This project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.4] - 2025-12-10

### Added

- Ship `tests/report_coverage.py` so maintainers can generate the per-TLD field coverage numbers that back `coverage_report.txt`, making it easier to decide which registries deserve new fixtures next.
- Expand the WHOIS fixture corpus (Belgium, EU, Sweden, Ukraine, etc.) and expected outputs so regressions in tricky registries are caught by CI instead of surfacing in production.

### Changed

- Domain inference now refreshes itself from every `domain_name` pattern defined in the Structly base fields and overrides, so newly registered TLD configs immediately influence CLI/domain auto-detection without extra plumbing.

### Fixed

- Harden the `.be` override to drop stray single-token statuses (no more `["NOT", "NOT AVAILABLE"]`) and capture registrar/registrant metadata that DNS Belgium hides behind multi-line blocks.

## [0.2.0] - 2024-06-01

- Rename the package from `structly_whois_parser` to `structly_whois` (distribution: `structly-whois`) and expose `__version__` from `__about__.py`.
- Introduce optional `date_parser: Callable[[str], datetime]` hooks across `WhoisParser` and `build_whois_record`.
- Add pytest suite (fixtures + Hypothesis), CLI entry point, Ruff tooling, Makefile, and GitHub Actions pipeline (lint → test → build → publish).
- Provide benchmark harness + marketing-grade docs/README demonstrating throughput vs `whois-parser` and `python-whois`.
- Document SemVer/tagging strategy and include `py.typed` for downstream type checking.

## [0.1.0] - 2023-xx-xx

- Initial `structly_whois_parser` release (legacy name).
