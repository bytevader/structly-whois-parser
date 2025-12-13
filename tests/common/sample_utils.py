"""Shared helpers for WHOIS sample fixtures used by tests and tooling."""

from __future__ import annotations

from pathlib import Path

COMMON_DIR = Path(__file__).resolve().parent
TESTS_ROOT = COMMON_DIR.parent
PROJECT_ROOT = TESTS_ROOT.parent
SAMPLES_ROOT = TESTS_ROOT / "samples"
WHOIS_ROOT = SAMPLES_ROOT / "whois"
EXPECTED_ROOT = SAMPLES_ROOT / "expected"

# Keep samples whose final WHOIS section does not include usable data out of the
# golden tests to avoid asserting on incomplete/denied payloads.
SKIPPED_SAMPLES = frozenset({
    "bbva.es",
    "claro.com.co",
    "cra-arc.gc.ca",
    "druid.fi",
    "echa.europa.eu",
    "google.cl",
    "google.com.tr",
    "google.lu",
    "liechtenstein.li",
})
