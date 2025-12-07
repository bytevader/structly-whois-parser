from __future__ import annotations

import io
import json
from pathlib import Path

import pytest

from structly_whois import cli


def test_cli_outputs_json(tmp_payload: Path, capsys: pytest.CaptureFixture[str]) -> None:
    exit_code = cli.main([
        str(tmp_payload),
        "--json",
        "--record",
        "--domain",
        "cli.example",
        "--date-parser",
        "tests.helpers:iso_to_datetime",
    ])

    assert exit_code == 0
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert data["domain"] == "cli.example"
    assert data["registered_at"].startswith("2021-01-01")


def test_cli_rejects_invalid_date_parser(tmp_payload: Path) -> None:
    with pytest.raises(ValueError):
        cli.main([
            str(tmp_payload),
            "--domain",
            "cli.example",
            "--date-parser",
            "not-a-module",
        ])


def test_cli_rejects_non_callable_date_parser(tmp_payload: Path) -> None:
    with pytest.raises(TypeError):
        cli.main([
            str(tmp_payload),
            "--domain",
            "cli.example",
            "--date-parser",
            "json:__doc__",
        ])


def test_read_payload_reads_stdin(monkeypatch: pytest.MonkeyPatch) -> None:
    fake_stdin = io.StringIO("Domain Name: stdin.example\n")
    monkeypatch.setattr(cli.sys, "stdin", fake_stdin)
    assert cli._read_payload("-") == "Domain Name: stdin.example\n"
