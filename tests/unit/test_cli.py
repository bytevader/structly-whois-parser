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
        "tests.common.helpers:iso_to_datetime",
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


def test_cli_default_output_uses_mapping(tmp_payload: Path, capsys: pytest.CaptureFixture[str]) -> None:
    exit_code = cli.main([str(tmp_payload)])

    assert exit_code == 0
    captured = capsys.readouterr()
    assert "cli.example" in captured.out
    assert captured.err == ""


def test_cli_jsonl_stream_best_effort(tmp_payload: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    payload_text = tmp_payload.read_text(encoding="utf-8")
    jsonl_file = tmp_path / "payloads.jsonl"
    jsonl_file.write_text(
        "\n".join([
            json.dumps({"raw_text": payload_text, "domain": "cli.example"}),
            json.dumps({"domain": "missing-raw"}),  # invalid entry should be skipped
            json.dumps({"raw_text": payload_text.replace("cli", "cli2"), "domain": "cli2.example"}),
        ]),
        encoding="utf-8",
    )

    exit_code = cli.main([
        str(jsonl_file),
        "--input-format",
        "jsonl",
        "--jsonl",
        "--best-effort",
        "--metrics",
    ])

    captured = capsys.readouterr()
    lines = [json.loads(line) for line in captured.out.strip().splitlines()]
    assert exit_code == 1  # failures were logged but parsing continued
    assert len(lines) == 2
    assert lines[0]["domain_name"] == "cli.example"
    assert lines[1]["domain_name"] == "cli2.example"
    assert "failed" in captured.err


def test_cli_metrics_summary(tmp_payload: Path, capsys: pytest.CaptureFixture[str]) -> None:
    exit_code = cli.main([
        str(tmp_payload),
        "--metrics",
        "--json",
    ])

    captured = capsys.readouterr()
    assert exit_code == 0
    assert '"domain_name": "cli.example"' in captured.out
    assert "Processed 1 payload(s); 1 succeeded / 0 failed" in captured.err


def test_cli_jsonl_fail_fast_stops_on_first_error(
    tmp_payload: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    bad_line = '{"raw_text":'
    good_line = json.dumps({"raw_text": tmp_payload.read_text(), "domain": "cli.example"})
    jsonl_path = tmp_path / "bad.jsonl"
    jsonl_path.write_text(f"{bad_line}\n{good_line}\n", encoding="utf-8")

    with pytest.raises(ValueError) as exc:
        cli.main([
            str(jsonl_path),
            "--input-format",
            "jsonl",
            "--jsonl",
            "--fail-fast",
        ])

    captured = capsys.readouterr()
    assert captured.out == ""
    assert "invalid JSON" in str(exc.value)
    assert captured.err == ""


def test_cli_jsonl_missing_raw_text_best_effort(
    tmp_payload: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    missing_payload = json.dumps({"id": "broken"})
    valid_payload = json.dumps({"raw_text": tmp_payload.read_text(), "domain": "cli.example"})
    jsonl_path = tmp_path / "missing_raw.jsonl"
    jsonl_path.write_text(f"{missing_payload}\n{valid_payload}\n", encoding="utf-8")

    exit_code = cli.main([
        str(jsonl_path),
        "--input-format",
        "jsonl",
        "--jsonl",
        "--best-effort",
    ])

    captured = capsys.readouterr()
    assert exit_code == 1
    assert json.loads(captured.out)["domain_name"] == "cli.example"
    assert "missing raw_text" in captured.err


def test_cli_rejects_mutually_exclusive_output_flags(tmp_payload: Path) -> None:
    with pytest.raises(SystemExit):
        cli.main([
            str(tmp_payload),
            "--json",
            "--jsonl",
        ])


def test_iter_jsonl_payloads_reads_stdin_and_context(
    tmp_payload: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    payload_text = tmp_payload.read_text(encoding="utf-8")
    stream = io.StringIO(
        "\n"  # blank line should be skipped
        "not json\n"  # invalid JSON handled best-effort
        f"{json.dumps({'raw_text': payload_text, 'domain': 'cli.example', 'id': 'row-1'})}\n"
    )
    monkeypatch.setattr(cli.sys, "stdin", stream)
    metrics = {"processed": 0, "failed": 0}

    specs = list(
        cli._iter_jsonl_payloads(
            "-",
            default_domain=None,
            default_tld=None,
            default_lowercase=False,
            fail_fast=False,
            metrics=metrics,
        )
    )

    stderr = capsys.readouterr().err
    assert specs and specs[0].context.endswith("(row-1)")
    assert "invalid JSON" in stderr
    assert metrics == {"processed": 2, "failed": 1}


def test_iter_jsonl_payloads_fail_fast_on_missing_raw_text(tmp_path: Path) -> None:
    jsonl_path = tmp_path / "missing_raw.jsonl"
    jsonl_path.write_text('{"domain": "cli.example"}\n', encoding="utf-8")
    metrics = {"processed": 0, "failed": 0}

    iterator = cli._iter_jsonl_payloads(
        str(jsonl_path),
        default_domain=None,
        default_tld=None,
        default_lowercase=False,
        fail_fast=True,
        metrics=metrics,
    )

    with pytest.raises(ValueError) as exc:
        next(iterator)

    assert "missing raw_text field" in str(exc.value)
