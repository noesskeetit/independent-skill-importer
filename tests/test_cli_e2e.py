"""End-to-end tests for the public scan CLI."""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

import pytest
from click.testing import CliRunner
from fixture_factory import write_tree

from skill_importer.cli import _render_human, cli
from skill_importer.models import ExternalRequirements, ScanReport, SourceSpec
from skill_importer.pipeline import ScanOptions, SkillImporterPipeline


def _skill(name: str, body: str = "Self-contained.\n") -> str:
    return f"---\nname: {name}\ndescription: CLI test skill\n---\n{body}"


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


def test_scan_json_has_exact_schema_counts_and_is_byte_deterministic(
    runner: CliRunner, tmp_path: Path
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    write_tree(source, {"nested/SKILL.md": _skill("standalone")})
    arguments = ["scan", str(source), "--no-llm", "--json"]

    first = runner.invoke(cli, arguments)
    second = runner.invoke(cli, arguments)

    assert first.exit_code == 0, first.output
    assert second.exit_code == 0, second.output
    assert first.stdout_bytes == second.stdout_bytes
    payload = json.loads(first.stdout)
    assert set(payload) == {
        "schemaVersion",
        "source",
        "skills",
        "duplicates",
        "nameConflicts",
        "counts",
        "warnings",
        "errors",
    }
    assert payload["schemaVersion"] == "1.0"
    assert payload["counts"] == {
        "total": 1,
        "portable": 1,
        "plugin_bound": 0,
        "ambiguous": 0,
        "invalid": 0,
        "blocked": 0,
    }
    assert first.stderr == ""


def test_scan_json_never_exposes_temporary_workspace_or_secret(
    runner: CliRunner, tmp_path: Path
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    write_tree(source, {"SKILL.md": _skill("standalone")})
    secret = "do-not-print-this-fm-key"

    result = runner.invoke(
        cli,
        ["scan", str(source), "--json"],
        env={"LLM_API_KEY": secret},
    )

    assert result.exit_code == 0, result.output
    assert secret not in result.stdout
    assert "skill-importer-scan-" not in result.stdout
    assert "snapshotRoot" not in result.stdout
    assert result.stderr == ""


def test_scan_empty_repository_is_a_valid_zero_result(runner: CliRunner, tmp_path: Path) -> None:
    source = tmp_path / "empty"
    source.mkdir()

    result = runner.invoke(cli, ["scan", str(source), "--json"], env={"LLM_API_KEY": ""})

    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout)["counts"]["total"] == 0


def test_scan_with_only_rejected_candidates_still_exits_zero(
    runner: CliRunner, tmp_path: Path
) -> None:
    source = tmp_path / "invalid"
    source.mkdir()
    write_tree(source, {"SKILL.md": "---\nname: [broken\n---\n"})

    result = runner.invoke(
        cli, ["scan", str(source), "--no-llm", "--json"], env={"LLM_API_KEY": ""}
    )

    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout)["counts"]["invalid"] == 1


def test_no_llm_cli_keeps_mixed_plugin_ambiguous_without_fm_reason(
    runner: CliRunner, tmp_path: Path
) -> None:
    source = tmp_path / "mixed"
    source.mkdir()
    write_tree(
        source,
        {
            "plugin.json": '{"name":"mixed"}',
            "src/runtime.py": "def activate():\n    return None\n",
            "skills/alpha/SKILL.md": _skill("alpha"),
        },
    )

    result = runner.invoke(cli, ["scan", str(source), "--no-llm", "--json"])

    assert result.exit_code == 0, result.output
    skill = json.loads(result.stdout)["skills"][0]
    assert skill["classification"] == "ambiguous"
    assert skill["analysisMethod"] == "static"
    assert not any(reason["code"].startswith("FM_") for reason in skill["reasons"])


def test_human_output_escapes_untrusted_terminal_control_characters(
    runner: CliRunner, tmp_path: Path
) -> None:
    source = tmp_path / "controls"
    source.mkdir()
    write_tree(source, {"SKILL.md": _skill('"\\u001b[31mowned"')})

    result = runner.invoke(cli, ["scan", str(source), "--no-llm"])

    assert result.exit_code == 0, result.output
    assert "\x1b" not in result.stdout
    assert "\\u001b[31mowned" in result.stdout
    assert "portable" in result.stdout
    assert "package: none" in result.stdout
    assert "externalRequirements: binaries=[] environment=[]" in result.stdout


def test_human_preview_shows_boundary_requirements_and_exact_groups_with_escaping(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    plugin_root = "plugins/\x1bplugin"
    skill_text = _skill('"\\u001b[31msame"')
    write_tree(
        source,
        {
            f"{plugin_root}/plugin.json": '{"name":"mixed"}',
            f"{plugin_root}/src/runtime.py": "def activate():\n    return None\n",
            f"{plugin_root}/skills/one/SKILL.md": skill_text,
            f"{plugin_root}/skills/two/SKILL.md": skill_text,
        },
    )
    report = SkillImporterPipeline(api_key_provider=lambda: None).scan(
        SourceSpec.local(source),
        ScanOptions(use_llm=False),
    )
    skills = tuple(
        replace(
            skill,
            external_requirements=ExternalRequirements(
                binaries=("git", "\x1bbin"),
                environment=("TOKEN", "\x1bENV"),
            ),
        )
        for skill in report.skills
    )
    report = ScanReport(
        source=report.source,
        skills=skills,
        duplicates=report.duplicates,
        name_conflicts=report.name_conflicts,
    )

    output = _render_human(report)

    assert "\x1b" not in output
    assert "package: root=plugins/\\u001bplugin" in output
    assert "manifest=plugins/\\u001bplugin/plugin.json" in output
    assert "kind=plugin packageKind=mixed" in output
    assert "externalRequirements: binaries=[git, \\u001bbin]" in output
    assert "environment=[TOKEN, \\u001bENV]" in output
    assert f"groupId={report.duplicates[0].group_id}" in output
    assert f"contentHash={report.duplicates[0].content_hash}" in output
    assert all(candidate_id in output for candidate_id in report.duplicates[0].candidate_ids)
    assert f"groupId={report.name_conflicts[0].group_id}" in output
    assert "name=\\u001b[31msame" in output


def test_scan_does_not_create_output_or_modify_source(runner: CliRunner, tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    write_tree(source, {"SKILL.md": _skill("standalone")})
    before = sorted(path.relative_to(tmp_path).as_posix() for path in tmp_path.rglob("*"))

    result = runner.invoke(cli, ["scan", str(source), "--no-llm", "--json"])

    after = sorted(path.relative_to(tmp_path).as_posix() for path in tmp_path.rglob("*"))
    assert result.exit_code == 0, result.output
    assert after == before


def test_operational_error_exits_one_and_keeps_json_stdout_empty(
    runner: CliRunner, tmp_path: Path
) -> None:
    missing = tmp_path / "missing"

    result = runner.invoke(cli, ["scan", str(missing), "--json"])

    assert result.exit_code == 1
    assert result.stdout == ""
    assert "SOURCE_UNAVAILABLE" in result.stderr


def test_click_usage_error_exits_two(runner: CliRunner) -> None:
    result = runner.invoke(cli, ["scan"])

    assert result.exit_code == 2
    assert "Missing argument" in result.stderr


@pytest.mark.parametrize("model", ["", "bad\nmodel", "bad\u202emodel", "x" * 257])
def test_invalid_model_is_a_click_usage_error(runner: CliRunner, model: str) -> None:
    result = runner.invoke(cli, ["scan", ".", "--model", model])

    assert result.exit_code == 2
    assert "model" in result.stderr.casefold()


def test_ref_on_local_source_is_an_operational_error(runner: CliRunner, tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()

    result = runner.invoke(cli, ["scan", str(source), "--ref", "main", "--json"])

    assert result.exit_code == 1
    assert result.stdout == ""
    assert "INVALID_SOURCE" in result.stderr


def test_subpath_and_model_options_are_reflected_in_same_report_pipeline(
    runner: CliRunner, tmp_path: Path
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    write_tree(
        source,
        {
            "one/SKILL.md": _skill("one"),
            "two/SKILL.md": _skill("two"),
        },
    )

    result = runner.invoke(
        cli,
        [
            "scan",
            str(source),
            "--subpath",
            "two",
            "--model",
            "test/model",
            "--no-llm",
            "--json",
        ],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.stdout)
    assert [skill["root"] for skill in payload["skills"]] == ["two"]
    assert payload["source"]["discoveryScope"] == "two"
