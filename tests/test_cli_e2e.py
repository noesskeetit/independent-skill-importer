"""End-to-end tests for the public scan CLI."""

from __future__ import annotations

import json
import os
import shutil
import stat
import subprocess
import sys
from dataclasses import replace
from pathlib import Path

import pytest
from click.testing import CliRunner
from fixture_factory import write_tree

import skill_importer.cli as cli_module
from skill_importer.cli import _render_human, cli
from skill_importer.importer import ImportResult
from skill_importer.models import ExternalRequirements, ScanReport, SourceSpec
from skill_importer.pipeline import ScanOptions, SkillImporterPipeline


def _skill(name: str, body: str = "Self-contained.\n") -> str:
    return f"---\nname: {name}\ndescription: CLI test skill\n---\n{body}"


def _installed_console_script() -> Path:
    script = shutil.which("skill-importer", path=str(Path(sys.executable).parent))
    assert script is not None, "skill-importer console script is not installed beside Python"
    return Path(script)


def _offline_child_environment(tmp_path: Path) -> dict[str, str]:
    environment = dict(os.environ)
    environment.pop("LLM_API_KEY", None)
    environment["HOME"] = str(tmp_path / "child-home")
    environment["UV_OFFLINE"] = "1"
    environment["PYTHONNOUSERSITE"] = "1"
    for key in (
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "http_proxy",
        "https_proxy",
        "all_proxy",
    ):
        environment[key] = "http://127.0.0.1:9"
    environment["NO_PROXY"] = ""
    environment["no_proxy"] = ""
    assert "LLM_API_KEY" not in environment
    return environment


def _run_console(
    tmp_path: Path,
    arguments: list[str],
    *,
    extra_environment: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    environment = _offline_child_environment(tmp_path)
    if extra_environment is not None:
        environment.update(extra_environment)
    return subprocess.run(
        [str(_installed_console_script()), *arguments],
        check=False,
        capture_output=True,
        cwd=tmp_path,
        env=environment,
        shell=False,
        text=True,
        timeout=30,
    )


def _tree_state(root: Path) -> tuple[tuple[str, str, int, bytes | None], ...]:
    state: list[tuple[str, str, int, bytes | None]] = []
    for path in sorted(root.rglob("*")):
        metadata = path.lstat()
        if path.is_dir():
            kind = "directory"
            content = None
        else:
            kind = "file"
            content = path.read_bytes()
        state.append(
            (
                path.relative_to(root).as_posix(),
                kind,
                stat.S_IMODE(metadata.st_mode),
                content,
            )
        )
    return tuple(state)


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


def test_import_cli_runs_fresh_scan_copies_payload_and_never_executes_script(
    runner: CliRunner, tmp_path: Path
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    write_tree(
        source,
        {
            "tool/SKILL.md": _skill("fresh"),
            "tool/scripts/run.sh": "exit 99\n",
        },
    )
    os.chmod(source / "tool/scripts/run.sh", 0o755)

    preview = runner.invoke(cli, ["scan", str(source), "--no-llm", "--json"])
    assert preview.exit_code == 0, preview.output
    (source / "tool/assets").mkdir()
    (source / "tool/assets/after-scan.txt").write_text("fresh scan")
    out = tmp_path / "out"

    imported = runner.invoke(
        cli,
        ["import", str(source), "--out", str(out), "--no-llm"],
    )

    assert imported.exit_code == 0, imported.output
    payload_dirs = [path for path in out.iterdir() if path.is_dir()]
    assert len(payload_dirs) == 1
    assert (payload_dirs[0] / "assets/after-scan.txt").read_text() == "fresh scan"
    assert (out / "import-manifest.json").is_file()
    assert "Imported 1" in imported.stdout


def test_import_cli_with_only_rejected_candidates_exits_zero(
    runner: CliRunner, tmp_path: Path
) -> None:
    source = tmp_path / "invalid"
    source.mkdir()
    write_tree(source, {"SKILL.md": "---\nname: [broken\n---\n"})
    out = tmp_path / "out"

    result = runner.invoke(
        cli,
        ["import", str(source), "--out", str(out), "--no-llm"],
    )

    assert result.exit_code == 0, result.output
    assert "Imported 0" in result.stdout
    assert json.loads((out / "import-manifest.json").read_text())["imported"] == []


def test_import_cli_operational_error_is_safe_and_exits_one(
    runner: CliRunner, tmp_path: Path
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    write_tree(source, {"SKILL.md": _skill("existing")})
    out = tmp_path / "out"
    out.write_text("keep")

    result = runner.invoke(
        cli,
        ["import", str(source), "--out", str(out), "--no-llm"],
    )

    assert result.exit_code == 1
    assert "OUTPUT_EXISTS" in result.stderr
    assert result.stdout == ""
    assert out.read_text() == "keep"


def test_import_cli_requires_out_and_uses_click_exit_two(runner: CliRunner) -> None:
    result = runner.invoke(cli, ["import", ".", "--no-llm"])

    assert result.exit_code == 2
    assert "Missing option" in result.stderr


def test_import_cli_propagates_ref_subpath_model_and_no_llm(
    monkeypatch: pytest.MonkeyPatch,
    runner: CliRunner,
    tmp_path: Path,
) -> None:
    captured: dict[str, object] = {}

    class FakeImporter:
        def import_source(
            self,
            spec: SourceSpec,
            out: Path,
            options: ScanOptions | None = None,
        ) -> ImportResult:
            captured.update(spec=spec, out=out, options=options)
            return ImportResult(output_path=out, imported=(), skipped=())

    monkeypatch.setattr(cli_module, "SkillImporter", FakeImporter)
    out = tmp_path / "out"

    result = runner.invoke(
        cli,
        [
            "import",
            "https://example.com/acme/repo.git",
            "--out",
            str(out),
            "--ref",
            "release",
            "--subpath",
            "nested/skill",
            "--model",
            "test/model",
            "--no-llm",
        ],
    )

    assert result.exit_code == 0, result.output
    spec = captured["spec"]
    options = captured["options"]
    assert isinstance(spec, SourceSpec)
    assert spec.ref == "release"
    assert spec.subpath == "nested/skill"
    assert isinstance(options, ScanOptions)
    assert options.model == "test/model"
    assert not options.use_llm


def test_import_human_output_escapes_untrusted_controls(runner: CliRunner, tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    write_tree(source, {"SKILL.md": _skill('"\\u001b[31mowned"')})
    out = tmp_path / "out"

    result = runner.invoke(
        cli,
        ["import", str(source), "--out", str(out), "--no-llm"],
    )

    assert result.exit_code == 0, result.output
    assert "\x1b" not in result.stdout
    assert "\\u001b[31mowned" in result.stdout


def test_scan_console_subprocess_emits_json_and_is_read_only(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    write_tree(
        source,
        {
            "nested/SKILL.md": _skill("subprocess-scan"),
            "nested/assets/data.txt": "kept\n",
        },
    )
    before = _tree_state(source)

    result = _run_console(
        tmp_path,
        ["scan", str(source), "--no-llm", "--json"],
    )

    assert result.returncode == 0, result.stderr
    assert result.stderr == ""
    payload = json.loads(result.stdout)
    assert payload["schemaVersion"] == "1.0"
    assert payload["counts"] == {
        "total": 1,
        "portable": 1,
        "plugin_bound": 0,
        "ambiguous": 0,
        "invalid": 0,
        "blocked": 0,
    }
    assert payload["skills"][0]["root"] == "nested"
    assert _tree_state(source) == before
    assert not (tmp_path / "out").exists()


def test_import_console_subprocess_rescans_and_never_executes_payload(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    script_text = '#!/bin/sh\nprintf executed > "${SKILL_IMPORTER_EXECUTION_SENTINEL}"\nexit 97\n'
    write_tree(
        source,
        {
            "tool/SKILL.md": _skill("subprocess-import"),
            "tool/scripts/never-run.sh": script_text,
        },
    )
    script = source / "tool/scripts/never-run.sh"
    script.chmod(0o755)
    sentinel = tmp_path / "repository-code-executed"
    child_environment = {"SKILL_IMPORTER_EXECUTION_SENTINEL": str(sentinel)}

    preview = _run_console(
        tmp_path,
        ["scan", str(source), "--no-llm", "--json"],
        extra_environment=child_environment,
    )
    assert preview.returncode == 0, preview.stderr
    assert json.loads(preview.stdout)["counts"]["portable"] == 1
    assert not sentinel.exists()

    (source / "tool/assets").mkdir()
    (source / "tool/assets/after-scan.txt").write_text("fresh scan\n", encoding="utf-8")
    out = tmp_path / "out"
    imported = _run_console(
        tmp_path,
        ["import", str(source), "--out", str(out), "--no-llm"],
        extra_environment=child_environment,
    )

    assert imported.returncode == 0, imported.stderr
    assert imported.stderr == ""
    assert "Imported 1" in imported.stdout
    assert not sentinel.exists()
    payload_directories = [path for path in out.iterdir() if path.is_dir()]
    assert len(payload_directories) == 1
    payload = payload_directories[0]
    copied_script = payload / "scripts/never-run.sh"
    assert (payload / "assets/after-scan.txt").read_text(encoding="utf-8") == "fresh scan\n"
    assert copied_script.read_bytes() == script_text.encode()
    assert copied_script.stat().st_mode & stat.S_IXUSR
    assert (out / "import-manifest.json").is_file()
