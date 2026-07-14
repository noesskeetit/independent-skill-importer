"""Acceptance matrix for inspectable source-layout fixtures."""

from __future__ import annotations

import json
import shutil
import stat
from collections.abc import Mapping
from pathlib import Path

import pytest
from fixture_factory import StaticArchiveGitRunner, TarEntry, create_tar

from skill_importer.errors import ImporterError
from skill_importer.importer import ImportResult, SkillImporter
from skill_importer.limits import Limits
from skill_importer.models import (
    AnalyzedSkill,
    Classification,
    DecisionReason,
    ReasonCode,
    ScanReport,
    SourceKind,
    SourceSpec,
)
from skill_importer.pipeline import ScanOptions, SkillImporterPipeline
from skill_importer.source import SourceResolver, snapshot_local

FIXTURES = Path(__file__).parent / "fixtures"


def _fixture_source(name: str) -> Path:
    source = FIXTURES / name
    assert source.is_dir(), f"missing acceptance fixture: {name}"
    return source


def _forbid_api_key_read() -> str:
    raise AssertionError("--no-llm acceptance scans must not read the FM API key")


def _scan_source_without_llm(source: Path) -> ScanReport:
    pipeline = SkillImporterPipeline(api_key_provider=_forbid_api_key_read)
    return pipeline.scan(SourceSpec.local(source), ScanOptions(use_llm=False))


def _scan_fixture_without_llm(name: str) -> ScanReport:
    return _scan_source_without_llm(_fixture_source(name))


def _import_fixture_without_llm(name: str, out: Path) -> ImportResult:
    pipeline = SkillImporterPipeline(api_key_provider=_forbid_api_key_read)
    return SkillImporter(pipeline=pipeline).import_source(
        SourceSpec.local(_fixture_source(name)),
        out,
        ScanOptions(use_llm=False),
    )


def _only_skill(report: ScanReport) -> AnalyzedSkill:
    assert len(report.skills) == 1
    return report.skills[0]


def _reason(skill: AnalyzedSkill, code: ReasonCode) -> DecisionReason:
    return next(reason for reason in skill.reasons if reason.code is code)


class _PortableFmTransport:
    """Return one deterministic hash-bound response at the HTTP boundary."""

    def __init__(self) -> None:
        self.calls = 0

    def send(
        self,
        endpoint: str,
        headers: Mapping[str, str],
        request: Mapping[str, object],
        *,
        timeout_seconds: int,
    ) -> bytes:
        del endpoint, headers, timeout_seconds
        self.calls += 1
        messages = request["messages"]
        assert isinstance(messages, list)
        user_message = messages[1]
        assert isinstance(user_message, dict)
        prompt = user_message["content"]
        assert isinstance(prompt, str)
        marker = "ANALYSIS_HASH: "
        start = prompt.index(marker) + len(marker)
        analysis_hash = prompt[start : start + 71]
        payload = {
            "analysis_hash": analysis_hash,
            "verdict": "portable",
            "confidence": 0.97,
            "reason_codes": ["SELF_CONTAINED_FILES"],
            "evidence": [
                {
                    "path": "skills/alpha/SKILL.md",
                    "line": 6,
                    "value": "All required resources are bundled in this skill directory.",
                }
            ],
            "rationale": "The cited instruction establishes a self-contained payload.",
        }
        completion = json.dumps(payload, separators=(",", ":"))
        return json.dumps(
            {"choices": [{"message": {"role": "assistant", "content": completion}}]},
            separators=(",", ":"),
        ).encode()


def test_standalone_fixture_is_portable_and_preserves_payload_contract() -> None:
    source = _fixture_source("01_standalone")
    script = source / "skill/scripts/never-run.sh"

    assert (source / "skill/assets/payload.txt").is_file()
    assert (source / "skill/references/guide.md").is_file()
    assert script.is_file()
    assert script.stat().st_mode & stat.S_IXUSR

    skill = _only_skill(_scan_source_without_llm(source))

    assert skill.candidate.root == "skill"
    assert skill.classification is Classification.PORTABLE
    assert ReasonCode.STANDALONE_NO_PLUGIN_BOUNDARY in skill.reason_codes
    assert skill.external_requirements.binaries == ("docker", "git")
    assert skill.external_requirements.environment == ("WORKSPACE_ID",)


def test_monorepo_fixture_finds_two_independent_skills_without_groups() -> None:
    report = _scan_fixture_without_llm("02_monorepo")

    assert [
        (
            skill.candidate.root,
            skill.candidate.entrypoint,
            skill.name,
            skill.classification,
        )
        for skill in report.skills
    ] == [
        (
            "apps/editor/custom-skill",
            "apps/editor/custom-skill/SKILL.md",
            "editor-helper",
            Classification.PORTABLE,
        ),
        (
            "packages/ops/nested/skill-two",
            "packages/ops/nested/skill-two/skill.md",
            "ops-helper",
            Classification.PORTABLE,
        ),
    ]
    assert all(
        ReasonCode.STANDALONE_NO_PLUGIN_BOUNDARY in skill.reason_codes for skill in report.skills
    )
    assert report.duplicates == ()
    assert report.name_conflicts == ()


@pytest.mark.parametrize(
    ("fixture_name", "root", "classification", "reason_code"),
    [
        (
            "03_skills_only_plugin",
            "skills/alpha",
            Classification.PORTABLE,
            ReasonCode.SKILLS_ONLY_PACKAGE,
        ),
        (
            "04_plugin_root_variable",
            "skills/internal",
            Classification.PLUGIN_BOUND,
            ReasonCode.PLUGIN_ROOT_VARIABLE,
        ),
        (
            "05_runtime_uses_skill",
            "skills/internal",
            Classification.PLUGIN_BOUND,
            ReasonCode.REFERENCED_BY_PLUGIN_RUNTIME,
        ),
        (
            "07_outside_resource",
            "skill",
            Classification.PLUGIN_BOUND,
            ReasonCode.REFERENCE_OUTSIDE_SKILL_ROOT,
        ),
        (
            "08_adjacent_plugin",
            "standalone",
            Classification.PORTABLE,
            ReasonCode.STANDALONE_NO_PLUGIN_BOUNDARY,
        ),
    ],
)
def test_static_acceptance_matrix(
    fixture_name: str,
    root: str,
    classification: Classification,
    reason_code: ReasonCode,
) -> None:
    skill = _only_skill(_scan_fixture_without_llm(fixture_name))

    assert skill.candidate.root == root
    assert skill.classification is classification
    assert reason_code in skill.reason_codes


def test_static_acceptance_reasons_include_source_addressable_evidence() -> None:
    plugin_variable = _only_skill(_scan_fixture_without_llm("04_plugin_root_variable"))
    runtime_reference = _only_skill(_scan_fixture_without_llm("05_runtime_uses_skill"))
    outside_reference = _only_skill(_scan_fixture_without_llm("07_outside_resource"))

    variable_evidence = _reason(plugin_variable, ReasonCode.PLUGIN_ROOT_VARIABLE).evidence[0]
    assert (
        variable_evidence.path,
        variable_evidence.line,
        variable_evidence.field,
        variable_evidence.value,
    ) == ("skills/internal/SKILL.md", 5, "text", "${PLUGIN_ROOT}")

    runtime_evidence = _reason(runtime_reference, ReasonCode.REFERENCED_BY_PLUGIN_RUNTIME).evidence[
        0
    ]
    assert runtime_evidence.path == "src/runtime.py"
    assert "skills/internal" in runtime_evidence.value

    outside_evidence = _reason(outside_reference, ReasonCode.REFERENCE_OUTSIDE_SKILL_ROOT).evidence[
        0
    ]
    assert outside_evidence.path == "skill/SKILL.md"
    assert outside_evidence.value == "../shared/resource.md -> shared/resource.md"


def test_mixed_fixture_is_static_ambiguous_then_hash_bound_fm_portable() -> None:
    source = _fixture_source("06_mixed_unproven")
    static_skill = _only_skill(_scan_source_without_llm(source))

    assert static_skill.classification is Classification.AMBIGUOUS
    assert static_skill.analysis_method == "static"
    assert ReasonCode.MIXED_PLUGIN_AUTONOMY_UNPROVEN in static_skill.reason_codes

    transport = _PortableFmTransport()
    pipeline = SkillImporterPipeline(
        fm_transport_factory=lambda limits: transport,
        api_key_provider=lambda: "fixture-api-key",
    )
    fm_skill = _only_skill(pipeline.scan(SourceSpec.local(source), ScanOptions(use_llm=True)))

    assert transport.calls == 1
    assert fm_skill.static_classification is Classification.AMBIGUOUS
    assert fm_skill.classification is Classification.PORTABLE
    assert fm_skill.analysis_method == "static+fm"
    assert ReasonCode.FM_PORTABLE_VERIFIED in fm_skill.reason_codes
    fm_evidence = _reason(fm_skill, ReasonCode.FM_PORTABLE_VERIFIED).evidence[0]
    assert (fm_evidence.path, fm_evidence.line, fm_evidence.value) == (
        "skills/alpha/SKILL.md",
        6,
        "All required resources are bundled in this skill directory.",
    )


def test_invalid_frontmatter_does_not_abort_valid_sibling() -> None:
    report = _scan_fixture_without_llm("09_invalid_frontmatter")

    assert report.counts == {
        "total": 2,
        "portable": 1,
        "plugin_bound": 0,
        "ambiguous": 0,
        "invalid": 1,
        "blocked": 0,
    }
    assert [skill.classification for skill in report.skills] == [
        Classification.INVALID,
        Classification.PORTABLE,
    ]
    assert ReasonCode.INVALID_FRONTMATTER in report.skills[0].reason_codes
    assert ReasonCode.STANDALONE_NO_PLUGIN_BOUNDARY in report.skills[1].reason_codes


def test_path_traversal_and_symlink_escape_are_both_blocked(tmp_path: Path) -> None:
    source = tmp_path / "unsafe-source"
    shutil.copytree(_fixture_source("10_symlink_escape"), source)
    (source / "skill/escape").symlink_to("../outside/secret.txt")

    skill = _only_skill(_scan_source_without_llm(source))

    assert skill.classification is Classification.BLOCKED
    assert ReasonCode.PATH_TRAVERSAL in skill.reason_codes
    assert ReasonCode.SYMLINK_ESCAPE in skill.reason_codes
    symlink = _reason(skill, ReasonCode.SYMLINK_ESCAPE).evidence[0]
    assert (symlink.path, symlink.value) == (
        "skill/escape",
        "../outside/secret.txt -> outside/secret.txt",
    )


def test_unsafe_local_source_entry_is_rejected_before_static_analysis(
    tmp_path: Path,
) -> None:
    source = tmp_path / "unsafe-local-source"
    source.mkdir()
    (source / "bad\\name").write_text("unsafe", encoding="utf-8")

    with pytest.raises(ImporterError, match="unsafe source path"):
        snapshot_local(source, tmp_path / "workspace", Limits())


def test_archive_traversal_is_rejected_before_static_analysis(tmp_path: Path) -> None:
    archive = tmp_path / "hostile.tar"
    create_tar(archive, [TarEntry("../escape", content=b"unsafe")])
    resolver = SourceResolver(
        limits=Limits(),
        git_runner=StaticArchiveGitRunner(archive),
    )
    spec = SourceSpec(
        kind=SourceKind.GIT,
        value="https://example.com/acme/repository.git",
    )

    with pytest.raises(ImporterError, match="archive path traversal"):
        resolver.resolve(spec, tmp_path / "workspace")


def test_same_name_different_payloads_form_only_a_name_conflict() -> None:
    report = _scan_fixture_without_llm("11_name_conflict")

    assert len(report.skills) == 2
    assert all(skill.classification is Classification.PORTABLE for skill in report.skills)
    assert {skill.name for skill in report.skills} == {"collision"}
    assert len({skill.content_hash for skill in report.skills}) == 2
    assert report.duplicates == ()
    assert len(report.name_conflicts) == 1
    assert all(ReasonCode.NAME_CONFLICT in skill.reason_codes for skill in report.skills)
    assert all(skill.duplicate_group is None for skill in report.skills)
    assert all(
        skill.name_conflict_group == report.name_conflicts[0].group_id for skill in report.skills
    )


def test_identical_layouts_form_duplicate_and_name_conflict_groups() -> None:
    report = _scan_fixture_without_llm("12_duplicate_layouts")

    assert [skill.candidate.root for skill in report.skills] == [
        "layout-a/tool",
        "marketplace/packages/tool",
    ]
    assert all(skill.classification is Classification.PORTABLE for skill in report.skills)
    assert len({skill.content_hash for skill in report.skills}) == 1
    assert len(report.duplicates) == 1
    assert len(report.name_conflicts) == 1
    assert all(ReasonCode.DUPLICATE_CONTENT in skill.reason_codes for skill in report.skills)
    assert all(ReasonCode.NAME_CONFLICT in skill.reason_codes for skill in report.skills)
    assert all(skill.duplicate_group == report.duplicates[0].group_id for skill in report.skills)
    assert all(
        skill.name_conflict_group == report.name_conflicts[0].group_id for skill in report.skills
    )


def test_same_name_fixture_imports_two_distinct_payloads_without_clobber(
    tmp_path: Path,
) -> None:
    out = tmp_path / "out"

    result = _import_fixture_without_llm("11_name_conflict", out)
    manifest = json.loads((out / "import-manifest.json").read_text(encoding="utf-8"))
    payload_directories = sorted(path for path in out.iterdir() if path.is_dir())

    assert len(result.imported) == 2
    assert {record.name for record in result.imported} == {"collision"}
    assert len({record.content_hash for record in result.imported}) == 2
    assert len({record.destination.casefold() for record in result.imported}) == 2
    assert all(record.destination.startswith("collision--") for record in result.imported)
    assert len(payload_directories) == 2
    assert {
        (payload / "assets/payload.txt").read_text(encoding="utf-8")
        for payload in payload_directories
    } == {"first distinct payload\n", "second distinct payload\n"}
    assert len(manifest["imported"]) == 2
    assert len({record["destination"].casefold() for record in manifest["imported"]}) == 2
    assert {
        item["originalRoot"] for record in manifest["imported"] for item in record["provenance"]
    } == {
        "one",
        "two",
    }


def test_duplicate_fixture_imports_one_payload_with_complete_provenance(
    tmp_path: Path,
) -> None:
    source = _fixture_source("12_duplicate_layouts")
    out = tmp_path / "out"
    preview = _scan_fixture_without_llm("12_duplicate_layouts")
    expected_provenance = {
        (
            skill.candidate_id,
            skill.candidate.root,
            skill.candidate.entrypoint,
        )
        for skill in preview.skills
    }

    result = _import_fixture_without_llm("12_duplicate_layouts", out)
    raw_manifest = (out / "import-manifest.json").read_bytes()
    manifest = json.loads(raw_manifest)
    payload_directories = [path for path in out.iterdir() if path.is_dir()]

    assert len(result.imported) == 1
    assert len(result.imported[0].candidate_ids) == 2
    assert len(payload_directories) == 1
    assert (payload_directories[0] / "assets/payload.txt").read_text(encoding="utf-8") == (
        "identical payload\n"
    )
    assert len(manifest["imported"]) == 1
    imported = manifest["imported"][0]
    assert imported["candidateIds"] == list(result.imported[0].candidate_ids)
    assert len(imported["provenance"]) == 2
    assert all(
        set(provenance) == {"candidateId", "originalRoot", "entrypoint"}
        for provenance in imported["provenance"]
    )
    actual_provenance = [
        (
            provenance["candidateId"],
            provenance["originalRoot"],
            provenance["entrypoint"],
        )
        for provenance in imported["provenance"]
    ]
    assert len(actual_provenance) == len(expected_provenance)
    assert len(set(actual_provenance)) == len(actual_provenance)
    assert set(actual_provenance) == expected_provenance
    assert {candidate_id for candidate_id, _, _ in expected_provenance} == set(
        imported["candidateIds"]
    )
    assert {(root, entrypoint) for _, root, entrypoint in expected_provenance} == {
        ("layout-a/tool", "layout-a/tool/SKILL.md"),
        (
            "marketplace/packages/tool",
            "marketplace/packages/tool/SKILL.md",
        ),
    }
    canonical_url = source.resolve().as_uri()
    assert manifest["source"]["canonicalSourceUrl"] == canonical_url
    assert raw_manifest.count(canonical_url.encode()) == 1


def test_github_blob_fixture_seeds_repository_context_for_later_e2e() -> None:
    source = _fixture_source("13_github_blob")
    expected_files = {
        "packages/demo/.claude-plugin/plugin.json",
        "packages/demo/src/runtime.py",
        "packages/demo/skills/blob-skill/SKILL.md",
        "packages/demo/skills/blob-skill/assets/data.txt",
        "packages/demo/skills/blob-skill/references/guide.md",
        "packages/demo/skills/other/SKILL.md",
    }

    assert {
        path.relative_to(source).as_posix() for path in source.rglob("*") if path.is_file()
    } == expected_files
