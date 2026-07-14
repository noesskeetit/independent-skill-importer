"""Scan-pipeline orchestration, identity, and grouping tests."""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from pathlib import Path

import pytest
from fixture_factory import write_tree

import skill_importer.pipeline as pipeline_module
from skill_importer.errors import ImporterError
from skill_importer.limits import Limits
from skill_importer.models import (
    Classification,
    Inventory,
    InventoryEntry,
    ReasonCode,
    ResolvedSource,
    SkillCandidate,
    SourceSpec,
    build_candidate_id,
)
from skill_importer.pipeline import (
    ScanOptions,
    SkillImporterPipeline,
    compute_skill_content_hash,
)


def _skill(name: str, description: str = "test skill", body: str = "Self-contained.\n") -> str:
    return f"---\nname: {name}\ndescription: {description}\n---\n{body}"


def _scan(
    source: Path,
    *,
    use_llm: bool = False,
    pipeline: SkillImporterPipeline | None = None,
    subpath: str | None = None,
):
    importer = pipeline or SkillImporterPipeline(api_key_provider=lambda: None)
    return importer.scan(SourceSpec.local(source, subpath=subpath), ScanOptions(use_llm=use_llm))


class _CountingTransport:
    def __init__(self) -> None:
        self.calls = 0
        self.authorizations: list[str | None] = []

    def send(
        self,
        endpoint: str,
        headers: Mapping[str, str],
        request: Mapping[str, object],
        *,
        timeout_seconds: int,
    ) -> bytes:
        del endpoint, request, timeout_seconds
        self.calls += 1
        self.authorizations.append(headers.get("Authorization"))
        return b"{}"


def _mixed_tree(root: Path, *, skill_count: int = 1) -> None:
    files = {
        "plugin.json": '{"name":"mixed"}',
        "src/runtime.py": "def activate():\n    return None\n",
    }
    for index in range(skill_count):
        files[f"skills/skill-{index}/SKILL.md"] = _skill(f"skill-{index}")
    write_tree(root, files)


def test_scan_pipeline_keeps_snapshot_alive_only_inside_operation(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    write_tree(source, {"nested/SKILL.md": _skill("nested")})
    pipeline = SkillImporterPipeline(api_key_provider=lambda: None)

    with pipeline.scan_operation(SourceSpec.local(source), ScanOptions(use_llm=False)) as operation:
        snapshot = operation.resolved.snapshot_root
        assert snapshot.is_dir()
        assert operation.inventory.by_path["nested/SKILL.md"].kind == "file"
        assert operation.report.skills[0].classification is Classification.PORTABLE

    assert not snapshot.exists()


def test_public_scan_returns_report_after_workspace_cleanup(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    write_tree(source, {"SKILL.md": _skill("root")})

    report = _scan(source)

    assert not report.source.snapshot_root.exists()
    assert "snapshotRoot" not in report.to_dict()["source"]


def test_scan_workspace_is_cleaned_when_a_stage_fails(tmp_path: Path) -> None:
    workspaces: list[Path] = []

    class FailingResolver:
        def resolve(self, spec: SourceSpec, workspace: Path) -> ResolvedSource:
            del spec
            workspaces.append(workspace)
            (workspace / "created-before-error").mkdir()
            raise ImporterError("TEST_FAILURE", "controlled test failure")

    pipeline = SkillImporterPipeline(resolver=FailingResolver(), api_key_provider=lambda: None)

    with pytest.raises(ImporterError, match="TEST_FAILURE"):
        pipeline.scan(SourceSpec.local(tmp_path), ScanOptions(use_llm=False))

    assert len(workspaces) == 1
    assert not workspaces[0].exists()


def test_invalid_frontmatter_does_not_abort_valid_sibling(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    write_tree(
        source,
        {
            "00-invalid/SKILL.md": "---\nname: [broken\n---\n",
            "10-valid/SKILL.md": _skill("valid"),
        },
    )

    report = _scan(source)

    assert [skill.classification for skill in report.skills] == [
        Classification.INVALID,
        Classification.PORTABLE,
    ]
    assert report.counts["total"] == 2


def test_scan_rejects_excess_candidates_before_analysis(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    write_tree(
        source,
        {
            "skills/one/SKILL.md": _skill("one"),
            "skills/two/SKILL.md": _skill("two"),
        },
    )
    pipeline = SkillImporterPipeline(
        limits=Limits(max_candidates=1),
        api_key_provider=lambda: None,
    )

    def forbidden_analysis(*args: object, **kwargs: object) -> object:
        del args, kwargs
        raise AssertionError("candidate limit must be enforced before analysis")

    monkeypatch.setattr(pipeline, "_analyze_candidates", forbidden_analysis)

    with pytest.raises(ImporterError) as captured:
        pipeline.scan(SourceSpec.local(source), ScanOptions(use_llm=False))

    assert captured.value.code == "SCAN_LIMIT_EXCEEDED"
    assert "candidate" in captured.value.message


def test_symlink_entrypoint_escaping_skill_root_is_discovered_and_blocked(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    (source / "skill").mkdir(parents=True)
    (source / "outside").mkdir()
    (source / "outside/real.md").write_text(_skill("outside"), encoding="utf-8")
    (source / "skill/SKILL.md").symlink_to("../outside/real.md")

    report = _scan(source)

    assert report.counts == {
        "total": 1,
        "portable": 0,
        "plugin_bound": 0,
        "ambiguous": 0,
        "invalid": 0,
        "blocked": 1,
    }
    skill = report.skills[0]
    assert skill.candidate.root == "skill"
    assert skill.classification is Classification.BLOCKED
    assert {ReasonCode.INVALID_FRONTMATTER, ReasonCode.SYMLINK_ESCAPE} <= skill.reason_codes
    reason = next(item for item in skill.reasons if item.code is ReasonCode.SYMLINK_ESCAPE)
    assert reason.evidence[0].path == "skill/SKILL.md"
    assert reason.evidence[0].field == "symlinkTarget"


def test_metadata_only_root_plugin_skill_imports_its_local_script(tmp_path: Path) -> None:
    from skill_importer.importer import SkillImporter

    source = tmp_path / "source"
    source.mkdir()
    write_tree(
        source,
        {
            "plugin.json": '{"name":"metadata-only"}',
            "SKILL.md": _skill("root", body="Run `scripts/tool.sh`.\n"),
            "scripts/tool.sh": "#!/bin/sh\nexit 0\n",
        },
    )
    out = tmp_path / "out"
    pipeline = SkillImporterPipeline(api_key_provider=lambda: None)

    result = SkillImporter(pipeline=pipeline).import_source(
        SourceSpec.local(source),
        out,
        ScanOptions(use_llm=False),
    )

    assert len(result.imported) == 1
    payloads = [path for path in out.iterdir() if path.is_dir()]
    assert len(payloads) == 1
    assert (payloads[0] / "scripts/tool.sh").read_text(encoding="utf-8") == ("#!/bin/sh\nexit 0\n")


def test_subpath_limits_discovery_but_reverse_analysis_uses_full_inventory(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    write_tree(
        source,
        {
            "plugin.json": '{"name":"mixed"}',
            "src/runtime.py": 'SKILL_PATH = "skills/alpha"\n',
            "skills/alpha/SKILL.md": _skill("alpha"),
            "skills/beta/SKILL.md": _skill("beta"),
        },
    )

    report = _scan(source, subpath="skills/alpha")

    assert [skill.candidate.root for skill in report.skills] == ["skills/alpha"]
    assert report.skills[0].classification is Classification.PLUGIN_BOUND
    assert ReasonCode.REFERENCED_BY_PLUGIN_RUNTIME in report.skills[0].reason_codes


def test_default_missing_key_records_fail_closed_fm_reason_without_network(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    _mixed_tree(source)

    class NoNetworkTransport(_CountingTransport):
        def send(self, *args: object, **kwargs: object) -> bytes:
            raise AssertionError("transport must not be called without an API key")

    pipeline = SkillImporterPipeline(
        fm_transport_factory=lambda limits: NoNetworkTransport(),
        api_key_provider=lambda: None,
    )

    report = pipeline.scan(SourceSpec.local(source))

    skill = report.skills[0]
    assert skill.classification is Classification.AMBIGUOUS
    assert skill.analysis_method == "static+fm"
    assert ReasonCode.FM_REVIEW_UNAVAILABLE in skill.reason_codes


@pytest.mark.parametrize(
    ("primary_key", "expected_key"),
    [("primary-test-key", "primary-test-key"), (None, "legacy-test-key")],
)
def test_default_key_provider_uses_documented_precedence(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    primary_key: str | None,
    expected_key: str,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    _mixed_tree(source)
    if primary_key is None:
        monkeypatch.delenv("FM_API_KEY", raising=False)
    else:
        monkeypatch.setenv("FM_API_KEY", primary_key)
    monkeypatch.setenv("LLM_API_KEY", "legacy-test-key")
    transport = _CountingTransport()

    pipeline = SkillImporterPipeline(
        fm_transport_factory=lambda limits: transport,
    )

    pipeline.scan(SourceSpec.local(source))

    assert transport.authorizations == [f"Bearer {expected_key}"]


@pytest.mark.parametrize("primary_key", ["", "bad\r\nInjected: yes"])
def test_explicit_invalid_fm_api_key_does_not_fall_back_to_legacy_key(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    primary_key: str,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    _mixed_tree(source)
    monkeypatch.setenv("FM_API_KEY", primary_key)
    monkeypatch.setenv("LLM_API_KEY", "legacy-test-key")

    transport = _CountingTransport()
    pipeline = SkillImporterPipeline(
        fm_transport_factory=lambda limits: transport,
    )

    skill = pipeline.scan(SourceSpec.local(source)).skills[0]

    assert skill.classification is Classification.AMBIGUOUS
    assert ReasonCode.FM_REVIEW_UNAVAILABLE in skill.reason_codes
    assert transport.calls == 0


def test_no_llm_keeps_static_ambiguity_and_does_not_read_key(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    _mixed_tree(source)

    def forbidden_key_provider() -> str:
        raise AssertionError("--no-llm must not read the FM key")

    pipeline = SkillImporterPipeline(api_key_provider=forbidden_key_provider)
    report = pipeline.scan(SourceSpec.local(source), ScanOptions(use_llm=False))

    skill = report.skills[0]
    assert skill.classification is Classification.AMBIGUOUS
    assert skill.analysis_method == "static"
    assert not any(code.value.startswith("FM_") for code in skill.reason_codes)


def test_fm_transport_is_used_only_for_ambiguous_candidates(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    write_tree(
        source,
        {
            "standalone/SKILL.md": _skill("standalone"),
            "plugins/mixed/plugin.json": '{"name":"mixed"}',
            "plugins/mixed/src/runtime.py": "def activate():\n    return None\n",
            "plugins/mixed/skills/alpha/SKILL.md": _skill("alpha"),
        },
    )
    transport = _CountingTransport()
    pipeline = SkillImporterPipeline(
        fm_transport_factory=lambda limits: transport,
        api_key_provider=lambda: "test-key",
    )

    report = pipeline.scan(SourceSpec.local(source))

    assert transport.calls == 1
    assert {skill.static_classification for skill in report.skills} == {
        Classification.PORTABLE,
        Classification.AMBIGUOUS,
    }


def test_residual_static_ambiguity_is_dispatched_to_fm_review(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    write_tree(
        source,
        {
            "runtime/tool.rb": "puts :runtime\n",
            "skills/x/SKILL.md": _skill("x"),
            "skills/x/scripts/run.rb": (
                'target = "../../../runtime/tool.rb"\nloader.call(target)\n'
            ),
        },
    )
    transport = _CountingTransport()
    pipeline = SkillImporterPipeline(
        fm_transport_factory=lambda limits: transport,
        api_key_provider=lambda: "test-key",
    )

    skill = pipeline.scan(
        SourceSpec.local(source),
        ScanOptions(use_llm=True),
    ).skills[0]

    assert transport.calls == 1
    assert skill.static_classification is Classification.AMBIGUOUS
    assert skill.analysis_method == "static+fm"
    assert ReasonCode.STATIC_ANALYSIS_INCOMPLETE in skill.reason_codes


def test_mixed_plugin_whose_root_is_the_skill_is_plugin_bound_without_fm(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    write_tree(
        source,
        {
            "SKILL.md": _skill("root-skill"),
            "plugin.json": '{"name":"mixed"}',
            "src/runtime.py": "def activate():\n    return None\n",
        },
    )
    transport = _CountingTransport()
    pipeline = SkillImporterPipeline(
        fm_transport_factory=lambda limits: transport,
        api_key_provider=lambda: "test-key",
    )

    skill = pipeline.scan(SourceSpec.local(source)).skills[0]

    assert skill.classification is Classification.PLUGIN_BOUND
    assert ReasonCode.PLUGIN_RUNTIME_INSIDE_SKILL_ROOT in skill.reason_codes
    assert transport.calls == 0


def test_skills_only_plugin_whose_root_is_the_skill_remains_portable(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    write_tree(
        source,
        {
            "SKILL.md": _skill("root-skill"),
            "plugin.json": '{"name":"skills-only"}',
            "README.md": "distribution metadata\n",
        },
    )

    skill = _scan(source).skills[0]

    assert skill.classification is Classification.PORTABLE
    assert ReasonCode.SKILLS_ONLY_PACKAGE in skill.reason_codes


def test_mixed_plugin_nested_inside_skill_payload_is_plugin_bound(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    write_tree(
        source,
        {
            "SKILL.md": _skill("outer-skill"),
            "plugins/acme/plugin.json": '{"name":"mixed"}',
            "plugins/acme/src/runtime.py": "def activate():\n    return None\n",
        },
    )

    skill = _scan(source).skills[0]

    assert skill.candidate.enclosing_boundary is None
    assert skill.classification is Classification.PLUGIN_BOUND
    assert ReasonCode.PLUGIN_RUNTIME_INSIDE_SKILL_ROOT in skill.reason_codes


def test_fm_quota_is_shared_within_scan_and_reset_for_next_scan(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    _mixed_tree(source, skill_count=2)
    transport = _CountingTransport()
    pipeline = SkillImporterPipeline(
        limits=Limits(max_fm_reviews=1),
        fm_transport_factory=lambda limits: transport,
        api_key_provider=lambda: "test-key",
    )

    first = pipeline.scan(SourceSpec.local(source))
    second = pipeline.scan(SourceSpec.local(source))

    assert transport.calls == 2
    assert (
        sum(ReasonCode.FM_REVIEW_UNAVAILABLE in skill.reason_codes for skill in first.skills) == 1
    )
    assert (
        sum(ReasonCode.FM_REVIEW_UNAVAILABLE in skill.reason_codes for skill in second.skills) == 1
    )


def _hash_source(
    tmp_path: Path,
    root: str,
    entries: tuple[InventoryEntry, ...],
) -> str:
    source = ResolvedSource(
        spec=SourceSpec.local(tmp_path),
        canonical_url=tmp_path.as_uri(),
        snapshot_root=tmp_path.resolve(),
        snapshot_sha256="a" * 64,
        discovery_scope=".",
    )
    entrypoint = f"{root}/SKILL.md" if root != "." else "SKILL.md"
    candidate = SkillCandidate(
        candidate_id=build_candidate_id(source, root),
        source=source,
        root=root,
        entrypoint=entrypoint,
        enclosing_boundary=None,
    )
    return compute_skill_content_hash(candidate, Inventory(entries=entries))


def _file(path: str, content: bytes, *, executable: bool = False) -> InventoryEntry:
    return InventoryEntry(
        path=path,
        kind="file",
        size=len(content),
        executable=executable,
        sha256=hashlib.sha256(content).hexdigest(),
        content=content.decode("utf-8", errors="ignore") if b"\x00" not in content else None,
    )


def test_content_hash_is_layout_independent_and_excludes_skill_root_marker(tmp_path: Path) -> None:
    left = (
        InventoryEntry(path="dist/alpha", kind="directory", size=0),
        _file("dist/alpha/SKILL.md", b"same"),
        InventoryEntry(path="dist/alpha/empty", kind="directory", size=0),
    )
    right = (
        InventoryEntry(path="vendor/copy", kind="directory", size=0),
        _file("vendor/copy/SKILL.md", b"same"),
        InventoryEntry(path="vendor/copy/empty", kind="directory", size=0),
    )

    assert _hash_source(tmp_path, "dist/alpha", left) == _hash_source(
        tmp_path, "vendor/copy", right
    )


@pytest.mark.parametrize(
    "change",
    ["bytes", "executable", "binary", "path", "symlink-target", "empty-directory"],
)
def test_content_hash_changes_with_each_payload_semantic(change: str, tmp_path: Path) -> None:
    baseline = (
        _file("skill/SKILL.md", b"same"),
        _file("skill/asset.txt", b"asset"),
        InventoryEntry(path="skill/link", kind="symlink", size=8, symlink_target="asset-v1"),
        InventoryEntry(path="skill/empty", kind="directory", size=0),
    )
    changed = list(baseline)
    if change == "bytes":
        changed[0] = _file("skill/SKILL.md", b"different")
    elif change == "executable":
        changed[0] = _file("skill/SKILL.md", b"same", executable=True)
    elif change == "binary":
        changed[1] = _file("skill/asset.txt", b"\x00asset")
    elif change == "path":
        changed[1] = _file("skill/renamed.txt", b"asset")
    elif change == "symlink-target":
        changed[2] = InventoryEntry(
            path="skill/link", kind="symlink", size=8, symlink_target="asset-v2"
        )
    else:
        changed.pop()

    assert _hash_source(tmp_path, "skill", baseline) != _hash_source(
        tmp_path, "skill", tuple(changed)
    )


def test_content_hash_depends_on_bytes_not_text_decoding_metadata(tmp_path: Path) -> None:
    raw = b"same bytes"
    text_entry = _file("skill/SKILL.md", raw)
    binary_view = InventoryEntry(
        path="skill/SKILL.md",
        kind="file",
        size=len(raw),
        sha256=hashlib.sha256(raw).hexdigest(),
        content=None,
    )

    assert _hash_source(tmp_path, "skill", (text_entry,)) == _hash_source(
        tmp_path, "skill", (binary_view,)
    )


def test_scan_keeps_same_name_duplicates_and_annotates_both_groups(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    skill_text = _skill("same-name")
    write_tree(
        source,
        {
            "layout-a/tool/SKILL.md": skill_text,
            "layout-b/tool/SKILL.md": skill_text,
        },
    )

    report = _scan(source)

    assert len(report.skills) == 2
    assert len({skill.candidate_id for skill in report.skills}) == 2
    assert len(report.duplicates) == 1
    assert len(report.name_conflicts) == 1
    duplicate = report.duplicates[0]
    conflict = report.name_conflicts[0]
    assert duplicate.candidate_ids == tuple(sorted(skill.candidate_id for skill in report.skills))
    assert conflict.candidate_ids == duplicate.candidate_ids
    assert all(skill.duplicate_group == duplicate.group_id for skill in report.skills)
    assert all(skill.name_conflict_group == conflict.group_id for skill in report.skills)
    assert all(ReasonCode.DUPLICATE_CONTENT in skill.reason_codes for skill in report.skills)
    assert all(ReasonCode.NAME_CONFLICT in skill.reason_codes for skill in report.skills)
    assert all(
        evidence.line is None
        for skill in report.skills
        for reason in skill.reasons
        if reason.code in {ReasonCode.DUPLICATE_CONTENT, ReasonCode.NAME_CONFLICT}
        for evidence in reason.evidence
    )
    assert all(skill.classification is Classification.PORTABLE for skill in report.skills)


def test_same_name_with_different_content_is_conflict_not_duplicate(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    write_tree(
        source,
        {
            "one/SKILL.md": _skill("same-name", body="one\n"),
            "two/SKILL.md": _skill("same-name", body="two\n"),
        },
    )

    report = _scan(source)

    assert report.duplicates == ()
    assert len(report.name_conflicts) == 1


def test_validation_warning_is_merged_into_decision_reasons(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    synthetic_inventory = Inventory(
        entries=(
            InventoryEntry(path="tool", kind="directory", size=0),
            _file("tool/SKILL.md", _skill("canonical").encode()),
            _file("tool/skill.md", _skill("compatibility").encode()),
        )
    )
    monkeypatch.setattr(
        pipeline_module,
        "build_inventory",
        lambda resolved, limits: synthetic_inventory,
    )

    skill = _scan(source).skills[0]

    assert skill.name == "canonical"
    assert ReasonCode.DUPLICATE_ENTRYPOINT in skill.reason_codes


@pytest.mark.parametrize(
    "model",
    ["", " ", "bad\nmodel", "bad\u202emodel", "x" * 257],
)
def test_scan_options_reject_unbounded_or_controlled_model(model: str) -> None:
    with pytest.raises(ValueError, match="model"):
        ScanOptions(model=model)


def test_pipeline_does_not_read_fm_key_when_no_candidate_is_ambiguous(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    write_tree(source, {"SKILL.md": _skill("standalone")})

    def forbidden_key_provider() -> str:
        raise AssertionError("key provider is only needed for ambiguous candidates")

    report = SkillImporterPipeline(api_key_provider=forbidden_key_provider).scan(
        SourceSpec.local(source)
    )

    assert report.skills[0].classification is Classification.PORTABLE
