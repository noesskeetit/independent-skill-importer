"""Offline end-to-end proofs for real Git and normalized GitHub sources."""

from __future__ import annotations

import json
import re
import shutil
from collections.abc import Mapping
from pathlib import Path
from typing import Never

import pytest
from fixture_factory import (
    LocalMirrorGitRunner,
    create_bare_repository,
    create_git_repository,
    run_git,
)

from skill_importer.importer import SkillImporter
from skill_importer.limits import Limits
from skill_importer.models import Classification, ReasonCode
from skill_importer.pipeline import ScanOptions, SkillImporterPipeline
from skill_importer.source import SourceResolver, parse_source_spec

FIXTURES = Path(__file__).parent / "fixtures"
GITHUB_CANONICAL_URL = "https://github.com/acme/repo.git"
GITHUB_BLOB_ROOT = "packages/demo/skills/blob-skill"
GITHUB_BLOB_URL = "https://github.com/acme/repo/blob/main/packages/demo/skills/blob-skill/SKILL.md"


def _skill(name: str, body: str = "Self-contained.\n") -> str:
    return f"---\nname: {name}\ndescription: remote E2E skill\n---\n{body}"


def _forbid_api_key_read() -> Never:
    raise AssertionError("a statically decided candidate must not read the FM API key")


def _forbid_fm_transport(_limits: Limits) -> Never:
    raise AssertionError("a statically decided candidate must not construct an FM transport")


def _offline_pipeline(remote_url: str, bare_repository: Path) -> SkillImporterPipeline:
    limits = Limits()
    resolver = SourceResolver(
        limits=limits,
        git_runner=LocalMirrorGitRunner(remote_url, bare_repository),
    )
    return SkillImporterPipeline(
        limits=limits,
        resolver=resolver,
        api_key_provider=_forbid_api_key_read,
    )


def _github_repository(tmp_path: Path) -> tuple[Path, str, str]:
    worktree = tmp_path / "github-worktree"
    shutil.copytree(FIXTURES / "13_github_blob", worktree)
    run_git(worktree, ["init", "--initial-branch=main"])
    run_git(worktree, ["add", "--all"])
    run_git(worktree, ["commit", "-m", "main fixture"])
    main_sha = run_git(worktree, ["rev-parse", "HEAD"])

    run_git(worktree, ["checkout", "-b", "bound"])
    (worktree / "packages/demo/src/runtime.py").write_text(
        'runSkill("blob-skill")\n',
        encoding="utf-8",
    )
    run_git(worktree, ["add", "packages/demo/src/runtime.py"])
    run_git(worktree, ["commit", "-m", "bind skill to runtime"])
    bound_sha = run_git(worktree, ["rev-parse", "HEAD"])
    run_git(worktree, ["checkout", "main"])

    return create_bare_repository(worktree, tmp_path / "github-remote.git"), main_sha, bound_sha


class _PortableFmTransport:
    """Return a strict response bound to the prompt hash and real source evidence."""

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
                    "path": f"{GITHUB_BLOB_ROOT}/SKILL.md",
                    "line": 5,
                    "value": "Read the [guide](references/guide.md).",
                }
            ],
            "rationale": "Every referenced resource is inside the selected skill root.",
        }
        completion = json.dumps(payload, separators=(",", ":"))
        return json.dumps(
            {"choices": [{"message": {"role": "assistant", "content": completion}}]},
            separators=(",", ":"),
        ).encode()


def test_local_bare_git_named_ref_scan_then_import_preserves_exact_sha(
    tmp_path: Path,
) -> None:
    worktree = tmp_path / "git-worktree"
    create_git_repository(
        worktree,
        {
            "tool/SKILL.md": _skill("release-tool"),
            "tool/assets/version.txt": "main\n",
        },
    )
    run_git(worktree, ["checkout", "-b", "release"])
    (worktree / "tool/assets/version.txt").write_text("release\n", encoding="utf-8")
    run_git(worktree, ["add", "tool/assets/version.txt"])
    run_git(worktree, ["commit", "-m", "release fixture"])
    release_sha = run_git(worktree, ["rev-parse", "HEAD"])
    bare = create_bare_repository(worktree, tmp_path / "remote.git")
    remote_url = "https://git.example.invalid/acme/repo.git"
    pipeline = _offline_pipeline(remote_url, bare)
    spec = parse_source_spec(remote_url, ref="release", subpath=None)

    preview = pipeline.scan(spec, ScanOptions(use_llm=False))

    assert re.fullmatch(r"[0-9a-f]{40}", release_sha)
    assert preview.source.resolved_commit_sha == release_sha
    assert preview.source.canonical_url == remote_url
    assert [skill.classification for skill in preview.skills] == [Classification.PORTABLE]

    out = tmp_path / "out"
    result = SkillImporter(pipeline=pipeline).import_source(
        spec,
        out,
        ScanOptions(use_llm=False),
    )
    manifest = json.loads((out / "import-manifest.json").read_text(encoding="utf-8"))
    payload = out / result.imported[0].destination

    assert len(result.imported) == 1
    assert (payload / "assets/version.txt").read_text(encoding="utf-8") == "release\n"
    assert manifest["source"]["canonicalSourceUrl"] == remote_url
    assert manifest["source"]["resolvedCommitSha"] == release_sha
    assert manifest["imported"][0]["provenance"][0]["originalRoot"] == "tool"


@pytest.mark.parametrize(
    ("source_url", "expected_scope", "expected_roots"),
    [
        (
            "https://github.com/acme/repo",
            ".",
            (
                "packages/demo/skills/blob-skill",
                "packages/demo/skills/other",
            ),
        ),
        (
            "https://github.com/acme/repo/tree/main/packages/demo/skills/blob-skill",
            GITHUB_BLOB_ROOT,
            (GITHUB_BLOB_ROOT,),
        ),
        (GITHUB_BLOB_URL, GITHUB_BLOB_ROOT, (GITHUB_BLOB_ROOT,)),
    ],
)
def test_fake_github_repository_tree_and_blob_urls_have_expected_scope(
    source_url: str,
    expected_scope: str,
    expected_roots: tuple[str, ...],
    tmp_path: Path,
) -> None:
    bare, main_sha, _ = _github_repository(tmp_path)
    pipeline = _offline_pipeline(GITHUB_CANONICAL_URL, bare)
    spec = parse_source_spec(
        source_url, ref="main" if expected_scope == "." else None, subpath=None
    )

    report = pipeline.scan(spec, ScanOptions(use_llm=False))

    assert report.source.canonical_url == GITHUB_CANONICAL_URL
    assert report.source.resolved_commit_sha == main_sha
    assert report.source.discovery_scope == expected_scope
    assert tuple(skill.candidate.root for skill in report.skills) == expected_roots
    assert all(skill.classification is Classification.AMBIGUOUS for skill in report.skills)


def test_github_blob_bound_branch_is_plugin_bound_without_fm(tmp_path: Path) -> None:
    bare, _, bound_sha = _github_repository(tmp_path)
    limits = Limits()
    pipeline = SkillImporterPipeline(
        limits=limits,
        resolver=SourceResolver(
            limits=limits,
            git_runner=LocalMirrorGitRunner(GITHUB_CANONICAL_URL, bare),
        ),
        fm_transport_factory=_forbid_fm_transport,
        api_key_provider=_forbid_api_key_read,
    )
    spec = parse_source_spec(GITHUB_BLOB_URL, ref="bound", subpath=None)

    with pipeline.scan_operation(spec, ScanOptions(use_llm=True)) as operation:
        report = operation.report
        inventory_paths = set(operation.inventory.by_path)

    assert report.source.resolved_commit_sha == bound_sha
    assert report.source.discovery_scope == GITHUB_BLOB_ROOT
    assert inventory_paths >= {
        "packages/demo/.claude-plugin/plugin.json",
        "packages/demo/src/runtime.py",
        "packages/demo/skills/other/SKILL.md",
    }
    assert len(report.skills) == 1
    skill = report.skills[0]
    assert skill.candidate.root == GITHUB_BLOB_ROOT
    assert skill.classification is Classification.PLUGIN_BOUND
    assert skill.analysis_method == "static"
    assert skill.fm_review is None
    reason = next(
        reason for reason in skill.reasons if reason.code is ReasonCode.REFERENCED_BY_PLUGIN_RUNTIME
    )
    assert any(evidence.path == "packages/demo/src/runtime.py" for evidence in reason.evidence)
    assert any("blob-skill" in evidence.value for evidence in reason.evidence)


def test_github_blob_main_scan_then_import_copies_whole_parent_only(tmp_path: Path) -> None:
    bare, main_sha, _ = _github_repository(tmp_path)
    limits = Limits()
    transport = _PortableFmTransport()
    pipeline = SkillImporterPipeline(
        limits=limits,
        resolver=SourceResolver(
            limits=limits,
            git_runner=LocalMirrorGitRunner(GITHUB_CANONICAL_URL, bare),
        ),
        fm_transport_factory=lambda _limits: transport,
        api_key_provider=lambda: "offline-test-key",
    )
    spec = parse_source_spec(GITHUB_BLOB_URL, ref=None, subpath=None)

    preview = pipeline.scan(spec, ScanOptions(use_llm=True))

    assert preview.source.resolved_commit_sha == main_sha
    assert preview.source.discovery_scope == GITHUB_BLOB_ROOT
    assert len(preview.skills) == 1
    assert preview.skills[0].static_classification is Classification.AMBIGUOUS
    assert preview.skills[0].classification is Classification.PORTABLE
    assert preview.skills[0].analysis_method == "static+fm"

    out = tmp_path / "out"
    result = SkillImporter(pipeline=pipeline).import_source(
        spec,
        out,
        ScanOptions(use_llm=True),
    )
    payload = out / result.imported[0].destination
    copied_files = {
        path.relative_to(payload).as_posix() for path in payload.rglob("*") if path.is_file()
    }
    manifest = json.loads((out / "import-manifest.json").read_text(encoding="utf-8"))

    assert transport.calls == 2
    assert copied_files == {
        "SKILL.md",
        "assets/data.txt",
        "references/guide.md",
    }
    assert not (payload / "src/runtime.py").exists()
    assert not (payload / ".claude-plugin/plugin.json").exists()
    assert not (payload / "skills/other/SKILL.md").exists()
    assert manifest["source"]["canonicalSourceUrl"] == GITHUB_CANONICAL_URL
    assert manifest["source"]["resolvedCommitSha"] == main_sha
    assert manifest["imported"][0]["provenance"] == [
        {
            "candidateId": result.imported[0].candidate_ids[0],
            "originalRoot": GITHUB_BLOB_ROOT,
            "entrypoint": f"{GITHUB_BLOB_ROOT}/SKILL.md",
        }
    ]
