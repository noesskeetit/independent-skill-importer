"""Import planning, no-follow copy, and atomic publication tests."""

from __future__ import annotations

import errno
import json
import os
import shutil
import stat
import sys
from collections.abc import Callable, Iterator
from contextlib import contextmanager, suppress
from dataclasses import replace
from pathlib import Path

import pytest
from fixture_factory import write_tree

import skill_importer.importer as importer_module
from skill_importer.errors import ImporterError
from skill_importer.importer import (
    ImportResult,
    NativeAtomicPublisher,
    SkillImporter,
    build_import_plan,
)
from skill_importer.limits import Limits
from skill_importer.models import (
    AnalyzedSkill,
    Classification,
    DecisionReason,
    Evidence,
    InventoryEntry,
    ReasonCode,
    ResolvedSource,
    ScanReport,
    SkillCandidate,
    SourceSpec,
    build_candidate_id,
)
from skill_importer.pipeline import ScanOperation, ScanOptions, SkillImporterPipeline
from skill_importer.source import SourceResolver


def _skill(name: str, body: str = "Self-contained.\n", **extra: str) -> str:
    fields = [f"name: {name}", "description: importer test skill"]
    fields.extend(f"{key}: {value}" for key, value in extra.items())
    return "---\n" + "\n".join(fields) + "\n---\n" + body


def _scan(source: Path) -> ScanReport:
    return SkillImporterPipeline(api_key_provider=lambda: None).scan(
        SourceSpec.local(source), ScanOptions(use_llm=False)
    )


def _import(source: Path, out: Path, **kwargs: object) -> ImportResult:
    importer = SkillImporter(
        pipeline=SkillImporterPipeline(api_key_provider=lambda: None),
        **kwargs,  # type: ignore[arg-type]
    )
    return importer.import_source(SourceSpec.local(source), out, ScanOptions(use_llm=False))


class _CapturingPipeline(SkillImporterPipeline):
    operation: ScanOperation | None = None

    @contextmanager
    def scan_operation(
        self,
        spec: SourceSpec,
        options: ScanOptions | None = None,
    ) -> Iterator[ScanOperation]:
        with super().scan_operation(spec, options) as operation:
            self.operation = operation
            yield operation


def _snapshot_path(pipeline: _CapturingPipeline, entry: InventoryEntry) -> Path:
    assert pipeline.operation is not None
    return pipeline.operation.resolved.snapshot_root / entry.path


def _safe_reason(entrypoint: str) -> DecisionReason:
    return DecisionReason(
        code=ReasonCode.STANDALONE_NO_PLUGIN_BOUNDARY,
        message="standalone test override",
        evidence=(
            Evidence(
                path=entrypoint,
                line=1,
                field=None,
                value="standalone",
                detector="test.override",
            ),
        ),
    )


def test_build_import_plan_is_exact_deterministic_partition(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    write_tree(
        source,
        {
            "portable/SKILL.md": _skill("portable"),
            "invalid/SKILL.md": "---\nname: [broken\n---\n",
        },
    )
    report = _scan(source)

    first = build_import_plan(report)
    second = build_import_plan(report)

    assert first == second
    assert tuple(item.candidate_id for item in first.selected) == tuple(
        sorted(
            item.candidate_id
            for item in report.skills
            if item.classification is Classification.PORTABLE
        )
    )
    assert {item.candidate_id for item in first.rejected} == {
        item.candidate_id
        for item in report.skills
        if item.classification is not Classification.PORTABLE
    }
    assert {item.candidate_id for item in (*first.selected, *first.rejected)} == {
        item.candidate_id for item in report.skills
    }
    assert len(first.records) == 1


def test_duplicate_payload_is_one_record_with_only_portable_provenance(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    skill_text = _skill("duplicate")
    write_tree(
        source,
        {
            "a/tool/SKILL.md": skill_text,
            "b/tool/SKILL.md": skill_text,
            "c/tool/SKILL.md": skill_text,
        },
    )
    report = _scan(source)
    rejected = replace(
        report.skills[2],
        static_classification=Classification.AMBIGUOUS,
        classification=Classification.AMBIGUOUS,
    )
    report = replace(report, skills=(*report.skills[:2], rejected))

    plan = build_import_plan(report)

    assert len(plan.records) == 1
    assert plan.records[0].candidate_ids == tuple(
        sorted(skill.candidate_id for skill in report.skills[:2])
    )
    assert rejected in plan.rejected
    assert rejected.candidate_id not in plan.records[0].candidate_ids
    imported = plan.to_dict()["manifest"]["imported"]
    assert len(imported) == 1
    assert len(imported[0]["provenance"]) == 2


def test_same_name_different_content_gets_two_destinations(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    write_tree(
        source,
        {
            "one/SKILL.md": _skill("same", "one\n"),
            "two/SKILL.md": _skill("same", "two\n"),
        },
    )

    plan = build_import_plan(_scan(source))

    assert len(plan.records) == 2
    assert len({record.destination for record in plan.records}) == 2
    assert all(record.destination.startswith("same--") for record in plan.records)


def test_forced_hash_prefix_and_nfc_casefold_collision_extends_prefix(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    write_tree(
        source,
        {
            "one/SKILL.md": _skill("placeholder-one", "one\n"),
            "two/SKILL.md": _skill("placeholder-two", "two\n"),
        },
    )
    report = _scan(source)
    hashes = ("a" * 12 + "1" * 52, "a" * 12 + "2" * 52)
    names = ("Caf\u00e9", "Cafe\u0301")
    skills: list[AnalyzedSkill] = []
    for skill, content_hash, name in zip(report.skills, hashes, names, strict=True):
        validation = replace(
            skill.validation,
            name=name,
            frontmatter={"name": name, "description": "collision"},
        )
        skills.append(replace(skill, validation=validation, content_hash=content_hash))
    report = ScanReport(source=report.source, skills=tuple(skills))

    plan = build_import_plan(report)

    assert len(plan.records) == 2
    assert all(len(record.destination.rsplit("--", 1)[1]) > 12 for record in plan.records)
    assert len({record.destination.casefold() for record in plan.records}) == 2


def test_import_deduplicates_payload_and_preserves_all_provenance(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    skill_text = _skill("duplicate")
    write_tree(
        source,
        {
            "layout-a/tool/SKILL.md": skill_text,
            "layout-a/tool/assets/data.bin": "same",
            "layout-b/tool/SKILL.md": skill_text,
            "layout-b/tool/assets/data.bin": "same",
        },
    )
    out = tmp_path / "out"

    result = _import(source, out)
    manifest = json.loads((out / "import-manifest.json").read_text())

    assert len(result.imported) == 1
    assert len(result.imported[0].candidate_ids) == 2
    assert len([path for path in out.iterdir() if path.is_dir()]) == 1
    assert manifest["imported"][0]["candidateIds"] == list(result.imported[0].candidate_ids)
    assert len(manifest["imported"][0]["provenance"]) == 2


def test_import_copies_payload_bytes_empty_dirs_and_exact_modes_without_execution(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    write_tree(
        source,
        {
            "tool/SKILL.md": _skill("complete"),
            "tool/scripts/run.sh": "exit 99\n",
            "tool/assets/data.bin": b"\x00\xffbinary",
            "tool/references/info.md": "reference\n",
        },
    )
    (source / "tool/empty").mkdir()
    os.chmod(source / "tool/scripts/run.sh", 0o775)
    os.chmod(source / "tool/assets/data.bin", 0o666)
    original_skill = (source / "tool/SKILL.md").read_bytes()
    out = tmp_path / "out"

    result = _import(source, out)
    payload = out / result.imported[0].destination

    assert (payload / "SKILL.md").read_bytes() == original_skill
    assert (payload / "assets/data.bin").read_bytes() == b"\x00\xffbinary"
    assert (payload / "references/info.md").read_text() == "reference\n"
    assert (payload / "empty").is_dir()
    assert stat.S_IMODE((payload / "scripts/run.sh").stat().st_mode) == 0o700
    assert stat.S_IMODE((payload / "assets/data.bin").stat().st_mode) == 0o600
    assert stat.S_IMODE((payload / "empty").stat().st_mode) == 0o700


def test_safe_internal_symlink_and_chain_are_preserved(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    write_tree(
        source,
        {
            "tool/SKILL.md": _skill("links"),
            "tool/assets/data.txt": "data",
        },
    )
    (source / "tool/links").mkdir()
    (source / "tool/links/mid").symlink_to("../assets/data.txt")
    (source / "tool/links/top").symlink_to("mid")
    out = tmp_path / "out"

    result = _import(source, out)
    payload = out / result.imported[0].destination

    assert (payload / "links/mid").is_symlink()
    assert os.readlink(payload / "links/mid") == "../assets/data.txt"
    assert os.readlink(payload / "links/top") == "mid"
    assert (payload / "links/top").read_text() == "data"


@pytest.mark.parametrize("target", ["../../outside", "/etc/passwd", "missing"])
def test_static_unsafe_symlink_candidate_is_never_copied(target: str, tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    write_tree(source, {"tool/SKILL.md": _skill("unsafe-link")})
    (source / "tool/link").symlink_to(target)
    out = tmp_path / "out"

    result = _import(source, out)

    assert result.imported == ()
    assert len(result.skipped) == 1
    assert list(out.iterdir()) == [out / "import-manifest.json"]


@pytest.mark.parametrize(
    "mutation",
    ["escape", "absolute", "dangling", "cycle", "target-change"],
)
def test_symlink_mutation_fails_copy_and_never_publishes(mutation: str, tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    write_tree(
        source,
        {
            "tool/SKILL.md": _skill("mutating-links"),
            "tool/target.txt": "target",
        },
    )
    (source / "tool/00-link").symlink_to("10-mid")
    (source / "tool/10-mid").symlink_to("target.txt")
    pipeline = _CapturingPipeline(api_key_provider=lambda: None)
    mutated = False

    def observer(entry: InventoryEntry) -> None:
        nonlocal mutated
        if mutated or entry.path != "tool/00-link":
            return
        mutated = True
        path = _snapshot_path(pipeline, entry)
        if mutation in {"escape", "absolute", "dangling", "target-change"}:
            path.unlink()
            targets = {
                "escape": "../../outside",
                "absolute": "/etc/passwd",
                "dangling": "does-not-exist",
                "target-change": "target.txt",
            }
            path.symlink_to(targets[mutation])
        else:
            mid = path.parent / "10-mid"
            mid.unlink()
            mid.symlink_to("00-link")

    out = tmp_path / "out"
    importer = SkillImporter(pipeline=pipeline, copy_observer=observer)

    with pytest.raises(ImporterError, match="SYMLINK"):
        importer.import_source(SourceSpec.local(source), out, ScanOptions(use_llm=False))

    assert not os.path.lexists(out)
    assert not list(tmp_path.glob(".out.skill-importer-*"))


@pytest.mark.parametrize(
    "mutation",
    ["replace", "same-size-hash", "size", "mode", "hardlink", "unsupported"],
)
def test_regular_file_toctou_mutations_fail_without_output(mutation: str, tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    write_tree(
        source,
        {
            "tool/SKILL.md": _skill("mutating-file"),
            "tool/asset.txt": "original",
        },
    )
    pipeline = _CapturingPipeline(api_key_provider=lambda: None)
    mutated = False

    def observer(entry: InventoryEntry) -> None:
        nonlocal mutated
        if mutated or entry.path != "tool/asset.txt":
            return
        mutated = True
        path = _snapshot_path(pipeline, entry)
        if mutation == "replace":
            path.unlink()
            path.write_text("original")
            os.chmod(path, 0o600)
        elif mutation == "same-size-hash":
            path.write_text("ORIGINAL")
        elif mutation == "size":
            path.write_text("longer-content")
        elif mutation == "mode":
            os.chmod(path, 0o700)
        elif mutation == "hardlink":
            os.link(path, path.parent / "not-in-inventory")
        else:
            path.unlink()
            path.mkdir()

    out = tmp_path / "out"
    importer = SkillImporter(pipeline=pipeline, copy_observer=observer)

    with pytest.raises(ImporterError):
        importer.import_source(SourceSpec.local(source), out, ScanOptions(use_llm=False))

    assert not os.path.lexists(out)
    assert not list(tmp_path.glob(".out.skill-importer-*"))


def test_file_mutation_during_stream_is_detected(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    write_tree(
        source,
        {
            "tool/SKILL.md": _skill("stream-mutation"),
            "tool/asset.bin": b"a" * (256 * 1024),
        },
    )
    pipeline = _CapturingPipeline(api_key_provider=lambda: None)
    original_read = importer_module.os.read
    changed = False

    def mutating_read(file_fd: int, size: int) -> bytes:
        nonlocal changed
        chunk = original_read(file_fd, min(size, 4096))
        if not changed and pipeline.operation is not None:
            target = pipeline.operation.resolved.snapshot_root / "tool/asset.bin"
            try:
                if os.fstat(file_fd).st_ino == target.stat().st_ino and chunk:
                    changed = True
                    with target.open("r+b", buffering=0) as handle:
                        handle.seek(8192)
                        handle.write(b"b")
            except FileNotFoundError:
                pass
        return chunk

    monkeypatch.setattr(importer_module.os, "read", mutating_read)
    out = tmp_path / "out"

    with pytest.raises(ImporterError, match=r"SOURCE_CHANGED|HASH"):
        SkillImporter(pipeline=pipeline).import_source(
            SourceSpec.local(source), out, ScanOptions(use_llm=False)
        )

    assert changed
    assert not os.path.lexists(out)


def test_file_path_replacement_during_stream_is_detected(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    write_tree(
        source,
        {
            "tool/SKILL.md": _skill("path-replacement"),
            "tool/asset.bin": b"a" * (256 * 1024),
        },
    )
    pipeline = _CapturingPipeline(api_key_provider=lambda: None)
    original_read = importer_module.os.read
    replaced = False

    # Model a filesystem where rename does not change the open inode timestamps.
    monkeypatch.setattr(
        importer_module,
        "_regular_signature",
        lambda value: (
            value.st_dev,
            value.st_ino,
            value.st_size,
            value.st_mode & 0o111,
            value.st_nlink,
        ),
    )

    def replacing_read(file_fd: int, size: int) -> bytes:
        nonlocal replaced
        chunk = original_read(file_fd, min(size, 4096))
        if not replaced and pipeline.operation is not None:
            target = pipeline.operation.resolved.snapshot_root / "tool/asset.bin"
            try:
                if os.fstat(file_fd).st_ino == target.stat().st_ino and chunk:
                    replaced = True
                    target.rename(target.parent / "moved-after-open.bin")
                    target.write_bytes(b"b" * (256 * 1024))
                    os.chmod(target, 0o600)
            except FileNotFoundError:
                pass
        return chunk

    monkeypatch.setattr(importer_module.os, "read", replacing_read)
    out = tmp_path / "out"

    with pytest.raises(ImporterError, match="SOURCE_CHANGED"):
        SkillImporter(pipeline=pipeline).import_source(
            SourceSpec.local(source), out, ScanOptions(use_llm=False)
        )

    assert replaced
    assert not os.path.lexists(out)


class _SentinelBaseException(BaseException):
    pass


@pytest.mark.parametrize("failure", [OSError("ordinary"), _SentinelBaseException()])
def test_copy_failure_cleans_staging_for_exception_and_baseexception(
    failure: BaseException, tmp_path: Path
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    write_tree(source, {"SKILL.md": _skill("failure")})
    out = tmp_path / "out"

    def fail(_entry: InventoryEntry) -> None:
        raise failure

    importer = SkillImporter(
        pipeline=SkillImporterPipeline(api_key_provider=lambda: None),
        copy_observer=fail,
    )

    with (
        pytest.raises(type(failure))
        if isinstance(failure, _SentinelBaseException)
        else pytest.raises(ImporterError)
    ):
        importer.import_source(SourceSpec.local(source), out, ScanOptions(use_llm=False))

    assert not os.path.lexists(out)
    assert not list(tmp_path.glob(".out.skill-importer-*"))


def test_cleanup_failure_does_not_mask_original_baseexception(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    write_tree(source, {"SKILL.md": _skill("failure")})
    out = tmp_path / "out"

    def fail_copy(_entry: InventoryEntry) -> None:
        raise _SentinelBaseException()

    def fail_cleanup(*_args: object, **_kwargs: object) -> None:
        raise OSError("cleanup failed")

    monkeypatch.setattr(importer_module, "_cleanup_staging", fail_cleanup)

    with pytest.raises(_SentinelBaseException):
        SkillImporter(
            pipeline=SkillImporterPipeline(api_key_provider=lambda: None),
            copy_observer=fail_copy,
        ).import_source(SourceSpec.local(source), out, ScanOptions(use_llm=False))

    assert not os.path.lexists(out)


def test_cleanup_aborts_on_unexpected_entry_and_preserves_primary_exception(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    write_tree(source, {"SKILL.md": _skill("unexpected-cleanup")})
    out = tmp_path / "out"
    captured_staging: Path | None = None

    def add_unexpected(staging: Path) -> None:
        nonlocal captured_staging
        captured_staging = staging
        (staging / "competitor-marker").write_text("keep")
        raise _SentinelBaseException()

    with pytest.raises(_SentinelBaseException):
        _import(source, out, before_publish=add_unexpected)

    assert captured_staging is not None
    assert (captured_staging / "competitor-marker").read_text() == "keep"
    assert stat.S_IMODE(captured_staging.stat().st_mode) == 0o700
    assert not os.path.lexists(out)


def test_cleanup_aborts_when_a_ledger_entry_is_missing(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    write_tree(source, {"SKILL.md": _skill("missing-cleanup")})
    out = tmp_path / "out"
    captured_staging: Path | None = None

    def remove_manifest(staging: Path) -> None:
        nonlocal captured_staging
        captured_staging = staging
        (staging / "import-manifest.json").unlink()
        raise _SentinelBaseException()

    with pytest.raises(_SentinelBaseException):
        _import(source, out, before_publish=remove_manifest)

    assert captured_staging is not None
    assert captured_staging.is_dir()
    assert not os.path.lexists(out)


def test_cleanup_directory_replacement_between_lstat_and_open_is_preserved(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    write_tree(source, {"SKILL.md": _skill("cleanup-swap")})
    out = tmp_path / "out"
    original_open = importer_module.os.open
    cleanup_phase = False
    swapped = False
    captured_staging: Path | None = None
    payload_name: str | None = None

    def begin_cleanup(staging: Path) -> None:
        nonlocal cleanup_phase, captured_staging, payload_name
        captured_staging = staging
        payload = next(path for path in staging.iterdir() if path.is_dir())
        payload_name = payload.name
        cleanup_phase = True
        raise _SentinelBaseException()

    def swapping_open(path: object, flags: int, *args: object, **kwargs: object) -> int:
        nonlocal swapped
        if cleanup_phase and not swapped and path == payload_name:
            assert captured_staging is not None
            assert payload_name is not None
            swapped = True
            payload = captured_staging / payload_name
            shutil.rmtree(payload)
            payload.mkdir(mode=0o700)
            (payload / "competitor-marker").write_text("keep")
        return original_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(importer_module.os, "open", swapping_open)

    with pytest.raises(_SentinelBaseException):
        _import(source, out, before_publish=begin_cleanup)

    assert swapped
    assert captured_staging is not None
    assert payload_name is not None
    assert (captured_staging / payload_name / "competitor-marker").read_text() == "keep"
    assert not os.path.lexists(out)


def test_cleanup_top_level_replacement_is_preserved(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    write_tree(source, {"SKILL.md": _skill("top-level-swap")})
    out = tmp_path / "out"
    captured_staging: Path | None = None

    def replace_staging(staging: Path) -> None:
        nonlocal captured_staging
        captured_staging = staging
        shutil.rmtree(staging)
        staging.mkdir(mode=0o700)
        (staging / "competitor-marker").write_text("keep")
        raise _SentinelBaseException()

    with pytest.raises(_SentinelBaseException):
        _import(source, out, before_publish=replace_staging)

    assert captured_staging is not None
    assert (captured_staging / "competitor-marker").read_text() == "keep"
    assert not os.path.lexists(out)


def test_manifest_create_race_never_adopts_or_deletes_replacement(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    output = importer_module._prepare_output(tmp_path / "out")
    staging = importer_module._create_staging(output)
    original_stat = importer_module.os.stat
    swapped = False

    def swapping_stat(path: object, *args: object, **kwargs: object) -> os.stat_result:
        nonlocal swapped
        if path == "import-manifest.json" and not swapped:
            swapped = True
            directory_fd = kwargs["dir_fd"]
            assert isinstance(directory_fd, int)
            os.unlink("import-manifest.json", dir_fd=directory_fd)
            competitor_fd = os.open(
                "import-manifest.json",
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                0o600,
                dir_fd=directory_fd,
            )
            try:
                os.write(competitor_fd, b"keep")
            finally:
                os.close(competitor_fd)
        return original_stat(path, *args, **kwargs)

    monkeypatch.setattr(importer_module.os, "stat", swapping_stat)
    try:
        with pytest.raises(ImporterError, match="MANIFEST_WRITE_FAILED"):
            importer_module._write_manifest(staging.file_fd, staging.ledger, b"{}\n")
        importer_module._safe_cleanup_staging(output, staging)

        assert swapped
        assert (staging.path / "import-manifest.json").read_bytes() == b"keep"
    finally:
        monkeypatch.setattr(importer_module.os, "stat", original_stat)
        with suppress(OSError):
            os.close(staging.file_fd)
        shutil.rmtree(staging.path, ignore_errors=True)
        os.close(output.parent_fd)


@pytest.mark.parametrize(
    "existing_kind",
    ["file", "directory", "symlink", "dangling-symlink"],
)
def test_existing_output_of_any_kind_is_rejected_unchanged(
    existing_kind: str, tmp_path: Path
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    write_tree(source, {"SKILL.md": _skill("existing")})
    out = tmp_path / "out"
    marker = tmp_path / "marker"
    marker.write_text("keep")
    if existing_kind == "file":
        out.write_text("keep-output")
    elif existing_kind == "directory":
        out.mkdir()
        (out / "keep").write_text("keep-output")
    elif existing_kind == "symlink":
        out.symlink_to(marker)
    else:
        out.symlink_to(tmp_path / "missing")

    with pytest.raises(ImporterError, match="OUTPUT_EXISTS"):
        _import(source, out)

    assert os.path.lexists(out)
    if existing_kind == "file":
        assert out.read_text() == "keep-output"
    elif existing_kind == "directory":
        assert (out / "keep").read_text() == "keep-output"
    else:
        assert out.is_symlink()
    assert marker.read_text() == "keep"


def test_before_publish_race_preserves_competitor_and_cleans_own_staging(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    write_tree(source, {"SKILL.md": _skill("race")})
    out = tmp_path / "out"

    def competitor(_staging: Path) -> None:
        out.mkdir()
        (out / "marker").write_text("competitor")

    with pytest.raises(ImporterError, match="OUTPUT_EXISTS"):
        _import(source, out, before_publish=competitor)

    assert (out / "marker").read_text() == "competitor"
    assert not list(tmp_path.glob(".out.skill-importer-*"))


class _UnsupportedPublisher:
    def publish(self, parent_fd: int, staging_name: str, output_name: str) -> None:
        del parent_fd, staging_name, output_name
        raise ImporterError(
            "ATOMIC_NOREPLACE_UNSUPPORTED", "native no-clobber publication unavailable"
        )


def test_unsupported_native_publication_fails_closed_without_rename_fallback(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    write_tree(source, {"SKILL.md": _skill("unsupported")})
    out = tmp_path / "out"

    def forbidden(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("unsafe rename fallback was called")

    monkeypatch.setattr(importer_module.os, "replace", forbidden)
    monkeypatch.setattr(importer_module.os, "rename", forbidden)

    with pytest.raises(ImporterError, match="ATOMIC_NOREPLACE_UNSUPPORTED"):
        _import(source, out, publisher=_UnsupportedPublisher())

    assert not os.path.lexists(out)
    assert not list(tmp_path.glob(".out.skill-importer-*"))


@pytest.mark.skipif(sys.platform != "darwin", reason="macOS renameatx_np integration")
def test_macos_native_renameatx_np_publishes_and_never_clobbers(tmp_path: Path) -> None:
    parent_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    parent_fd = os.open(tmp_path, parent_flags)
    try:
        os.mkdir("stage", 0o700, dir_fd=parent_fd)
        NativeAtomicPublisher().publish(parent_fd, "stage", "out")
        assert (tmp_path / "out").is_dir()

        os.mkdir("stage-two", 0o700, dir_fd=parent_fd)
        with pytest.raises(ImporterError, match="OUTPUT_EXISTS"):
            NativeAtomicPublisher().publish(parent_fd, "stage-two", "out")
        assert (tmp_path / "stage-two").is_dir()
    finally:
        os.close(parent_fd)


@pytest.mark.parametrize(
    ("staging_name", "output_name"),
    [
        ("../stage", "out"),
        ("stage", "nested/out"),
        ("stage", ".."),
        ("stage", ""),
        ("stage\x00suffix", "out"),
    ],
)
def test_native_publisher_rejects_non_basename_arguments_before_syscall(
    staging_name: str,
    output_name: str,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    parent_fd = os.open(
        tmp_path,
        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
    )

    def forbidden_library(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("invalid basename reached the native syscall boundary")

    monkeypatch.setattr(importer_module.ctypes, "CDLL", forbidden_library)
    try:
        with pytest.raises(ImporterError, match="PUBLISH_FAILED"):
            NativeAtomicPublisher().publish(parent_fd, staging_name, output_name)
    finally:
        os.close(parent_fd)


def test_fatal_file_fsync_failure_leaves_no_output(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    write_tree(source, {"SKILL.md": _skill("fsync")})
    out = tmp_path / "out"

    def fail_fsync(_file_fd: int) -> None:
        raise OSError(errno.EIO, "injected data error")

    monkeypatch.setattr(importer_module.os, "fsync", fail_fsync)

    with pytest.raises(ImporterError, match="FSYNC_FAILED"):
        _import(source, out)

    assert not os.path.lexists(out)


def test_regular_files_are_fsynced_before_directories(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    write_tree(
        source,
        {"tool/SKILL.md": _skill("fsync-order"), "tool/assets/a": "a"},
    )
    out = tmp_path / "out"
    original_fsync = importer_module.os.fsync
    observed: list[str] = []

    def recording_fsync(file_fd: int) -> None:
        mode = os.fstat(file_fd).st_mode
        observed.append("directory" if stat.S_ISDIR(mode) else "file")
        original_fsync(file_fd)

    monkeypatch.setattr(importer_module.os, "fsync", recording_fsync)

    _import(source, out)

    first_directory = observed.index("directory")
    assert first_directory > 0
    assert all(kind == "file" for kind in observed[:first_directory])
    assert observed[-1] == "directory"


class _RecordingPublisher:
    def __init__(self) -> None:
        self.calls = 0

    def publish(self, parent_fd: int, staging_name: str, output_name: str) -> None:
        del parent_fd, staging_name, output_name
        self.calls += 1


class _CleanupFailingPipeline(SkillImporterPipeline):
    @contextmanager
    def scan_operation(
        self,
        spec: SourceSpec,
        options: ScanOptions | None = None,
    ) -> Iterator[ScanOperation]:
        with super().scan_operation(spec, options) as operation:
            yield operation
        raise ImporterError("SNAPSHOT_CLEANUP_FAILED", "injected cleanup failure")


def test_snapshot_cleanup_failure_happens_before_publication(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    write_tree(source, {"SKILL.md": _skill("cleanup-order")})
    out = tmp_path / "out"
    publisher = _RecordingPublisher()
    pipeline = _CleanupFailingPipeline(api_key_provider=lambda: None)

    with pytest.raises(ImporterError, match="SNAPSHOT_CLEANUP_FAILED"):
        SkillImporter(pipeline=pipeline, publisher=publisher).import_source(
            SourceSpec.local(source), out, ScanOptions(use_llm=False)
        )

    assert publisher.calls == 0
    assert not os.path.lexists(out)
    assert not list(tmp_path.glob(".out.skill-importer-*"))


class _ReportOverridePipeline(SkillImporterPipeline):
    def __init__(
        self,
        transform: Callable[[ScanOperation], ScanOperation],
        *,
        limits: Limits | None = None,
    ) -> None:
        super().__init__(limits=limits, api_key_provider=lambda: None)
        self._transform = transform

    @contextmanager
    def scan_operation(
        self,
        spec: SourceSpec,
        options: ScanOptions | None = None,
    ) -> Iterator[ScanOperation]:
        with super().scan_operation(spec, options) as operation:
            yield self._transform(operation)


@pytest.mark.parametrize("layout", ["equal", "nested"])
def test_mixed_runtime_defense_rejects_inconsistent_portable_plan(
    layout: str, tmp_path: Path
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    if layout == "equal":
        files = {
            "SKILL.md": _skill("bad-promotion"),
            "plugin.json": '{"name":"plugin"}',
            "src/runtime.py": "RUNTIME = True\n",
        }
    else:
        files = {
            "SKILL.md": _skill("bad-promotion"),
            "nested/plugin.json": '{"name":"plugin"}',
            "nested/src/runtime.py": "RUNTIME = True\n",
        }
    write_tree(source, files)

    def promote(operation: ScanOperation) -> ScanOperation:
        original = operation.report.skills[0]
        promoted = replace(
            original,
            static_classification=Classification.PORTABLE,
            classification=Classification.PORTABLE,
            reasons=(_safe_reason(original.candidate.entrypoint),),
        )
        return replace(operation, report=ScanReport(source=operation.resolved, skills=(promoted,)))

    out = tmp_path / "out"
    importer = SkillImporter(pipeline=_ReportOverridePipeline(promote))

    with pytest.raises(ImporterError, match="PLUGIN_RUNTIME_INSIDE_SKILL_ROOT"):
        importer.import_source(SourceSpec.local(source), out, ScanOptions(use_llm=False))

    assert not os.path.lexists(out)


def test_nonportable_candidates_and_files_outside_skill_root_are_never_copied(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    write_tree(
        source,
        {
            "standalone/SKILL.md": _skill("standalone"),
            "outside-secret.txt": "DO_NOT_COPY",
            "plugins/mixed/plugin.json": '{"name":"mixed"}',
            "plugins/mixed/src/runtime.py": "PLUGIN_RUNTIME_SECRET = True\n",
            "plugins/mixed/skills/internal/SKILL.md": _skill("internal"),
        },
    )
    out = tmp_path / "out"

    result = _import(source, out)
    all_files = [path for path in out.rglob("*") if path.is_file()]

    assert [record.name for record in result.imported] == ["standalone"]
    assert any(skill.name == "internal" for skill in result.skipped)
    assert not any("outside-secret" in path.name for path in all_files)
    assert not any("runtime.py" in path.name for path in all_files)
    assert "DO_NOT_COPY" not in (out / "import-manifest.json").read_text()
    assert "PLUGIN_RUNTIME_SECRET" not in (out / "import-manifest.json").read_text()


@pytest.mark.parametrize(
    ("limit_name", "limit_value"),
    [("max_entries", 1), ("max_scan_bytes", 1), ("max_file_bytes", 1), ("max_depth", 1)],
)
def test_aggregate_copy_limits_fail_before_publication(
    limit_name: str, limit_value: int, tmp_path: Path
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    write_tree(
        source,
        {"tool/SKILL.md": _skill("limits"), "tool/nested/asset.txt": "payload"},
    )

    class _LowImportLimitPipeline(SkillImporterPipeline):
        def __init__(self) -> None:
            super().__init__(api_key_provider=lambda: None)
            object.__setattr__(self, "limits", replace(Limits(), **{limit_name: limit_value}))

        @contextmanager
        def scan_operation(
            self,
            spec: SourceSpec,
            options: ScanOptions | None = None,
        ) -> Iterator[ScanOperation]:
            original_limits = self.limits
            object.__setattr__(self, "limits", Limits())
            try:
                with super().scan_operation(spec, options) as operation:
                    object.__setattr__(self, "limits", original_limits)
                    yield operation
            finally:
                object.__setattr__(self, "limits", original_limits)

    out = tmp_path / "out"

    with pytest.raises(ImporterError, match=r"LIMIT|TOO_LARGE"):
        SkillImporter(pipeline=_LowImportLimitPipeline()).import_source(
            SourceSpec.local(source), out, ScanOptions(use_llm=False)
        )

    assert not os.path.lexists(out)


def test_manifest_is_canonical_allowlisted_and_preserves_provenance(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    frontmatter_secret = "FRONTMATTER_SECRET_7b54"
    evidence_secret = "EVIDENCE_SECRET_55a2"
    api_key = "FM_API_KEY_SECRET_18d9"
    write_tree(
        source,
        {
            "good/SKILL.md": _skill(
                "manifested", f"Self-contained. {evidence_secret}\n", secret=frontmatter_secret
            ),
            "bad/SKILL.md": f"---\nname: [broken-{frontmatter_secret}\n---\n",
        },
    )
    monkeypatch.setenv("LLM_API_KEY", api_key)
    out = tmp_path / "out"

    result = SkillImporter().import_source(
        SourceSpec.local(source), out, ScanOptions(use_llm=False)
    )
    raw = (out / "import-manifest.json").read_bytes()
    manifest = json.loads(raw)

    assert (
        raw
        == (
            json.dumps(
                manifest,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            )
            + "\n"
        ).encode()
    )
    record = manifest["imported"][0]
    provenance = record["provenance"][0]
    source_provenance = manifest["source"]
    assert record["contentHash"] == result.imported[0].content_hash
    assert source_provenance["canonicalSourceUrl"] == source.resolve().as_uri()
    assert source_provenance["resolvedCommitSha"] is None
    assert len(source_provenance["snapshotSha256"]) == 64
    assert provenance["originalRoot"] == "good"
    assert provenance["entrypoint"] == "good/SKILL.md"
    assert set(manifest) == {"schemaVersion", "source", "imported", "rejected"}
    assert set(source_provenance) == {
        "canonicalSourceUrl",
        "resolvedCommitSha",
        "snapshotSha256",
    }
    assert set(record) == {
        "name",
        "contentHash",
        "destination",
        "candidateIds",
        "provenance",
    }
    assert set(manifest["rejected"][0]) == {
        "candidateId",
        "name",
        "nameTruncated",
        "classification",
        "originalRoot",
        "originalRootTruncated",
        "reasonCodes",
    }
    for forbidden in (
        frontmatter_secret,
        evidence_secret,
        api_key,
        "skill-importer-scan-",
        "snapshotRoot",
        "rationale",
        "frontmatter",
    ):
        assert forbidden.encode() not in raw


def test_manifest_serialization_never_calls_full_skill_serializer(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    write_tree(source, {"SKILL.md": _skill("allowlist-only", secret="DO_NOT_SERIALIZE")})
    out = tmp_path / "out"

    def forbidden(_skill: AnalyzedSkill) -> dict[str, object]:
        raise AssertionError("full analyzed skill serializer must not feed the manifest")

    monkeypatch.setattr(AnalyzedSkill, "to_dict", forbidden)

    result = _import(source, out)

    assert len(result.imported) == 1
    assert (out / "import-manifest.json").is_file()


def test_manifest_source_provenance_occurs_once_for_duplicate_layouts(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    skill_text = _skill("common-source")
    write_tree(
        source,
        {
            "one/SKILL.md": skill_text,
            "two/SKILL.md": skill_text,
            "three/SKILL.md": skill_text,
        },
    )
    out = tmp_path / "out"

    _import(source, out)
    raw = (out / "import-manifest.json").read_bytes()
    manifest = json.loads(raw)

    assert raw.count(source.resolve().as_uri().encode()) == 1
    assert manifest["source"]["canonicalSourceUrl"] == source.resolve().as_uri()
    assert len(manifest["imported"][0]["provenance"]) == 3
    assert set(manifest["imported"][0]["provenance"][0]) == {
        "candidateId",
        "originalRoot",
        "entrypoint",
    }


@pytest.mark.parametrize("limit_delta", [0, -1])
def test_manifest_limit_is_exact_and_includes_trailing_newline(
    limit_delta: int,
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    write_tree(source, {"SKILL.md": _skill("exact-limit")})
    report = _scan(source)
    plan = build_import_plan(report, Limits())
    encoded = importer_module._manifest_bytes(plan, Limits().max_manifest_bytes)
    exact_limit = len(encoded) + limit_delta

    if limit_delta == 0:
        exact_plan = build_import_plan(report, Limits(max_manifest_bytes=exact_limit))
        assert importer_module._manifest_bytes(exact_plan, exact_limit) == encoded
        assert importer_module._manifest_bytes(plan, exact_limit) == encoded
        assert encoded.endswith(b"\n")
    else:
        with pytest.raises(ImporterError, match="MANIFEST_TOO_LARGE"):
            build_import_plan(report, Limits(max_manifest_bytes=exact_limit))
        with pytest.raises(ImporterError, match="MANIFEST_TOO_LARGE"):
            importer_module._manifest_bytes(plan, exact_limit)


def test_many_provenance_records_fail_low_manifest_preflight(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    skill_text = _skill("many-layouts")
    write_tree(
        source,
        {f"layout-{index}/SKILL.md": skill_text for index in range(40)},
    )
    report = _scan(source)

    with pytest.raises(ImporterError, match="MANIFEST_TOO_LARGE"):
        build_import_plan(report, Limits(max_manifest_bytes=512))


def test_imported_name_over_byte_cap_fails_before_output(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    write_tree(source, {"SKILL.md": _skill("n" * 1025)})
    out = tmp_path / "out"

    with pytest.raises(ImporterError, match="MANIFEST_METADATA_TOO_LARGE"):
        _import(source, out)

    assert not os.path.lexists(out)
    assert not list(tmp_path.glob(".out.skill-importer-*"))


class _CanonicalUrlResolver:
    def __init__(self, canonical_url: str, limits: Limits) -> None:
        self._canonical_url = canonical_url
        self._delegate = SourceResolver(limits=limits)

    def resolve(self, spec: SourceSpec, workspace: Path) -> ResolvedSource:
        return replace(
            self._delegate.resolve(spec, workspace),
            canonical_url=self._canonical_url,
        )


def test_canonical_url_over_byte_cap_fails_before_output(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    write_tree(source, {"SKILL.md": _skill("long-url")})
    out = tmp_path / "out"
    limits = Limits()
    pipeline = SkillImporterPipeline(
        limits=limits,
        resolver=_CanonicalUrlResolver("https://example.invalid/" + "u" * 16_385, limits),
        api_key_provider=lambda: None,
    )

    with pytest.raises(ImporterError, match="MANIFEST_METADATA_TOO_LARGE"):
        SkillImporter(pipeline=pipeline).import_source(
            SourceSpec.local(source), out, ScanOptions(use_llm=False)
        )

    assert not os.path.lexists(out)


@pytest.mark.parametrize("field", ["root", "entrypoint"])
def test_imported_path_metadata_over_byte_cap_is_rejected(
    field: str,
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    write_tree(source, {"SKILL.md": _skill("long-path")})
    report = _scan(source)
    skill = report.skills[0]
    long_root = "r" * 4097
    entrypoint = f"{long_root}/SKILL.md"
    if field == "entrypoint":
        long_root = "r" * 4090
        entrypoint = f"{long_root}/SKILL.md"
    candidate = SkillCandidate(
        candidate_id=build_candidate_id(report.source, long_root),
        source=report.source,
        root=long_root,
        entrypoint=entrypoint,
        enclosing_boundary=None,
    )
    modified = replace(skill, candidate=candidate)
    modified_report = ScanReport(source=report.source, skills=(modified,))

    with pytest.raises(ImporterError, match="MANIFEST_METADATA_TOO_LARGE"):
        build_import_plan(modified_report, Limits())


def test_rejected_optional_metadata_has_explicit_truncation_flags(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    write_tree(
        source,
        {
            "plugin.json": '{"name":"mixed"}',
            "src/runtime.py": "RUNTIME = True\n",
            "skills/item/SKILL.md": _skill("r" * 2048),
        },
    )

    plan = build_import_plan(_scan(source), Limits())
    rejected = plan.to_dict()["manifest"]["rejected"][0]

    assert rejected["nameTruncated"] is True
    assert len(rejected["name"].encode()) <= 512
    assert rejected["originalRootTruncated"] is False


def test_zero_portable_import_publishes_only_manifest(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    write_tree(source, {"SKILL.md": "---\nname: [broken\n---\n"})
    out = tmp_path / "out"

    result = _import(source, out)
    manifest = json.loads((out / "import-manifest.json").read_text())

    assert result.imported == ()
    assert len(result.skipped) == 1
    assert list(out.iterdir()) == [out / "import-manifest.json"]
    assert manifest["imported"] == []
    assert manifest["rejected"][0]["classification"] == "invalid"


def test_output_inside_original_source_is_rejected(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    write_tree(source, {"SKILL.md": _skill("unsafe-output")})
    out = source / "imported"

    with pytest.raises(ImporterError, match="UNSAFE_OUTPUT"):
        _import(source, out)

    assert not os.path.lexists(out)


def test_case_insensitive_source_alias_cannot_bypass_output_containment(
    tmp_path: Path,
) -> None:
    source = tmp_path / "SourceCase"
    source.mkdir()
    write_tree(source, {"SKILL.md": _skill("case-alias")})
    alias = tmp_path / "sourcecase"
    try:
        alias_stat = alias.stat()
    except FileNotFoundError:
        pytest.skip("test filesystem is case-sensitive")
    if (alias_stat.st_dev, alias_stat.st_ino) != (
        source.stat().st_dev,
        source.stat().st_ino,
    ):
        pytest.skip("test filesystem does not resolve the alias to the source inode")
    out = alias / "imported"

    with pytest.raises(ImporterError, match="UNSAFE_OUTPUT"):
        _import(source, out)

    assert not os.path.lexists(out)


def test_intermediate_parent_symlink_swap_cannot_redirect_publication(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    write_tree(source, {"SKILL.md": _skill("binding")})
    binding = tmp_path / "binding"
    original_parent = binding / "parent"
    original_leaf = original_parent / "leaf"
    original_leaf.mkdir(parents=True)
    saved_parent = binding / "saved-parent"
    alternate_parent = binding / "alternate"
    alternate_leaf = alternate_parent / "leaf"
    alternate_leaf.mkdir(parents=True)
    out = original_leaf / "out"
    original_resolve = Path.resolve
    swapped = False

    def resolve_then_swap(path: Path, *args: object, **kwargs: object) -> Path:
        nonlocal swapped
        resolved = original_resolve(path, *args, **kwargs)
        if not swapped and path == out.parent:
            swapped = True
            original_parent.rename(saved_parent)
            original_parent.symlink_to(alternate_parent, target_is_directory=True)
        return resolved

    monkeypatch.setattr(Path, "resolve", resolve_then_swap)

    with pytest.raises(ImporterError, match="OUTPUT_PARENT"):
        _import(source, out)

    assert swapped
    assert not os.path.lexists(alternate_leaf / "out")
    assert not os.path.lexists(saved_parent / "leaf/out")


def test_stable_resolved_parent_symlink_remains_usable(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    write_tree(source, {"SKILL.md": _skill("stable-parent")})
    real_parent = tmp_path / "real-parent"
    real_parent.mkdir()
    alias = tmp_path / "parent-alias"
    alias.symlink_to(real_parent, target_is_directory=True)
    requested_out = alias / "out"

    result = _import(source, requested_out)

    assert result.output_path == real_parent / "out"
    assert (real_parent / "out/import-manifest.json").is_file()


@pytest.mark.parametrize("failure_point", ["fstat", "lstat"])
def test_prepare_output_closes_parent_fd_on_post_open_failure(
    failure_point: str,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    out = tmp_path / "out"
    original_open = importer_module.os.open
    original_fstat = importer_module.os.fstat
    captured_fd: int | None = None

    def capturing_open(path: object, flags: int, *args: object, **kwargs: object) -> int:
        nonlocal captured_fd
        file_fd = original_open(path, flags, *args, **kwargs)
        if Path(path) == tmp_path or (path == tmp_path.name and kwargs.get("dir_fd") is not None):
            captured_fd = file_fd
        return file_fd

    def failing_fstat(file_fd: int) -> os.stat_result:
        if failure_point == "fstat" and file_fd == captured_fd:
            raise OSError(errno.EIO, "injected fstat failure")
        return original_fstat(file_fd)

    def failing_lstat(directory_fd: int, name: str) -> os.stat_result | None:
        del directory_fd, name
        raise OSError(errno.EIO, "injected lstat failure")

    monkeypatch.setattr(importer_module.os, "open", capturing_open)
    monkeypatch.setattr(importer_module.os, "fstat", failing_fstat)
    if failure_point == "lstat":
        monkeypatch.setattr(importer_module, "_lstat_at", failing_lstat)

    with pytest.raises(ImporterError):
        importer_module._prepare_output(out)

    assert captured_fd is not None
    with pytest.raises(OSError) as error:
        original_fstat(captured_fd)
    assert error.value.errno == errno.EBADF


def test_prepare_output_maps_expanduser_runtime_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail_expanduser(_path: Path) -> Path:
        raise RuntimeError("unknown user")

    monkeypatch.setattr(Path, "expanduser", fail_expanduser)

    with pytest.raises(ImporterError, match=r"UNSAFE_OUTPUT|OUTPUT_PARENT"):
        importer_module._prepare_output(Path("~missing/out"))


@pytest.mark.parametrize("failure_point", ["lstat", "fstat", "fchmod"])
def test_create_staging_closes_fd_and_removes_owned_directory_on_failure(
    failure_point: str,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    output = importer_module._prepare_output(tmp_path / "out")
    original_open = importer_module.os.open
    original_fstat = importer_module.os.fstat
    original_fchmod = importer_module.os.fchmod
    original_lstat_at = importer_module._lstat_at
    captured_fd: int | None = None
    staging = None

    def capturing_open(path: object, flags: int, *args: object, **kwargs: object) -> int:
        nonlocal captured_fd
        file_fd = original_open(path, flags, *args, **kwargs)
        if isinstance(path, str) and ".skill-importer-" in path:
            captured_fd = file_fd
        return file_fd

    def failing_fstat(file_fd: int) -> os.stat_result:
        if failure_point == "fstat" and file_fd == captured_fd:
            raise OSError(errno.EIO, "injected fstat failure")
        return original_fstat(file_fd)

    def failing_fchmod(file_fd: int, mode: int) -> None:
        if failure_point == "fchmod" and file_fd == captured_fd:
            raise OSError(errno.EIO, "injected fchmod failure")
        original_fchmod(file_fd, mode)

    lstat_failed = False

    def failing_lstat(directory_fd: int, name: str) -> os.stat_result | None:
        nonlocal lstat_failed
        if failure_point == "lstat" and not lstat_failed and ".skill-importer-" in name:
            lstat_failed = True
            raise OSError(errno.EIO, "injected lstat failure")
        return original_lstat_at(directory_fd, name)

    monkeypatch.setattr(importer_module.os, "open", capturing_open)
    monkeypatch.setattr(importer_module.os, "fstat", failing_fstat)
    monkeypatch.setattr(importer_module.os, "fchmod", failing_fchmod)
    monkeypatch.setattr(importer_module, "_lstat_at", failing_lstat)
    try:
        with pytest.raises(ImporterError):
            staging = importer_module._create_staging(output)
    finally:
        if staging is not None:
            with suppress(OSError):
                os.close(staging.file_fd)
            shutil.rmtree(staging.path, ignore_errors=True)
        os.close(output.parent_fd)

    if captured_fd is not None:
        with pytest.raises(OSError) as error:
            original_fstat(captured_fd)
        assert error.value.errno == errno.EBADF
    assert not list(tmp_path.glob(".out.skill-importer-*"))
