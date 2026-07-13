from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest

from skill_importer.errors import ImporterError
from skill_importer.limits import Limits
from skill_importer.models import (
    AnalyzedSkill,
    Classification,
    DecisionReason,
    DuplicateGroup,
    Evidence,
    ExternalRequirements,
    FmReview,
    ImportPlan,
    ImportRecord,
    Inventory,
    InventoryEntry,
    NameConflictGroup,
    PackageBoundary,
    ReasonCode,
    ResolvedSource,
    ScanReport,
    SkillCandidate,
    SourceKind,
    SourceSpec,
    ValidationResult,
)

SHA256 = "a" * 64


def _resolved_source(snapshot_root: Path) -> ResolvedSource:
    spec = SourceSpec.local(snapshot_root)
    return ResolvedSource(
        spec=spec,
        canonical_url=snapshot_root.as_uri(),
        snapshot_root=snapshot_root,
        snapshot_sha256=SHA256,
        discovery_scope=".",
        resolved_commit_sha=None,
    )


def _reason(code: ReasonCode = ReasonCode.STANDALONE_NO_PLUGIN_BOUNDARY) -> DecisionReason:
    return DecisionReason(
        code=code,
        message="decision",
        evidence=(
            Evidence(
                path="skills/x/SKILL.md",
                line=1,
                field=None,
                value="name: x",
                detector="test.detector",
            ),
        ),
    )


def _analyzed_skill(snapshot_root: Path) -> AnalyzedSkill:
    source = _resolved_source(snapshot_root)
    candidate = SkillCandidate(
        candidate_id="candidate-1",
        source=source,
        root="skills/x",
        entrypoint="skills/x/SKILL.md",
        enclosing_boundary=None,
    )
    validation = ValidationResult(
        valid=True,
        name="x",
        description="example",
        frontmatter={"name": "x", "description": "example"},
    )
    return AnalyzedSkill(
        candidate=candidate,
        validation=validation,
        static_classification=Classification.PORTABLE,
        classification=Classification.PORTABLE,
        reasons=(_reason(),),
        external_requirements=ExternalRequirements(binaries=("git",), environment=("TOKEN",)),
        content_hash=SHA256,
    )


def test_reason_serializes_machine_readable_evidence() -> None:
    reason = DecisionReason(
        code=ReasonCode.PLUGIN_ROOT_VARIABLE,
        message="skill references plugin root",
        evidence=(
            Evidence(
                path="skills/x/SKILL.md",
                line=8,
                field=None,
                value="${PLUGIN_ROOT}/tool",
                detector="static.variable",
            ),
        ),
    )

    assert reason.to_dict()["code"] == "PLUGIN_ROOT_VARIABLE"
    assert reason.to_dict()["evidence"][0]["line"] == 8


def test_classification_precedence_is_fail_closed() -> None:
    assert (
        Classification.strongest(
            [
                Classification.PORTABLE,
                Classification.AMBIGUOUS,
                Classification.BLOCKED,
            ]
        )
        is Classification.BLOCKED
    )


def test_reason_code_surface_contains_approved_poc_codes() -> None:
    required = {
        "STANDALONE_NO_PLUGIN_BOUNDARY",
        "SKILLS_ONLY_PACKAGE",
        "PLUGIN_ROOT_VARIABLE",
        "REFERENCE_OUTSIDE_SKILL_ROOT",
        "PLUGIN_OWNED_MCP_TOOL",
        "PLUGIN_COMMAND_REFERENCE",
        "PLUGIN_RUNTIME_FILE_REFERENCE",
        "REFERENCED_BY_PLUGIN_RUNTIME",
        "MISSING_LOCAL_RESOURCE",
        "DYNAMIC_REFERENCE_UNRESOLVED",
        "MIXED_PLUGIN_AUTONOMY_UNPROVEN",
        "SYMLINK_ESCAPE",
        "PATH_TRAVERSAL",
        "PATH_COLLISION",
        "INVALID_FRONTMATTER",
        "FILE_TOO_LARGE",
        "SCAN_LIMIT_EXCEEDED",
        "DUPLICATE_CONTENT",
        "NAME_CONFLICT",
        "FM_PORTABLE_VERIFIED",
        "FM_PLUGIN_BOUND",
        "FM_REVIEW_UNAVAILABLE",
        "FM_INVALID_RESPONSE",
        "FM_EVIDENCE_INVALID",
        "FM_CONTEXT_TRUNCATED",
        "FM_CONTEXT_REDACTED",
        "FM_CONFIDENCE_TOO_LOW",
    }

    assert required <= {item.name for item in ReasonCode}


@pytest.mark.parametrize(
    "path",
    ["", "/absolute", "../escape", "a/../b", "./a", "a//b", "a\\b", "C:/drive"],
)
def test_inventory_entry_rejects_non_normalized_relative_paths(path: str) -> None:
    with pytest.raises(ValueError, match="normalized relative POSIX path"):
        InventoryEntry(path=path, kind="directory", size=0)


def test_file_inventory_entry_requires_valid_sha256() -> None:
    with pytest.raises(ValueError, match="sha256"):
        InventoryEntry(path="SKILL.md", kind="file", size=1, sha256="not-a-hash")

    entry = InventoryEntry(path="SKILL.md", kind="file", size=1, sha256=SHA256)
    assert entry.to_dict()["sha256"] == SHA256


def test_source_inventory_and_boundary_use_stable_json_names(tmp_path: Path) -> None:
    source = _resolved_source(tmp_path)
    inventory = Inventory(
        entries=(InventoryEntry(path="SKILL.md", kind="file", size=1, sha256=SHA256),)
    )
    boundary = PackageBoundary(
        root=".",
        manifest_path=".claude-plugin/plugin.json",
        manifest_kind="claude",
        package_kind="skills_only",
    )

    assert source.spec.kind is SourceKind.LOCAL
    assert source.to_dict()["snapshotSha256"] == SHA256
    assert "snapshotRoot" not in source.to_dict()
    assert inventory.by_path["SKILL.md"].size == 1
    assert inventory.to_dict()["totalBytes"] == 1
    assert boundary.to_dict()["manifestPath"] == ".claude-plugin/plugin.json"
    assert boundary.to_dict()["packageKind"] == "skills_only"


def test_fm_review_rejects_non_fm_classification() -> None:
    with pytest.raises(ValueError, match="FM classification"):
        FmReview(
            analysis_hash=f"sha256:{SHA256}",
            classification=Classification.BLOCKED,
            confidence=0.5,
            reason=_reason(ReasonCode.FM_INVALID_RESPONSE),
            rationale="invalid response",
        )


def test_scan_report_serializes_counts_conflicts_and_requirements(tmp_path: Path) -> None:
    skill = _analyzed_skill(tmp_path)
    report = ScanReport(
        source=skill.candidate.source,
        skills=(skill,),
        duplicates=(DuplicateGroup(content_hash=SHA256, candidate_ids=("candidate-1", "other")),),
        name_conflicts=(NameConflictGroup(name="x", candidate_ids=("candidate-1", "other")),),
    )

    payload = report.to_dict()
    assert payload["schemaVersion"] == "1.0"
    assert payload["counts"] == {
        "total": 1,
        "portable": 1,
        "plugin_bound": 0,
        "ambiguous": 0,
        "invalid": 0,
        "blocked": 0,
    }
    assert payload["skills"][0]["candidateId"] == "candidate-1"
    assert payload["skills"][0]["contentHash"] == SHA256
    assert payload["skills"][0]["externalRequirements"]["binaries"] == ["git"]
    assert payload["duplicates"][0]["candidateIds"] == ["candidate-1", "other"]
    assert payload["nameConflicts"][0]["name"] == "x"


def test_import_plan_serializes_destination_mapping(tmp_path: Path) -> None:
    skill = _analyzed_skill(tmp_path)
    record = ImportRecord(
        name="x",
        content_hash=SHA256,
        destination=f"x--{SHA256[:12]}",
        candidate_ids=("candidate-1",),
    )
    plan = ImportPlan(selected=(skill,), rejected=(), records=(record,))

    assert plan.to_dict()["records"][0]["contentHash"] == SHA256
    assert plan.to_dict()["records"][0]["destination"] == f"x--{SHA256[:12]}"


def test_limits_are_immutable_and_match_approved_defaults() -> None:
    limits = Limits()

    assert limits.git_timeout_seconds == 60
    assert limits.max_archive_bytes == 100 * 1024 * 1024
    assert limits.max_entries == 10_000
    assert limits.max_scan_bytes == 250 * 1024 * 1024
    assert limits.max_file_bytes == 10 * 1024 * 1024
    assert limits.max_depth == 64
    assert limits.max_fm_context_chars == 128 * 1024
    assert limits.max_fm_response_bytes == 1024 * 1024
    assert limits.max_fm_reviews == 50
    with pytest.raises(FrozenInstanceError):
        limits.max_entries = 1  # type: ignore[misc]


def test_importer_error_exposes_only_bounded_public_text() -> None:
    secret_tail = "SECRET_RAW_BODY"
    error = ImporterError("SOURCE_FAILED", "safe summary" + "x" * 600 + secret_tail)

    assert error.code == "SOURCE_FAILED"
    assert len(error.message) == ImporterError.MAX_MESSAGE_LENGTH
    assert secret_tail not in str(error)
    assert not hasattr(error, "raw_body")
