import json
from collections.abc import Mapping
from dataclasses import FrozenInstanceError, replace
from pathlib import Path

import pytest

import skill_importer.models as model_module
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
        candidate_id=model_module.build_candidate_id(source, "skills/x"),
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


def _analyzed_skill_at(
    snapshot_root: Path,
    root: str,
    *,
    name: str,
    content_hash: str = SHA256,
) -> AnalyzedSkill:
    source = _resolved_source(snapshot_root)
    candidate = SkillCandidate(
        candidate_id=model_module.build_candidate_id(source, root),
        source=source,
        root=root,
        entrypoint=f"{root}/SKILL.md",
        enclosing_boundary=None,
    )
    validation = ValidationResult(
        valid=True,
        name=name,
        description="example",
        frontmatter={"name": name, "description": "example"},
    )
    return AnalyzedSkill(
        candidate=candidate,
        validation=validation,
        static_classification=Classification.PORTABLE,
        classification=Classification.PORTABLE,
        reasons=(_reason(),),
        content_hash=content_hash,
    )


def _import_record_for(skill: AnalyzedSkill) -> ImportRecord:
    assert skill.name is not None
    assert skill.content_hash is not None
    return ImportRecord(
        name=skill.name,
        content_hash=skill.content_hash,
        destination=f"{skill.name}--{skill.content_hash[:12]}",
        candidate_ids=(skill.candidate_id,),
    )


def _invalid_validation() -> ValidationResult:
    return ValidationResult(
        valid=False,
        name=None,
        description=None,
        frontmatter={},
        reasons=(_reason(ReasonCode.INVALID_FRONTMATTER),),
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
        "PLUGIN_RUNTIME_INSIDE_SKILL_ROOT",
        "REFERENCED_BY_PLUGIN_RUNTIME",
        "MISSING_LOCAL_RESOURCE",
        "DYNAMIC_REFERENCE_UNRESOLVED",
        "STATIC_ANALYSIS_INCOMPLETE",
        "MIXED_PLUGIN_AUTONOMY_UNPROVEN",
        "SYMLINK_ESCAPE",
        "SYMLINK_CYCLE",
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


def test_candidate_id_builder_is_deterministic_for_source_revision_and_root(
    tmp_path: Path,
) -> None:
    source = _resolved_source(tmp_path)

    candidate_id = model_module.build_candidate_id(source, "skills/x")

    assert candidate_id == model_module.build_candidate_id(source, "skills/x")
    assert candidate_id.startswith("sha256:")
    assert len(candidate_id) == len("sha256:") + 64
    assert candidate_id != model_module.build_candidate_id(source, "skills/y")


def test_candidate_rejects_id_not_derived_from_provenance_and_root(tmp_path: Path) -> None:
    source = _resolved_source(tmp_path)

    with pytest.raises(ValueError, match="candidate ID must match"):
        SkillCandidate(
            candidate_id="candidate-1",
            source=source,
            root="skills/x",
            entrypoint="skills/x/SKILL.md",
            enclosing_boundary=None,
        )


def test_candidate_root_must_be_entrypoint_direct_parent(tmp_path: Path) -> None:
    source = _resolved_source(tmp_path)

    with pytest.raises(ValueError, match="direct parent"):
        SkillCandidate(
            candidate_id=model_module.build_candidate_id(source, "."),
            source=source,
            root=".",
            entrypoint="skills/x/SKILL.md",
            enclosing_boundary=None,
        )

    root = "skills/x"
    candidate = SkillCandidate(
        candidate_id=model_module.build_candidate_id(source, root),
        source=source,
        root=root,
        entrypoint="skills/x/SKILL.md",
        enclosing_boundary=None,
    )
    assert candidate.root == root


@pytest.mark.parametrize("kind", [SourceKind.GIT, SourceKind.GITHUB])
def test_remote_resolved_source_requires_immutable_commit(kind: SourceKind, tmp_path: Path) -> None:
    spec = SourceSpec(kind=kind, value="https://example.com/acme/repo.git")

    with pytest.raises(ValueError, match="remote source requires"):
        ResolvedSource(
            spec=spec,
            canonical_url="https://example.com/acme/repo.git",
            snapshot_root=tmp_path,
            snapshot_sha256=SHA256,
            discovery_scope=".",
            resolved_commit_sha=None,
        )


def test_local_source_revision_uses_snapshot_even_when_git_head_is_known(tmp_path: Path) -> None:
    source = ResolvedSource(
        spec=SourceSpec.local(tmp_path),
        canonical_url=tmp_path.as_uri(),
        snapshot_root=tmp_path,
        snapshot_sha256=SHA256,
        discovery_scope=".",
        resolved_commit_sha="b" * 40,
    )

    assert source.revision == SHA256


def test_import_plan_rejects_unverified_ambiguous_promotion(tmp_path: Path) -> None:
    static_skill = _analyzed_skill(tmp_path)

    with pytest.raises(ValueError, match="ambiguous classification requires FM review"):
        promoted = replace(
            static_skill,
            static_classification=Classification.AMBIGUOUS,
            classification=Classification.PORTABLE,
        )
        ImportPlan(selected=(promoted,), rejected=(), records=())


@pytest.mark.parametrize(
    ("review_classification", "final_classification", "reason_code"),
    [
        (Classification.PLUGIN_BOUND, Classification.PORTABLE, ReasonCode.FM_PLUGIN_BOUND),
        (Classification.PORTABLE, Classification.PLUGIN_BOUND, ReasonCode.FM_PORTABLE_VERIFIED),
        (Classification.AMBIGUOUS, Classification.PLUGIN_BOUND, ReasonCode.FM_INVALID_RESPONSE),
    ],
)
def test_final_classification_must_match_fm_review(
    review_classification: Classification,
    final_classification: Classification,
    reason_code: ReasonCode,
    tmp_path: Path,
) -> None:
    static_skill = _analyzed_skill(tmp_path)
    review = FmReview(
        analysis_hash=f"sha256:{SHA256}",
        classification=review_classification,
        confidence=0.95,
        reason=_reason(reason_code),
        rationale="review",
    )

    with pytest.raises(ValueError, match="match FM review"):
        replace(
            static_skill,
            static_classification=Classification.AMBIGUOUS,
            classification=final_classification,
            fm_review=review,
            analysis_method="static+fm",
            reasons=(review.reason,),
        )


def test_portable_fm_promotion_requires_confidence_threshold(tmp_path: Path) -> None:
    static_skill = _analyzed_skill(tmp_path)
    review = FmReview(
        analysis_hash=f"sha256:{SHA256}",
        classification=Classification.PORTABLE,
        confidence=0.89,
        reason=_reason(ReasonCode.FM_PORTABLE_VERIFIED),
        rationale="review",
    )

    with pytest.raises(ValueError, match="confidence"):
        replace(
            static_skill,
            static_classification=Classification.AMBIGUOUS,
            classification=Classification.PORTABLE,
            fm_review=review,
            analysis_method="static+fm",
            reasons=(review.reason,),
        )


@pytest.mark.parametrize("missing_proof", ["evidence", "reason"])
def test_portable_fm_promotion_requires_verified_reason_and_evidence(
    missing_proof: str,
    tmp_path: Path,
) -> None:
    static_skill = _analyzed_skill(tmp_path)
    reason = (
        DecisionReason(
            code=ReasonCode.FM_PORTABLE_VERIFIED,
            message="review",
            evidence=(),
        )
        if missing_proof == "evidence"
        else _reason(ReasonCode.FM_INVALID_RESPONSE)
    )
    review = FmReview(
        analysis_hash=f"sha256:{SHA256}",
        classification=Classification.PORTABLE,
        confidence=0.95,
        reason=reason,
        rationale="review",
    )

    with pytest.raises(ValueError, match="verified reason with evidence"):
        replace(
            static_skill,
            static_classification=Classification.AMBIGUOUS,
            classification=Classification.PORTABLE,
            fm_review=review,
            analysis_method="static+fm",
            reasons=(review.reason,),
        )


def test_fm_reason_must_be_present_in_analyzed_reasons(tmp_path: Path) -> None:
    static_skill = _analyzed_skill(tmp_path)
    review = FmReview(
        analysis_hash=f"sha256:{SHA256}",
        classification=Classification.PLUGIN_BOUND,
        confidence=0.95,
        reason=_reason(ReasonCode.FM_PLUGIN_BOUND),
        rationale="review",
    )

    with pytest.raises(ValueError, match="FM reason"):
        replace(
            static_skill,
            static_classification=Classification.AMBIGUOUS,
            classification=Classification.PLUGIN_BOUND,
            fm_review=review,
            analysis_method="static+fm",
            reasons=(_reason(ReasonCode.MIXED_PLUGIN_AUTONOMY_UNPROVEN),),
        )


def test_fm_reason_evidence_order_does_not_change_semantic_presence(tmp_path: Path) -> None:
    static_skill = _analyzed_skill(tmp_path)
    first = Evidence(
        path="z-runtime.py",
        line=2,
        field=None,
        value="runtime",
        detector="fm.review",
    )
    second = Evidence(
        path="skills/x/SKILL.md",
        line=5,
        field=None,
        value="self-contained",
        detector="fm.review",
    )
    fm_reason = DecisionReason(
        code=ReasonCode.FM_REVIEW_UNAVAILABLE,
        message="review",
        evidence=(first, second),
    )
    canonical_reason = replace(fm_reason, evidence=(second, first))
    review = FmReview(
        analysis_hash=f"sha256:{SHA256}",
        classification=Classification.AMBIGUOUS,
        confidence=0.9,
        reason=fm_reason,
        rationale="review",
    )

    analyzed = replace(
        static_skill,
        static_classification=Classification.AMBIGUOUS,
        classification=Classification.AMBIGUOUS,
        fm_review=review,
        analysis_method="static+fm",
        reasons=(canonical_reason,),
    )

    assert analyzed.fm_review is review


def test_valid_fm_promotion_can_enter_import_plan(tmp_path: Path) -> None:
    static_skill = _analyzed_skill(tmp_path)
    review = FmReview(
        analysis_hash=f"sha256:{SHA256}",
        classification=Classification.PORTABLE,
        confidence=0.95,
        reason=_reason(ReasonCode.FM_PORTABLE_VERIFIED),
        rationale="review",
    )
    promoted = replace(
        static_skill,
        static_classification=Classification.AMBIGUOUS,
        classification=Classification.PORTABLE,
        fm_review=review,
        analysis_method="static+fm",
        reasons=(review.reason,),
    )

    plan = ImportPlan(
        selected=(promoted,),
        rejected=(),
        records=(_import_record_for(promoted),),
    )

    assert plan.selected == (promoted,)


@pytest.mark.parametrize(
    "context_reason",
    [ReasonCode.FM_CONTEXT_TRUNCATED, ReasonCode.FM_CONTEXT_REDACTED],
)
def test_portable_fm_promotion_rejects_incomplete_context(
    context_reason: ReasonCode,
    tmp_path: Path,
) -> None:
    static_skill = _analyzed_skill(tmp_path)
    review = FmReview(
        analysis_hash=f"sha256:{SHA256}",
        classification=Classification.PORTABLE,
        confidence=0.95,
        reason=_reason(ReasonCode.FM_PORTABLE_VERIFIED),
        rationale="review",
    )

    with pytest.raises(ValueError, match="unredacted context"):
        replace(
            static_skill,
            static_classification=Classification.AMBIGUOUS,
            classification=Classification.PORTABLE,
            fm_review=review,
            analysis_method="static+fm",
            reasons=(review.reason, _reason(context_reason)),
        )


def test_import_plan_defensively_revalidates_portable_fm_promotion(tmp_path: Path) -> None:
    static_skill = _analyzed_skill(tmp_path)
    review = FmReview(
        analysis_hash=f"sha256:{SHA256}",
        classification=Classification.PORTABLE,
        confidence=0.95,
        reason=_reason(ReasonCode.FM_PORTABLE_VERIFIED),
        rationale="review",
    )
    promoted = replace(
        static_skill,
        static_classification=Classification.AMBIGUOUS,
        classification=Classification.PORTABLE,
        fm_review=review,
        analysis_method="static+fm",
        reasons=(review.reason,),
    )
    object.__setattr__(
        promoted,
        "reasons",
        (*promoted.reasons, _reason(ReasonCode.FM_CONTEXT_REDACTED)),
    )

    with pytest.raises(ValueError, match="unredacted context"):
        ImportPlan(selected=(promoted,), rejected=(), records=())


@pytest.mark.parametrize(
    "classification",
    [Classification.PORTABLE, Classification.PLUGIN_BOUND, Classification.AMBIGUOUS],
)
def test_broken_validation_rejects_non_fail_closed_classification(
    classification: Classification,
    tmp_path: Path,
) -> None:
    skill = _analyzed_skill(tmp_path)

    with pytest.raises(ValueError, match="invalid validation requires"):
        replace(
            skill,
            validation=_invalid_validation(),
            static_classification=classification,
            classification=classification,
            reasons=(_reason(ReasonCode.INVALID_FRONTMATTER),),
        )


def test_import_plan_rejects_portable_skill_with_broken_validation(tmp_path: Path) -> None:
    skill = _analyzed_skill(tmp_path)
    object.__setattr__(skill, "validation", _invalid_validation())

    with pytest.raises(ValueError, match="invalid validation requires"):
        ImportPlan(selected=(skill,), rejected=(), records=())


@pytest.mark.parametrize("classification", [Classification.INVALID, Classification.BLOCKED])
def test_broken_validation_allows_fail_closed_results(
    classification: Classification,
    tmp_path: Path,
) -> None:
    skill = replace(
        _analyzed_skill(tmp_path),
        validation=_invalid_validation(),
        static_classification=classification,
        classification=classification,
        reasons=(_reason(ReasonCode.INVALID_FRONTMATTER),),
    )

    assert skill.classification is classification


def test_frontmatter_is_recursively_immutable_and_detached() -> None:
    original = {
        "name": "x",
        "description": "example",
        "requires": {"bins": ["git"]},
    }
    validation = ValidationResult(
        valid=True,
        name="x",
        description="example",
        frontmatter=original,
    )

    original["requires"]["bins"].append("docker")

    assert validation.to_dict()["frontmatter"]["requires"]["bins"] == ["git"]
    requires = validation.frontmatter["requires"]
    assert isinstance(requires, Mapping)
    with pytest.raises(TypeError):
        requires["bins"] = ("docker",)  # type: ignore[index]


def test_manifest_payload_is_recursively_immutable_and_detached(tmp_path: Path) -> None:
    payload = {"metadata": {"tags": ["safe"]}}
    plan = ImportPlan(
        selected=(_analyzed_skill(tmp_path),),
        rejected=(),
        records=(_import_record_for(_analyzed_skill(tmp_path)),),
        manifest_payload=payload,
    )

    payload["metadata"]["tags"].append("mutated")

    assert plan.to_dict()["manifest"] == {"metadata": {"tags": ["safe"]}}
    metadata = plan.manifest_payload["metadata"]
    assert isinstance(metadata, Mapping)
    with pytest.raises(TypeError):
        metadata["tags"] = ("mutated",)  # type: ignore[index]


@pytest.mark.parametrize(
    "value",
    [object(), float("nan"), float("inf"), {1: "non-string-key"}],
)
def test_frontmatter_rejects_values_outside_strict_json_domain(value: object) -> None:
    with pytest.raises(ValueError, match="JSON"):
        ValidationResult(
            valid=True,
            name="x",
            description="example",
            frontmatter={"name": "x", "description": "example", "value": value},
        )


@pytest.mark.parametrize("value", [object(), float("-inf"), {1: "non-string-key"}])
def test_manifest_rejects_values_outside_strict_json_domain(
    value: object,
    tmp_path: Path,
) -> None:
    with pytest.raises(ValueError, match="JSON"):
        ImportPlan(
            selected=(_analyzed_skill(tmp_path),),
            rejected=(),
            records=(),
            manifest_payload={"value": value},
        )


def test_nested_domain_serializers_return_plain_json_values(tmp_path: Path) -> None:
    validation = ValidationResult(
        valid=True,
        name="x",
        description="example",
        frontmatter={"nested": {"items": [1, True, None]}},
    )
    plan = ImportPlan(
        selected=(_analyzed_skill(tmp_path),),
        rejected=(),
        records=(_import_record_for(_analyzed_skill(tmp_path)),),
        manifest_payload={"nested": {"items": [1, True, None]}},
    )

    json.dumps(validation.to_dict(), allow_nan=False)
    json.dumps(plan.to_dict(), allow_nan=False)


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
    duplicate = DuplicateGroup(content_hash=SHA256, candidate_ids=(skill.candidate_id, "other"))
    conflict = NameConflictGroup(name="x", candidate_ids=(skill.candidate_id, "other"))
    report = ScanReport(source=skill.candidate.source, skills=(skill,))

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
    assert payload["skills"][0]["candidateId"] == skill.candidate_id
    assert payload["skills"][0]["contentHash"] == SHA256
    assert payload["skills"][0]["externalRequirements"]["binaries"] == ["git"]
    assert duplicate.to_dict()["candidateIds"] == sorted([skill.candidate_id, "other"])
    assert conflict.to_dict()["name"] == "x"
    assert duplicate.to_dict()["groupId"].startswith("sha256:")
    assert conflict.to_dict()["groupId"].startswith("sha256:")


def test_scan_report_rejects_duplicate_candidate_identity(tmp_path: Path) -> None:
    skill = _analyzed_skill(tmp_path)

    with pytest.raises(ValueError, match="candidate IDs"):
        ScanReport(source=skill.candidate.source, skills=(skill, skill))


def test_scan_report_rejects_group_member_missing_from_skills(tmp_path: Path) -> None:
    skill = _analyzed_skill(tmp_path)
    group = DuplicateGroup(content_hash=SHA256, candidate_ids=(skill.candidate_id, "other"))

    with pytest.raises(ValueError, match="duplicate equivalence groups"):
        ScanReport(source=skill.candidate.source, skills=(skill,), duplicates=(group,))


@pytest.mark.parametrize("dimension", ["duplicate", "name"])
def test_scan_report_rejects_dangling_skill_group_annotation(
    dimension: str, tmp_path: Path
) -> None:
    skill = replace(
        _analyzed_skill(tmp_path),
        **{
            "duplicate_group" if dimension == "duplicate" else "name_conflict_group": (
                f"sha256:{SHA256}"
            )
        },
    )

    with pytest.raises(ValueError, match="group annotation"):
        ScanReport(source=skill.candidate.source, skills=(skill,))


def test_scan_report_rejects_annotation_for_nonmember_of_existing_group(tmp_path: Path) -> None:
    first = _analyzed_skill_at(tmp_path, "skills/first", name="first")
    second = _analyzed_skill_at(tmp_path, "skills/second", name="second")
    unrelated = _analyzed_skill_at(
        tmp_path, "skills/unrelated", name="unrelated", content_hash="b" * 64
    )
    group = DuplicateGroup(
        content_hash=SHA256,
        candidate_ids=(first.candidate_id, second.candidate_id),
    )
    first = _annotate_equivalence("duplicate", first, group)
    second = _annotate_equivalence("duplicate", second, group)
    unrelated = replace(unrelated, duplicate_group=group.group_id)

    with pytest.raises(ValueError, match="duplicate group annotation"):
        ScanReport(
            source=first.candidate.source,
            skills=(first, second, unrelated),
            duplicates=(group,),
        )


def _equivalent_skills(
    tmp_path: Path,
    dimension: str,
    count: int,
) -> tuple[AnalyzedSkill, ...]:
    return tuple(
        _analyzed_skill_at(
            tmp_path,
            f"skills/item-{index}",
            name="same-name" if dimension == "name" else f"name-{index}",
            content_hash=(SHA256 if dimension == "duplicate" else f"{index + 1:064x}"),
        )
        for index in range(count)
    )


def _equivalence_group(
    dimension: str,
    skills: tuple[AnalyzedSkill, ...],
) -> DuplicateGroup | NameConflictGroup:
    candidate_ids = tuple(skill.candidate_id for skill in skills)
    if dimension == "duplicate":
        return DuplicateGroup(content_hash=SHA256, candidate_ids=candidate_ids)
    return NameConflictGroup(name="same-name", candidate_ids=candidate_ids)


def _annotate_equivalence(
    dimension: str,
    skill: AnalyzedSkill,
    group: DuplicateGroup | NameConflictGroup,
) -> AnalyzedSkill:
    if dimension == "duplicate":
        return replace(
            skill,
            duplicate_group=group.group_id,
            reasons=(*skill.reasons, _reason(ReasonCode.DUPLICATE_CONTENT)),
        )
    return replace(
        skill,
        name_conflict_group=group.group_id,
        reasons=(*skill.reasons, _reason(ReasonCode.NAME_CONFLICT)),
    )


@pytest.mark.parametrize("dimension", ["duplicate", "name"])
def test_scan_report_accepts_exact_triple_equivalence_group(dimension: str, tmp_path: Path) -> None:
    skills = _equivalent_skills(tmp_path, dimension, 3)
    group = _equivalence_group(dimension, skills)
    annotated = tuple(_annotate_equivalence(dimension, skill, group) for skill in skills)

    report = ScanReport(
        source=annotated[0].candidate.source,
        skills=annotated,
        duplicates=(group,) if dimension == "duplicate" else (),
        name_conflicts=(group,) if dimension == "name" else (),  # type: ignore[arg-type]
    )

    assert len(report.duplicates if dimension == "duplicate" else report.name_conflicts) == 1


@pytest.mark.parametrize("dimension", ["duplicate", "name"])
def test_scan_report_rejects_group_missing_third_equivalent_candidate(
    dimension: str, tmp_path: Path
) -> None:
    skills = _equivalent_skills(tmp_path, dimension, 3)
    group = _equivalence_group(dimension, skills[:2])
    annotated = (
        *(_annotate_equivalence(dimension, skill, group) for skill in skills[:2]),
        skills[2],
    )

    with pytest.raises(ValueError, match="equivalence groups"):
        ScanReport(
            source=skills[0].candidate.source,
            skills=annotated,
            duplicates=(group,) if dimension == "duplicate" else (),
            name_conflicts=(group,) if dimension == "name" else (),  # type: ignore[arg-type]
        )


@pytest.mark.parametrize("dimension", ["duplicate", "name"])
def test_scan_report_rejects_split_equivalence_groups(dimension: str, tmp_path: Path) -> None:
    skills = _equivalent_skills(tmp_path, dimension, 4)
    first_group = _equivalence_group(dimension, skills[:2])
    second_group = _equivalence_group(dimension, skills[2:])
    annotated = tuple(
        _annotate_equivalence(
            dimension,
            skill,
            first_group if index < 2 else second_group,
        )
        for index, skill in enumerate(skills)
    )

    with pytest.raises(ValueError, match="equivalence groups"):
        ScanReport(
            source=skills[0].candidate.source,
            skills=annotated,
            duplicates=(first_group, second_group) if dimension == "duplicate" else (),
            name_conflicts=(first_group, second_group) if dimension == "name" else (),  # type: ignore[arg-type]
        )


@pytest.mark.parametrize("dimension", ["duplicate", "name"])
def test_scan_report_rejects_missing_equivalence_group(dimension: str, tmp_path: Path) -> None:
    skills = _equivalent_skills(tmp_path, dimension, 2)

    with pytest.raises(ValueError, match="equivalence groups"):
        ScanReport(source=skills[0].candidate.source, skills=skills)


@pytest.mark.parametrize(
    ("dimension", "reason_code"),
    [
        ("duplicate", ReasonCode.DUPLICATE_CONTENT),
        ("name", ReasonCode.NAME_CONFLICT),
    ],
)
def test_scan_report_rejects_equivalence_reason_on_nonmember(
    dimension: str,
    reason_code: ReasonCode,
    tmp_path: Path,
) -> None:
    skill = _equivalent_skills(tmp_path, dimension, 1)[0]
    skill = replace(skill, reasons=(*skill.reasons, _reason(reason_code)))

    with pytest.raises(ValueError, match="equivalence reason"):
        ScanReport(source=skill.candidate.source, skills=(skill,))


def test_import_plan_serializes_destination_mapping(tmp_path: Path) -> None:
    skill = _analyzed_skill(tmp_path)
    record = ImportRecord(
        name="x",
        content_hash=SHA256,
        destination=f"x--{SHA256[:12]}",
        candidate_ids=(skill.candidate_id,),
    )
    plan = ImportPlan(selected=(skill,), rejected=(), records=(record,))

    assert plan.to_dict()["records"][0]["contentHash"] == SHA256
    assert plan.to_dict()["records"][0]["destination"] == f"x--{SHA256[:12]}"


def test_import_record_requires_sorted_unique_candidate_ids() -> None:
    with pytest.raises(ValueError, match="sorted and unique"):
        ImportRecord(
            name="x",
            content_hash=SHA256,
            destination=f"x--{SHA256[:12]}",
            candidate_ids=("candidate-b", "candidate-a", "candidate-a"),
        )


def test_import_plan_records_exactly_cover_selected_content_groups(tmp_path: Path) -> None:
    first = _analyzed_skill_at(tmp_path, "skills/one", name="one", content_hash=SHA256)
    second_hash = "b" * 64
    second = _analyzed_skill_at(
        tmp_path,
        "skills/two",
        name="two",
        content_hash=second_hash,
    )
    only_first = ImportRecord(
        name="one",
        content_hash=SHA256,
        destination=f"one--{SHA256[:12]}",
        candidate_ids=(first.candidate_id,),
    )

    with pytest.raises(ValueError, match="exactly cover selected content groups"):
        ImportPlan(selected=(first, second), rejected=(), records=(only_first,))


def test_import_plan_rejects_overlapping_partition(tmp_path: Path) -> None:
    skill = _analyzed_skill(tmp_path)
    record = ImportRecord(
        name="x",
        content_hash=SHA256,
        destination=f"x--{SHA256[:12]}",
        candidate_ids=(skill.candidate_id,),
    )
    rejected = replace(
        skill,
        static_classification=Classification.AMBIGUOUS,
        classification=Classification.AMBIGUOUS,
    )
    object.__setattr__(rejected.candidate, "candidate_id", skill.candidate_id)

    with pytest.raises(ValueError, match="disjoint"):
        ImportPlan(selected=(skill,), rejected=(rejected,), records=(record,))


def test_import_plan_rejects_nfc_casefold_destination_collision(tmp_path: Path) -> None:
    first = _analyzed_skill_at(tmp_path, "skills/one", name="one", content_hash=SHA256)
    second_hash = "b" * 64
    second = _analyzed_skill_at(
        tmp_path,
        "skills/two",
        name="two",
        content_hash=second_hash,
    )
    records = (
        ImportRecord(
            name="one",
            content_hash=SHA256,
            destination="Caf\u00e9--aaaaaaaaaaaa",
            candidate_ids=(first.candidate_id,),
        ),
        ImportRecord(
            name="two",
            content_hash=second_hash,
            destination="Cafe\u0301--AAAAAAAAAAAA",
            candidate_ids=(second.candidate_id,),
        ),
    )

    with pytest.raises(ValueError, match="destinations must be unique"):
        ImportPlan(selected=(first, second), rejected=(), records=records)


def test_limits_are_immutable_and_match_approved_defaults() -> None:
    limits = Limits()

    assert limits.git_timeout_seconds == 60
    assert limits.fm_timeout_seconds == 60
    assert limits.max_archive_bytes == 100 * 1024 * 1024
    assert limits.max_entries == 10_000
    assert limits.max_candidates == 1_000
    assert limits.max_scan_bytes == 250 * 1024 * 1024
    assert limits.max_file_bytes == 10 * 1024 * 1024
    assert limits.max_depth == 64
    assert limits.max_fm_context_chars == 128 * 1024
    assert limits.max_fm_response_bytes == 1024 * 1024
    assert limits.max_fm_reviews == 50
    assert limits.max_manifest_bytes == 10 * 1024 * 1024
    assert limits.to_dict()["maxCandidates"] == 1_000
    assert limits.to_dict()["maxManifestBytes"] == 10 * 1024 * 1024
    with pytest.raises(ValueError, match="resource limits must be positive"):
        Limits(max_candidates=0)
    with pytest.raises(FrozenInstanceError):
        limits.max_entries = 1  # type: ignore[misc]


def test_limits_preserve_existing_positional_parameter_order() -> None:
    limits = Limits(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12)

    assert limits.git_timeout_seconds == 1
    assert limits.fm_timeout_seconds == 2
    assert limits.max_archive_bytes == 3
    assert limits.max_entries == 4
    assert limits.max_scan_bytes == 5
    assert limits.max_file_bytes == 6
    assert limits.max_depth == 7
    assert limits.max_fm_context_chars == 8
    assert limits.max_fm_response_bytes == 9
    assert limits.max_fm_reviews == 10
    assert limits.max_manifest_bytes == 11
    assert limits.max_candidates == 12
    assert limits.to_dict()["maxCandidates"] == 12


def test_importer_error_exposes_only_bounded_public_text() -> None:
    secret_tail = "SECRET_RAW_BODY"
    error = ImporterError("SOURCE_FAILED", "safe summary" + "x" * 600 + secret_tail)

    assert error.code == "SOURCE_FAILED"
    assert len(error.message) == ImporterError.MAX_MESSAGE_LENGTH
    assert secret_tail not in str(error)
    assert not hasattr(error, "raw_body")
