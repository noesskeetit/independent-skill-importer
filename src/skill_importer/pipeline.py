"""Deterministic scan orchestration over one immutable source snapshot."""

from __future__ import annotations

import hashlib
import os
import tempfile
import unicodedata
from collections.abc import Callable, Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Protocol

from .boundaries import detect_boundaries
from .discovery import discover_candidates, validate_candidate
from .fm_review import (
    DEFAULT_FM_MODEL,
    FmReviewer,
    FmTransport,
    ReviewContext,
    UrllibFmTransport,
)
from .inventory import build_inventory
from .limits import Limits
from .models import (
    AnalyzedSkill,
    Classification,
    DecisionReason,
    DuplicateGroup,
    Evidence,
    Inventory,
    InventoryEntry,
    NameConflictGroup,
    PackageBoundary,
    ReasonCode,
    ResolvedSource,
    ScanReport,
    SkillCandidate,
    SourceSpec,
)
from .source import SourceResolver
from .static_analysis import analyze_static

_MAX_MODEL_CHARS = 256
_CONTENT_HASH_DOMAIN = b"skill-importer-content-v1\0"


class Resolver(Protocol):
    """Injected source resolver boundary used by a scan operation."""

    def resolve(self, spec: SourceSpec, workspace: Path) -> ResolvedSource: ...


FmTransportFactory = Callable[[Limits], FmTransport]
ApiKeyProvider = Callable[[], str | None]


@dataclass(frozen=True, slots=True)
class ScanOptions:
    """Bounded user-controlled options for one scan."""

    use_llm: bool = True
    model: str = DEFAULT_FM_MODEL

    def __post_init__(self) -> None:
        if (
            not isinstance(self.model, str)
            or not self.model.strip()
            or len(self.model) > _MAX_MODEL_CHARS
            or any(unicodedata.category(character).startswith("C") for character in self.model)
        ):
            raise ValueError("FM model must be non-empty, control-free text of at most 256 chars")


@dataclass(frozen=True, slots=True)
class ScanOperation:
    """Private operation result whose immutable snapshot is alive in the context manager."""

    report: ScanReport
    resolved: ResolvedSource
    inventory: Inventory
    boundaries: tuple[PackageBoundary, ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "boundaries", tuple(self.boundaries))
        if self.report.source != self.resolved:
            raise ValueError("scan operation report must use its resolved source")


def _length_prefixed(hasher: object, value: bytes) -> None:
    digest = hasher
    if not hasattr(digest, "update"):  # pragma: no cover - fixed internal call contract
        raise TypeError("hash object must provide update")
    digest.update(len(value).to_bytes(8, "big"))
    digest.update(value)


def _relative_payload_path(path: str, root: str) -> str | None:
    if root == ".":
        return path
    if path == root:
        return None
    prefix = f"{root}/"
    if path.startswith(prefix):
        return path[len(prefix) :]
    return None


def _entry_hash_payload(entry: InventoryEntry) -> bytes:
    if entry.kind == "file":
        if entry.sha256 is None:  # pragma: no cover - InventoryEntry validates this invariant
            raise ValueError("file inventory entry is missing its digest")
        return bytes.fromhex(entry.sha256)
    if entry.kind == "symlink":
        if entry.symlink_target is None:  # pragma: no cover - model invariant
            raise ValueError("symlink inventory entry is missing its target")
        return entry.symlink_target.encode("utf-8", errors="surrogateescape")
    return b""


def compute_skill_content_hash(candidate: SkillCandidate, inventory: Inventory) -> str:
    """Hash exactly the candidate payload using layout-independent relative entry records."""
    records: list[tuple[str, InventoryEntry]] = []
    for entry in inventory.entries:
        relative_path = _relative_payload_path(entry.path, candidate.root)
        if relative_path is not None:
            records.append((relative_path, entry))
    records.sort(key=lambda item: item[0])

    hasher = hashlib.sha256()
    hasher.update(_CONTENT_HASH_DOMAIN)
    for relative_path, entry in records:
        _length_prefixed(hasher, relative_path.encode("utf-8"))
        _length_prefixed(hasher, entry.kind.encode("ascii"))
        _length_prefixed(hasher, b"1" if entry.executable else b"0")
        _length_prefixed(hasher, _entry_hash_payload(entry))
    return hasher.hexdigest()


def _evidence_sort_key(evidence: Evidence) -> tuple[str, int, str, str, str]:
    return (
        evidence.path,
        evidence.line or 0,
        evidence.field or "",
        evidence.value,
        evidence.detector,
    )


def _merge_reasons(*reason_sets: Sequence[DecisionReason]) -> tuple[DecisionReason, ...]:
    grouped: dict[ReasonCode, tuple[set[str], set[Evidence]]] = {}
    for reasons in reason_sets:
        for reason in reasons:
            messages, evidence = grouped.setdefault(reason.code, (set(), set()))
            messages.add(reason.message)
            evidence.update(reason.evidence)
    return tuple(
        DecisionReason(
            code=code,
            message=sorted(messages)[0],
            evidence=tuple(sorted(evidence, key=_evidence_sort_key)),
        )
        for code, (messages, evidence) in sorted(grouped.items(), key=lambda item: item[0].value)
    )


def _default_transport_factory(limits: Limits) -> FmTransport:
    return UrllibFmTransport(max_response_bytes=limits.max_fm_response_bytes)


def _environment_api_key() -> str | None:
    """Prefer explicitly configured FM_API_KEY, then fall back to LLM_API_KEY.

    Presence, rather than truthiness, controls precedence so an explicitly empty or
    malformed primary value reaches the reviewer validation and fails closed instead
    of silently selecting the legacy key.
    """
    if "FM_API_KEY" in os.environ:
        return os.environ["FM_API_KEY"]
    return os.environ.get("LLM_API_KEY")


def _duplicate_reason(skill: AnalyzedSkill, group: DuplicateGroup) -> DecisionReason:
    return DecisionReason(
        code=ReasonCode.DUPLICATE_CONTENT,
        message="candidate payload duplicates another discovered skill",
        evidence=(
            Evidence(
                path=skill.candidate.entrypoint,
                line=None,
                field="contentHash",
                value=group.content_hash,
                detector="pipeline.duplicate_content",
            ),
        ),
    )


def _name_conflict_reason(skill: AnalyzedSkill, group: NameConflictGroup) -> DecisionReason:
    return DecisionReason(
        code=ReasonCode.NAME_CONFLICT,
        message="multiple discovered skills declare the same name",
        evidence=(
            Evidence(
                path=skill.candidate.entrypoint,
                line=None,
                field="name",
                value=group.name,
                detector="pipeline.name_conflict",
            ),
        ),
    )


def _group_and_annotate(
    skills: tuple[AnalyzedSkill, ...],
) -> tuple[tuple[AnalyzedSkill, ...], tuple[DuplicateGroup, ...], tuple[NameConflictGroup, ...]]:
    by_hash: dict[str, list[str]] = {}
    by_name: dict[str, list[str]] = {}
    for skill in skills:
        if skill.content_hash is not None:
            by_hash.setdefault(skill.content_hash, []).append(skill.candidate_id)
        if skill.name:
            by_name.setdefault(skill.name, []).append(skill.candidate_id)

    duplicates = tuple(
        DuplicateGroup(content_hash=content_hash, candidate_ids=tuple(candidate_ids))
        for content_hash, candidate_ids in sorted(by_hash.items())
        if len(set(candidate_ids)) > 1
    )
    name_conflicts = tuple(
        NameConflictGroup(name=name, candidate_ids=tuple(candidate_ids))
        for name, candidate_ids in sorted(by_name.items())
        if len(set(candidate_ids)) > 1
    )
    duplicate_by_candidate = {
        candidate_id: group for group in duplicates for candidate_id in group.candidate_ids
    }
    conflict_by_candidate = {
        candidate_id: group for group in name_conflicts for candidate_id in group.candidate_ids
    }

    annotated: list[AnalyzedSkill] = []
    for skill in skills:
        duplicate = duplicate_by_candidate.get(skill.candidate_id)
        conflict = conflict_by_candidate.get(skill.candidate_id)
        additions: list[DecisionReason] = []
        if duplicate is not None:
            additions.append(_duplicate_reason(skill, duplicate))
        if conflict is not None:
            additions.append(_name_conflict_reason(skill, conflict))
        annotated.append(
            replace(
                skill,
                reasons=_merge_reasons(skill.reasons, additions),
                duplicate_group=duplicate.group_id if duplicate is not None else None,
                name_conflict_group=conflict.group_id if conflict is not None else None,
            )
        )
    return tuple(annotated), duplicates, name_conflicts


class SkillImporterPipeline:
    """Run every read-only scan stage against one operation-owned snapshot."""

    def __init__(
        self,
        *,
        limits: Limits | None = None,
        resolver: Resolver | None = None,
        fm_transport_factory: FmTransportFactory | None = None,
        api_key_provider: ApiKeyProvider | None = None,
    ) -> None:
        self.limits = limits or Limits()
        self._resolver = resolver or SourceResolver(limits=self.limits)
        self._fm_transport_factory = fm_transport_factory or _default_transport_factory
        self._api_key_provider = api_key_provider or _environment_api_key

    def scan(self, spec: SourceSpec, options: ScanOptions | None = None) -> ScanReport:
        """Return the public report only after the private snapshot has been cleaned up."""
        with self.scan_operation(spec, options) as operation:
            return operation.report

    @contextmanager
    def scan_operation(
        self,
        spec: SourceSpec,
        options: ScanOptions | None = None,
    ) -> Iterator[ScanOperation]:
        """Yield a report plus the live immutable snapshot for a future atomic import."""
        scan_options = options or ScanOptions()
        with tempfile.TemporaryDirectory(prefix="skill-importer-scan-") as workspace_value:
            resolved = self._resolver.resolve(spec, Path(workspace_value))
            inventory = build_inventory(resolved, self.limits)
            boundaries = detect_boundaries(inventory)
            candidates = discover_candidates(resolved, inventory, boundaries)
            skills = self._analyze_candidates(
                candidates,
                inventory,
                boundaries,
                scan_options,
            )
            skills, duplicates, conflicts = _group_and_annotate(skills)
            report = ScanReport(
                source=resolved,
                skills=skills,
                duplicates=duplicates,
                name_conflicts=conflicts,
            )
            yield ScanOperation(
                report=report,
                resolved=resolved,
                inventory=inventory,
                boundaries=boundaries,
            )

    def _analyze_candidates(
        self,
        candidates: tuple[SkillCandidate, ...],
        inventory: Inventory,
        boundaries: tuple[PackageBoundary, ...],
        options: ScanOptions,
    ) -> tuple[AnalyzedSkill, ...]:
        reviewer: FmReviewer | None = None
        analyzed: list[AnalyzedSkill] = []
        for candidate in sorted(candidates, key=lambda item: (item.root, item.candidate_id)):
            validation = validate_candidate(candidate, inventory)
            static_result = analyze_static(candidate, validation, inventory, boundaries)
            fm_review = None
            classification = static_result.classification
            analysis_method = "static"
            reasons = _merge_reasons(static_result.reasons, validation.warnings)
            if options.use_llm and static_result.classification is Classification.AMBIGUOUS:
                if reviewer is None:
                    reviewer = FmReviewer(
                        transport=self._fm_transport_factory(self.limits),
                        api_key=self._api_key_provider(),
                        model=options.model,
                        limits=self.limits,
                    )
                fm_review = reviewer.review(
                    ReviewContext(
                        candidate=candidate,
                        validation=validation,
                        static_result=static_result,
                        inventory=inventory,
                        boundaries=boundaries,
                    )
                )
                classification = fm_review.classification
                reasons = _merge_reasons(reasons, (fm_review.reason,))
                analysis_method = "static+fm"
            analyzed.append(
                AnalyzedSkill(
                    candidate=candidate,
                    validation=validation,
                    static_classification=static_result.classification,
                    classification=classification,
                    reasons=reasons,
                    external_requirements=static_result.external_requirements,
                    content_hash=compute_skill_content_hash(candidate, inventory),
                    fm_review=fm_review,
                    analysis_method=analysis_method,
                )
            )
        return tuple(analyzed)
