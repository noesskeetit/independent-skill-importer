"""Immutable domain models shared across the importer pipeline."""

import hashlib
import json
import math
import re
import unicodedata
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path, PurePosixPath
from types import MappingProxyType

_SHA256_RE = re.compile(r"[0-9a-f]{64}")
_GIT_SHA_RE = re.compile(r"[0-9a-f]{40}")
_WINDOWS_DRIVE_RE = re.compile(r"[A-Za-z]:")
_INVENTORY_KINDS = frozenset({"file", "directory", "symlink", "unsupported"})
_PACKAGE_KINDS = frozenset({"skills_only", "mixed"})


def _validate_relative_path(value: str, field_name: str, *, allow_root: bool = False) -> None:
    message = f"{field_name} must be a normalized relative POSIX path"
    if not value or "\x00" in value or "\\" in value:
        raise ValueError(message)
    if value == ".":
        if allow_root:
            return
        raise ValueError(message)

    path = PurePosixPath(value)
    if (
        path.is_absolute()
        or _WINDOWS_DRIVE_RE.match(value) is not None
        or ".." in path.parts
        or path.as_posix() != value
    ):
        raise ValueError(message)


def _validate_sha256(value: str, field_name: str, *, prefixed: bool = False) -> None:
    candidate = value.removeprefix("sha256:") if prefixed else value
    if prefixed and not value.startswith("sha256:"):
        raise ValueError(f"{field_name} must use sha256:<64 lowercase hex>")
    if _SHA256_RE.fullmatch(candidate) is None:
        raise ValueError(f"{field_name} must be 64 lowercase hexadecimal sha256 characters")


def _is_within(path: str, root: str) -> bool:
    return root == "." or path == root or path.startswith(f"{root}/")


def _freeze_json(value: object, field_name: str) -> object:
    if value is None or isinstance(value, (str, bool, int)):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError(f"{field_name} must contain only finite JSON numbers")
        return value
    if isinstance(value, Mapping):
        frozen: dict[str, object] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise ValueError(f"{field_name} JSON object keys must be strings")
            frozen[key] = _freeze_json(item, field_name)
        return MappingProxyType(frozen)
    if isinstance(value, (list, tuple)):
        return tuple(_freeze_json(item, field_name) for item in value)
    raise ValueError(f"{field_name} must contain only JSON values")


def _thaw_json(value: object) -> object:
    if isinstance(value, Mapping):
        return {key: _thaw_json(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_thaw_json(item) for item in value]
    return value


class Classification(StrEnum):
    """Final or intermediate portability classification."""

    PORTABLE = "portable"
    PLUGIN_BOUND = "plugin_bound"
    AMBIGUOUS = "ambiguous"
    INVALID = "invalid"
    BLOCKED = "blocked"

    @classmethod
    def strongest(cls, values: Iterable["Classification"]) -> "Classification":
        """Return the most restrictive classification in ``values``."""
        order = {
            cls.PORTABLE: 0,
            cls.AMBIGUOUS: 1,
            cls.PLUGIN_BOUND: 2,
            cls.INVALID: 3,
            cls.BLOCKED: 4,
        }
        return max(values, key=order.__getitem__)


class ReasonCode(StrEnum):
    """Machine-readable reason for a classification decision."""

    STANDALONE_NO_PLUGIN_BOUNDARY = "STANDALONE_NO_PLUGIN_BOUNDARY"
    SKILLS_ONLY_PACKAGE = "SKILLS_ONLY_PACKAGE"
    PLUGIN_ROOT_VARIABLE = "PLUGIN_ROOT_VARIABLE"
    REFERENCE_OUTSIDE_SKILL_ROOT = "REFERENCE_OUTSIDE_SKILL_ROOT"
    PLUGIN_OWNED_MCP_TOOL = "PLUGIN_OWNED_MCP_TOOL"
    PLUGIN_COMMAND_REFERENCE = "PLUGIN_COMMAND_REFERENCE"
    PLUGIN_RUNTIME_FILE_REFERENCE = "PLUGIN_RUNTIME_FILE_REFERENCE"
    PLUGIN_RUNTIME_INSIDE_SKILL_ROOT = "PLUGIN_RUNTIME_INSIDE_SKILL_ROOT"
    REFERENCED_BY_PLUGIN_RUNTIME = "REFERENCED_BY_PLUGIN_RUNTIME"
    MISSING_LOCAL_RESOURCE = "MISSING_LOCAL_RESOURCE"
    DYNAMIC_REFERENCE_UNRESOLVED = "DYNAMIC_REFERENCE_UNRESOLVED"
    STATIC_ANALYSIS_INCOMPLETE = "STATIC_ANALYSIS_INCOMPLETE"
    MIXED_PLUGIN_AUTONOMY_UNPROVEN = "MIXED_PLUGIN_AUTONOMY_UNPROVEN"
    SYMLINK_ESCAPE = "SYMLINK_ESCAPE"
    SYMLINK_CYCLE = "SYMLINK_CYCLE"
    PATH_TRAVERSAL = "PATH_TRAVERSAL"
    PATH_COLLISION = "PATH_COLLISION"
    INVALID_FRONTMATTER = "INVALID_FRONTMATTER"
    FILE_TOO_LARGE = "FILE_TOO_LARGE"
    SCAN_LIMIT_EXCEEDED = "SCAN_LIMIT_EXCEEDED"
    DUPLICATE_ENTRYPOINT = "DUPLICATE_ENTRYPOINT"
    DUPLICATE_CONTENT = "DUPLICATE_CONTENT"
    NAME_CONFLICT = "NAME_CONFLICT"
    FM_PORTABLE_VERIFIED = "FM_PORTABLE_VERIFIED"
    FM_PLUGIN_BOUND = "FM_PLUGIN_BOUND"
    FM_REVIEW_UNAVAILABLE = "FM_REVIEW_UNAVAILABLE"
    FM_INVALID_RESPONSE = "FM_INVALID_RESPONSE"
    FM_EVIDENCE_INVALID = "FM_EVIDENCE_INVALID"
    FM_CONTEXT_TRUNCATED = "FM_CONTEXT_TRUNCATED"
    FM_CONTEXT_REDACTED = "FM_CONTEXT_REDACTED"
    FM_CONFIDENCE_TOO_LOW = "FM_CONFIDENCE_TOO_LOW"


class SourceKind(StrEnum):
    """Supported source families."""

    LOCAL = "local"
    GIT = "git"
    GITHUB = "github"


@dataclass(frozen=True, slots=True)
class Evidence:
    """A bounded, source-addressable fact supporting a decision."""

    path: str
    line: int | None
    field: str | None
    value: str
    detector: str

    def __post_init__(self) -> None:
        _validate_relative_path(self.path, "evidence path")
        if self.line is not None and self.line < 1:
            raise ValueError("evidence line must be positive")
        if self.field == "":
            raise ValueError("evidence field must be non-empty when provided")
        if not self.detector:
            raise ValueError("evidence detector must not be empty")

    def to_dict(self) -> dict[str, object]:
        """Serialize evidence using the public JSON field names."""
        return {
            "path": self.path,
            "line": self.line,
            "field": self.field,
            "value": self.value,
            "detector": self.detector,
        }


@dataclass(frozen=True, slots=True)
class DecisionReason:
    """A machine-readable decision reason with supporting evidence."""

    code: ReasonCode
    message: str
    evidence: tuple[Evidence, ...]

    def __post_init__(self) -> None:
        if not self.message:
            raise ValueError("decision reason message must not be empty")
        object.__setattr__(self, "evidence", tuple(self.evidence))

    def to_dict(self) -> dict[str, object]:
        """Serialize the reason for scan and manifest JSON."""
        return {
            "code": self.code.value,
            "message": self.message,
            "evidence": [item.to_dict() for item in self.evidence],
        }


@dataclass(frozen=True, slots=True)
class SourceSpec:
    """Normalized user request for a local, Git, or GitHub source."""

    kind: SourceKind
    value: str
    ref: str | None = None
    subpath: str | None = None

    def __post_init__(self) -> None:
        if not self.value or "\x00" in self.value:
            raise ValueError("source input must not be empty or contain NUL")
        if self.ref is not None and (not self.ref or "\x00" in self.ref):
            raise ValueError("source ref must be non-empty and contain no NUL")
        if self.subpath is not None:
            _validate_relative_path(self.subpath, "source subpath", allow_root=True)

    @classmethod
    def local(cls, path: str | Path, *, subpath: str | None = None) -> "SourceSpec":
        """Build a canonical local source specification."""
        return cls(
            kind=SourceKind.LOCAL,
            value=str(Path(path).expanduser().resolve()),
            subpath=subpath,
        )

    def to_dict(self) -> dict[str, object]:
        """Serialize the source request."""
        return {
            "kind": self.kind.value,
            "input": self.value,
            "ref": self.ref,
            "subpath": self.subpath,
        }


@dataclass(frozen=True, slots=True)
class ResolvedSource:
    """Immutable provenance and private snapshot handle for one source."""

    spec: SourceSpec
    canonical_url: str
    snapshot_root: Path
    snapshot_sha256: str
    discovery_scope: str
    resolved_commit_sha: str | None = None

    def __post_init__(self) -> None:
        if not self.canonical_url:
            raise ValueError("canonical source URL must not be empty")
        if not self.snapshot_root.is_absolute():
            raise ValueError("snapshot root must be absolute")
        _validate_sha256(self.snapshot_sha256, "snapshot_sha256")
        _validate_relative_path(self.discovery_scope, "discovery scope", allow_root=True)
        if (
            self.resolved_commit_sha is not None
            and _GIT_SHA_RE.fullmatch(self.resolved_commit_sha) is None
        ):
            raise ValueError("resolved commit SHA must be 40 lowercase hexadecimal characters")
        if self.spec.kind in {SourceKind.GIT, SourceKind.GITHUB} and (
            self.resolved_commit_sha is None
        ):
            raise ValueError("remote source requires a resolved commit SHA")

    @property
    def revision(self) -> str:
        """Return the immutable revision component used for candidate identity."""
        if self.spec.kind is SourceKind.LOCAL:
            return self.snapshot_sha256
        return self.resolved_commit_sha or self.snapshot_sha256

    def to_dict(self) -> dict[str, object]:
        """Serialize provenance without exposing the temporary snapshot path."""
        return {
            "kind": self.spec.kind.value,
            "input": self.spec.value,
            "canonicalUrl": self.canonical_url,
            "resolvedCommitSha": self.resolved_commit_sha,
            "snapshotSha256": self.snapshot_sha256,
            "discoveryScope": self.discovery_scope,
        }


def build_candidate_id(source: ResolvedSource, root: str) -> str:
    """Build a stable identity from immutable provenance and normalized skill root."""
    _validate_relative_path(root, "skill root", allow_root=True)
    identity = json.dumps(
        [source.canonical_url, source.revision, root],
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode()
    return f"sha256:{hashlib.sha256(identity).hexdigest()}"


def _build_group_id(kind: str, key: str, candidate_ids: tuple[str, ...]) -> str:
    identity = json.dumps(
        [kind, key, list(candidate_ids)],
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    return f"sha256:{hashlib.sha256(identity).hexdigest()}"


@dataclass(frozen=True, slots=True)
class InventoryEntry:
    """One bounded, no-follow entry in a source snapshot."""

    path: str
    kind: str
    size: int
    executable: bool = False
    symlink_target: str | None = None
    sha256: str | None = None
    content: str | None = None

    def __post_init__(self) -> None:
        _validate_relative_path(self.path, "inventory path")
        if self.kind not in _INVENTORY_KINDS:
            raise ValueError(f"unsupported inventory kind: {self.kind}")
        if self.size < 0:
            raise ValueError("inventory size must not be negative")

        if self.kind == "file":
            if self.sha256 is None:
                raise ValueError("file sha256 is required")
            _validate_sha256(self.sha256, "sha256")
            if self.symlink_target is not None:
                raise ValueError("regular file cannot have a symlink target")
        elif self.kind == "symlink":
            if self.symlink_target is None:
                raise ValueError("symlink target is required")
            if self.sha256 is not None or self.content is not None or self.executable:
                raise ValueError("symlink cannot have file content, hash, or executable bit")
        elif self.sha256 is not None or self.content is not None or self.symlink_target is not None:
            raise ValueError("non-file inventory entries cannot have file metadata")

    def to_dict(self) -> dict[str, object]:
        """Serialize inventory metadata."""
        return {
            "path": self.path,
            "kind": self.kind,
            "size": self.size,
            "executable": self.executable,
            "symlinkTarget": self.symlink_target,
            "sha256": self.sha256,
        }


@dataclass(frozen=True, slots=True)
class Inventory:
    """Complete bounded inventory of one immutable snapshot."""

    entries: tuple[InventoryEntry, ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "entries", tuple(self.entries))
        paths = [entry.path for entry in self.entries]
        if len(paths) != len(set(paths)):
            raise ValueError("inventory paths must be unique")

    @property
    def by_path(self) -> dict[str, InventoryEntry]:
        """Index entries by normalized relative path."""
        return {entry.path: entry for entry in self.entries}

    @property
    def total_bytes(self) -> int:
        """Return the total regular-file bytes in the inventory."""
        return sum(entry.size for entry in self.entries if entry.kind == "file")

    def to_dict(self) -> dict[str, object]:
        """Serialize bounded inventory metadata."""
        return {
            "entries": [entry.to_dict() for entry in self.entries],
            "totalBytes": self.total_bytes,
        }


@dataclass(frozen=True, slots=True)
class PackageBoundary:
    """The innermost plugin package enclosing a candidate."""

    root: str
    manifest_path: str
    manifest_kind: str
    package_kind: str

    def __post_init__(self) -> None:
        _validate_relative_path(self.root, "package root", allow_root=True)
        _validate_relative_path(self.manifest_path, "manifest path")
        if not _is_within(self.manifest_path, self.root):
            raise ValueError("manifest path must be within package root")
        if not self.manifest_kind:
            raise ValueError("manifest kind must not be empty")
        if self.package_kind not in _PACKAGE_KINDS:
            raise ValueError("package kind must be skills_only or mixed")

    def to_dict(self) -> dict[str, object]:
        """Serialize package boundary metadata."""
        return {
            "root": self.root,
            "manifestPath": self.manifest_path,
            "manifestKind": self.manifest_kind,
            "packageKind": self.package_kind,
        }


@dataclass(frozen=True, slots=True)
class SkillCandidate:
    """A discovered skill entrypoint with stable source identity."""

    candidate_id: str
    source: ResolvedSource
    root: str
    entrypoint: str
    enclosing_boundary: PackageBoundary | None

    def __post_init__(self) -> None:
        _validate_relative_path(self.root, "skill root", allow_root=True)
        _validate_relative_path(self.entrypoint, "skill entrypoint")
        entrypoint_parent = PurePosixPath(self.entrypoint).parent.as_posix()
        if self.root != entrypoint_parent:
            raise ValueError("skill root must be the entrypoint direct parent")
        if PurePosixPath(self.entrypoint).name not in {"SKILL.md", "skill.md"}:
            raise ValueError("skill entrypoint must be SKILL.md or skill.md")
        if self.candidate_id != build_candidate_id(self.source, self.root):
            raise ValueError("candidate ID must match source provenance and skill root")
        if self.enclosing_boundary is not None and not _is_within(
            self.root, self.enclosing_boundary.root
        ):
            raise ValueError("enclosing package must contain the skill root")

    def to_dict(self) -> dict[str, object]:
        """Serialize candidate identity and provenance."""
        return {
            "candidateId": self.candidate_id,
            "provenance": self.source.to_dict(),
            "root": self.root,
            "entrypoint": self.entrypoint,
            "enclosingPackage": (
                self.enclosing_boundary.to_dict() if self.enclosing_boundary is not None else None
            ),
        }


@dataclass(frozen=True, slots=True)
class ValidationResult:
    """Parsed frontmatter and validation outcome for one candidate."""

    valid: bool
    name: str | None
    description: str | None
    frontmatter: Mapping[str, object]
    reasons: tuple[DecisionReason, ...] = ()
    warnings: tuple[DecisionReason, ...] = ()

    def __post_init__(self) -> None:
        if self.valid and (
            self.name is None
            or not self.name.strip()
            or self.description is None
            or not self.description.strip()
        ):
            raise ValueError("valid frontmatter requires non-empty name and description")
        frozen_frontmatter = _freeze_json(self.frontmatter, "frontmatter")
        if not isinstance(frozen_frontmatter, Mapping):
            raise ValueError("frontmatter must be a JSON object")
        object.__setattr__(self, "frontmatter", frozen_frontmatter)
        object.__setattr__(self, "reasons", tuple(self.reasons))
        object.__setattr__(self, "warnings", tuple(self.warnings))

    def to_dict(self) -> dict[str, object]:
        """Serialize parsed validation data."""
        return {
            "valid": self.valid,
            "name": self.name,
            "description": self.description,
            "frontmatter": _thaw_json(self.frontmatter),
            "reasons": [reason.to_dict() for reason in self.reasons],
            "warnings": [warning.to_dict() for warning in self.warnings],
        }


@dataclass(frozen=True, slots=True)
class ExternalRequirements:
    """External executables and environment variables required by a skill."""

    binaries: tuple[str, ...] = ()
    environment: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "binaries", tuple(self.binaries))
        object.__setattr__(self, "environment", tuple(self.environment))
        if any(not item for item in (*self.binaries, *self.environment)):
            raise ValueError("external requirement names must not be empty")

    def to_dict(self) -> dict[str, object]:
        """Serialize requirements separately from plugin dependencies."""
        return {
            "binaries": list(self.binaries),
            "environment": list(self.environment),
        }


@dataclass(frozen=True, slots=True)
class FmReview:
    """Strict, hash-bound result of an optional FM portability review."""

    analysis_hash: str
    classification: Classification
    confidence: float | None
    reason: DecisionReason
    rationale: str
    model: str | None = None

    def __post_init__(self) -> None:
        _validate_sha256(self.analysis_hash, "analysis_hash", prefixed=True)
        if self.classification not in {
            Classification.PORTABLE,
            Classification.PLUGIN_BOUND,
            Classification.AMBIGUOUS,
        }:
            raise ValueError("FM classification must be portable, plugin_bound, or ambiguous")
        if self.confidence is not None and not 0.0 <= self.confidence <= 1.0:
            raise ValueError("FM confidence must be between 0 and 1")

    @property
    def final_classification(self) -> Classification:
        """Compatibility name used by the pipeline contract."""
        return self.classification

    def to_dict(self) -> dict[str, object]:
        """Serialize a validated FM review."""
        return {
            "analysisHash": self.analysis_hash,
            "classification": self.classification.value,
            "confidence": self.confidence,
            "reason": self.reason.to_dict(),
            "rationale": self.rationale,
            "model": self.model,
        }


@dataclass(frozen=True, slots=True)
class AnalyzedSkill:
    """Complete validation and portability decision for one candidate."""

    candidate: SkillCandidate
    validation: ValidationResult
    static_classification: Classification
    classification: Classification
    reasons: tuple[DecisionReason, ...]
    external_requirements: ExternalRequirements = field(default_factory=ExternalRequirements)
    content_hash: str | None = None
    fm_review: FmReview | None = None
    analysis_method: str = "static"
    duplicate_group: str | None = None
    name_conflict_group: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "reasons", tuple(self.reasons))
        self._validate_validation_classification()
        if self.content_hash is not None:
            _validate_sha256(self.content_hash, "content_hash")
        if self.duplicate_group is not None:
            _validate_sha256(self.duplicate_group, "duplicate_group", prefixed=True)
        if self.name_conflict_group is not None:
            _validate_sha256(self.name_conflict_group, "name_conflict_group", prefixed=True)
        if self.analysis_method not in {"static", "static+fm"}:
            raise ValueError("analysis method must be static or static+fm")
        if self.analysis_method == "static+fm" and self.fm_review is None:
            raise ValueError("static+fm analysis requires an FM review")
        if self.fm_review is not None and self.analysis_method != "static+fm":
            raise ValueError("FM review requires static+fm analysis method")
        if self.static_classification is Classification.AMBIGUOUS:
            self._validate_ambiguous_transition()
        elif self.classification is not self.static_classification:
            raise ValueError("final classification cannot weaken a deterministic static decision")
        elif self.fm_review is not None:
            raise ValueError("FM review is allowed only for ambiguous static classification")
        if self.classification is Classification.PORTABLE:
            self._validate_portable_for_import()

    def _validate_validation_classification(self) -> None:
        fail_closed = {Classification.INVALID, Classification.BLOCKED}
        if not self.validation.valid and (
            self.static_classification not in fail_closed or self.classification not in fail_closed
        ):
            raise ValueError("invalid validation requires invalid or blocked classification")

    def _validate_ambiguous_transition(self) -> None:
        if self.fm_review is None:
            if self.classification is not Classification.AMBIGUOUS:
                raise ValueError("ambiguous classification requires FM review before promotion")
            return
        if self.classification is not self.fm_review.classification:
            raise ValueError("final classification must match FM review classification")
        fm_reason = self.fm_review.reason
        if not any(
            reason.code is fm_reason.code
            and reason.message == fm_reason.message
            and frozenset(reason.evidence) == frozenset(fm_reason.evidence)
            for reason in self.reasons
        ):
            raise ValueError("FM reason must be present in analyzed reasons")
        if self.classification is Classification.PORTABLE:
            if self.fm_review.confidence is None or self.fm_review.confidence < 0.90:
                raise ValueError("portable FM promotion requires confidence >= 0.90")
            if (
                self.fm_review.reason.code is not ReasonCode.FM_PORTABLE_VERIFIED
                or not self.fm_review.reason.evidence
            ):
                raise ValueError("portable FM promotion requires a verified reason with evidence")

    def _validate_portable_for_import(self) -> None:
        self._validate_validation_classification()
        if self.classification is not Classification.PORTABLE:
            raise ValueError("import plan may select only portable skills")
        if self.static_classification is Classification.PORTABLE:
            return
        if self.static_classification is not Classification.AMBIGUOUS:
            raise ValueError("deterministic non-portable classification cannot be imported")
        self._validate_ambiguous_transition()
        if any(
            reason.code.value.startswith("FM_")
            and reason.code is not ReasonCode.FM_PORTABLE_VERIFIED
            for reason in self.reasons
        ):
            raise ValueError("portable FM promotion requires complete unredacted context")

    @property
    def candidate_id(self) -> str:
        return self.candidate.candidate_id

    @property
    def name(self) -> str | None:
        return self.validation.name

    @property
    def reason_codes(self) -> frozenset[ReasonCode]:
        return frozenset(reason.code for reason in self.reasons)

    def to_dict(self) -> dict[str, object]:
        """Serialize the stable per-skill scan schema."""
        return {
            "candidateId": self.candidate.candidate_id,
            "provenance": self.candidate.source.to_dict(),
            "root": self.candidate.root,
            "entrypoint": self.candidate.entrypoint,
            "name": self.validation.name,
            "description": self.validation.description,
            "classification": self.classification.value,
            "staticClassification": self.static_classification.value,
            "analysisMethod": self.analysis_method,
            "enclosingPackage": (
                self.candidate.enclosing_boundary.to_dict()
                if self.candidate.enclosing_boundary is not None
                else None
            ),
            "validation": self.validation.to_dict(),
            "reasons": [reason.to_dict() for reason in self.reasons],
            "externalRequirements": self.external_requirements.to_dict(),
            "contentHash": self.content_hash,
            "duplicateGroup": self.duplicate_group,
            "nameConflictGroup": self.name_conflict_group,
            "fmReview": self.fm_review.to_dict() if self.fm_review is not None else None,
        }


@dataclass(frozen=True, slots=True)
class DuplicateGroup:
    """Candidates sharing the same deterministic payload hash."""

    content_hash: str
    candidate_ids: tuple[str, ...]
    group_id: str = field(init=False)

    def __post_init__(self) -> None:
        _validate_sha256(self.content_hash, "content_hash")
        candidate_ids = tuple(sorted(self.candidate_ids))
        object.__setattr__(self, "candidate_ids", candidate_ids)
        if len(candidate_ids) != len(set(candidate_ids)) or len(candidate_ids) < 2:
            raise ValueError("duplicate group requires at least two distinct candidates")
        if any(not candidate_id for candidate_id in candidate_ids):
            raise ValueError("duplicate group candidate IDs must not be empty")
        object.__setattr__(
            self,
            "group_id",
            _build_group_id("duplicate", self.content_hash, candidate_ids),
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "groupId": self.group_id,
            "contentHash": self.content_hash,
            "candidateIds": list(self.candidate_ids),
        }


@dataclass(frozen=True, slots=True)
class NameConflictGroup:
    """Candidates sharing a parsed name but not an identity."""

    name: str
    candidate_ids: tuple[str, ...]
    group_id: str = field(init=False)

    def __post_init__(self) -> None:
        candidate_ids = tuple(sorted(self.candidate_ids))
        object.__setattr__(self, "candidate_ids", candidate_ids)
        if not self.name:
            raise ValueError("name conflict group requires a non-empty name")
        if len(candidate_ids) != len(set(candidate_ids)) or len(candidate_ids) < 2:
            raise ValueError("name conflict group requires at least two distinct candidates")
        if any(not candidate_id for candidate_id in candidate_ids):
            raise ValueError("name conflict group candidate IDs must not be empty")
        object.__setattr__(
            self,
            "group_id",
            _build_group_id("name-conflict", self.name, candidate_ids),
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "groupId": self.group_id,
            "name": self.name,
            "candidateIds": list(self.candidate_ids),
        }


@dataclass(frozen=True, slots=True)
class ScanReport:
    """Stable source-level scan result used by human and JSON output."""

    source: ResolvedSource
    skills: tuple[AnalyzedSkill, ...]
    duplicates: tuple[DuplicateGroup, ...] = ()
    name_conflicts: tuple[NameConflictGroup, ...] = ()
    warnings: tuple[DecisionReason, ...] = ()
    errors: tuple[DecisionReason, ...] = ()
    schema_version: str = "1.0"

    def __post_init__(self) -> None:
        skills = tuple(
            sorted(self.skills, key=lambda skill: (skill.candidate.root, skill.candidate_id))
        )
        duplicates = tuple(
            sorted(self.duplicates, key=lambda group: (group.content_hash, group.group_id))
        )
        name_conflicts = tuple(
            sorted(self.name_conflicts, key=lambda group: (group.name, group.group_id))
        )
        object.__setattr__(self, "skills", skills)
        object.__setattr__(self, "duplicates", duplicates)
        object.__setattr__(self, "name_conflicts", name_conflicts)
        object.__setattr__(self, "warnings", tuple(self.warnings))
        object.__setattr__(self, "errors", tuple(self.errors))
        if self.schema_version != "1.0":
            raise ValueError("unsupported scan report schema version")
        self._validate_references()

    def _validate_references(self) -> None:
        skills_by_id = {skill.candidate_id: skill for skill in self.skills}
        if len(skills_by_id) != len(self.skills):
            raise ValueError("scan report candidate IDs must be unique")
        if any(skill.candidate.source != self.source for skill in self.skills):
            raise ValueError("scan report skills must share report source provenance")

        expected_duplicate_members: dict[str, list[str]] = {}
        expected_conflict_members: dict[str, list[str]] = {}
        for skill in self.skills:
            if skill.content_hash is not None:
                expected_duplicate_members.setdefault(skill.content_hash, []).append(
                    skill.candidate_id
                )
            if skill.name:
                expected_conflict_members.setdefault(skill.name, []).append(skill.candidate_id)
        expected_duplicates = {
            content_hash: tuple(sorted(candidate_ids))
            for content_hash, candidate_ids in expected_duplicate_members.items()
            if len(candidate_ids) >= 2
        }
        expected_conflicts = {
            name: tuple(sorted(candidate_ids))
            for name, candidate_ids in expected_conflict_members.items()
            if len(candidate_ids) >= 2
        }

        actual_duplicates: dict[str, DuplicateGroup] = {}
        for duplicate_group in self.duplicates:
            if duplicate_group.content_hash in actual_duplicates:
                raise ValueError(
                    "duplicate equivalence groups must have exactly one group per hash"
                )
            actual_duplicates[duplicate_group.content_hash] = duplicate_group
        if set(actual_duplicates) != set(expected_duplicates) or any(
            actual_duplicates[key].candidate_ids != members
            for key, members in expected_duplicates.items()
        ):
            raise ValueError(
                "duplicate equivalence groups must exactly partition all matching skills"
            )

        actual_conflicts: dict[str, NameConflictGroup] = {}
        for conflict_group in self.name_conflicts:
            if conflict_group.name in actual_conflicts:
                raise ValueError("name equivalence groups must have exactly one group per name")
            actual_conflicts[conflict_group.name] = conflict_group
        if set(actual_conflicts) != set(expected_conflicts) or any(
            actual_conflicts[key].candidate_ids != members
            for key, members in expected_conflicts.items()
        ):
            raise ValueError("name equivalence groups must exactly partition all matching skills")

        for skill in self.skills:
            member_duplicate_group = (
                actual_duplicates.get(skill.content_hash)
                if skill.content_hash is not None
                else None
            )
            expected_duplicate_id = (
                member_duplicate_group.group_id if member_duplicate_group is not None else None
            )
            if skill.duplicate_group != expected_duplicate_id:
                raise ValueError("skill duplicate group annotation must exactly match membership")
            has_duplicate_reason = ReasonCode.DUPLICATE_CONTENT in skill.reason_codes
            if has_duplicate_reason != (member_duplicate_group is not None):
                raise ValueError("duplicate equivalence reason must exist if and only if grouped")

            member_conflict_group = actual_conflicts.get(skill.name) if skill.name else None
            expected_conflict_id = (
                member_conflict_group.group_id if member_conflict_group is not None else None
            )
            if skill.name_conflict_group != expected_conflict_id:
                raise ValueError(
                    "skill name conflict group annotation must exactly match membership"
                )
            has_conflict_reason = ReasonCode.NAME_CONFLICT in skill.reason_codes
            if has_conflict_reason != (member_conflict_group is not None):
                raise ValueError("name equivalence reason must exist if and only if grouped")

    @property
    def counts(self) -> dict[str, int]:
        """Derive classification counts from final decisions."""
        counts = {classification.value: 0 for classification in Classification}
        for skill in self.skills:
            counts[skill.classification.value] += 1
        return {"total": len(self.skills), **counts}

    def to_dict(self) -> dict[str, object]:
        """Serialize the stable scan schema version 1.0."""
        return {
            "schemaVersion": self.schema_version,
            "source": self.source.to_dict(),
            "skills": [skill.to_dict() for skill in self.skills],
            "duplicates": [group.to_dict() for group in self.duplicates],
            "nameConflicts": [group.to_dict() for group in self.name_conflicts],
            "counts": self.counts,
            "warnings": [warning.to_dict() for warning in self.warnings],
            "errors": [error.to_dict() for error in self.errors],
        }


@dataclass(frozen=True, slots=True)
class ImportRecord:
    """One physical imported payload and all candidate provenance IDs."""

    name: str
    content_hash: str
    destination: str
    candidate_ids: tuple[str, ...]

    def __post_init__(self) -> None:
        if not self.name:
            raise ValueError("import record name must not be empty")
        _validate_sha256(self.content_hash, "content_hash")
        _validate_relative_path(self.destination, "import destination")
        if len(PurePosixPath(self.destination).parts) != 1:
            raise ValueError("import destination must be one filesystem-safe basename")
        candidate_ids = tuple(self.candidate_ids)
        object.__setattr__(self, "candidate_ids", candidate_ids)
        if not self.candidate_ids or any(not item for item in self.candidate_ids):
            raise ValueError("import record requires candidate provenance")
        if candidate_ids != tuple(sorted(set(candidate_ids))):
            raise ValueError("import record candidate IDs must be sorted and unique")

    def to_dict(self) -> dict[str, object]:
        """Serialize import destination mapping and provenance."""
        return {
            "name": self.name,
            "contentHash": self.content_hash,
            "destination": self.destination,
            "candidateIds": list(self.candidate_ids),
        }


@dataclass(frozen=True, slots=True)
class ImportPlan:
    """Complete plan computed before any destination write."""

    selected: tuple[AnalyzedSkill, ...]
    rejected: tuple[AnalyzedSkill, ...]
    records: tuple[ImportRecord, ...]
    manifest_payload: Mapping[str, object] = field(default_factory=dict)

    def __post_init__(self) -> None:
        selected = tuple(sorted(self.selected, key=lambda skill: skill.candidate_id))
        rejected = tuple(sorted(self.rejected, key=lambda skill: skill.candidate_id))
        records = tuple(
            sorted(self.records, key=lambda record: (record.destination, record.content_hash))
        )
        object.__setattr__(self, "selected", selected)
        object.__setattr__(self, "rejected", rejected)
        object.__setattr__(self, "records", records)
        frozen_manifest = _freeze_json(self.manifest_payload, "manifest payload")
        if not isinstance(frozen_manifest, Mapping):
            raise ValueError("manifest payload must be a JSON object")
        object.__setattr__(self, "manifest_payload", frozen_manifest)
        if any(skill.classification is not Classification.PORTABLE for skill in self.selected):
            raise ValueError("import plan may select only portable skills")
        for skill in self.selected:
            skill._validate_portable_for_import()
        if any(skill.classification is Classification.PORTABLE for skill in self.rejected):
            raise ValueError("portable skills cannot appear in the rejected set")
        selected_ids = tuple(skill.candidate_id for skill in self.selected)
        rejected_ids = tuple(skill.candidate_id for skill in self.rejected)
        if len(selected_ids) != len(set(selected_ids)) or len(rejected_ids) != len(
            set(rejected_ids)
        ):
            raise ValueError("import plan candidate IDs must be unique within each partition")
        if set(selected_ids).intersection(rejected_ids):
            raise ValueError("import plan selected and rejected partitions must be disjoint")

        selected_groups: dict[str, tuple[str, ...]] = {}
        representative_names: dict[str, str] = {}
        for content_hash in sorted(
            {skill.content_hash for skill in self.selected if skill.content_hash is not None}
        ):
            members = tuple(
                sorted(
                    skill.candidate_id
                    for skill in self.selected
                    if skill.content_hash == content_hash
                )
            )
            selected_groups[content_hash] = members
            representative = min(
                (skill for skill in self.selected if skill.content_hash == content_hash),
                key=lambda skill: (skill.candidate.root, skill.candidate_id),
            )
            if representative.name is None or not representative.name.strip():
                raise ValueError("selected skill requires a non-empty parsed name")
            representative_names[content_hash] = representative.name
        if any(skill.content_hash is None for skill in self.selected):
            raise ValueError("selected skill requires a content hash")

        records_by_hash: dict[str, ImportRecord] = {}
        for record in self.records:
            if record.content_hash in records_by_hash:
                raise ValueError("import records must have unique content hashes")
            records_by_hash[record.content_hash] = record
        if set(records_by_hash) != set(selected_groups) or any(
            records_by_hash[content_hash].candidate_ids != candidate_ids
            for content_hash, candidate_ids in selected_groups.items()
        ):
            raise ValueError("import records must exactly cover selected content groups")
        if any(
            records_by_hash[content_hash].name != representative_names[content_hash]
            for content_hash in selected_groups
        ):
            raise ValueError("import record names must match deterministic representatives")

        destination_keys = [
            unicodedata.normalize("NFC", record.destination).casefold() for record in self.records
        ]
        if len(destination_keys) != len(set(destination_keys)):
            raise ValueError("import record destinations must be unique by NFC and case-fold")

    def to_dict(self) -> dict[str, object]:
        """Serialize the plan without writing it."""
        return {
            "selected": [skill.to_dict() for skill in self.selected],
            "rejected": [skill.to_dict() for skill in self.rejected],
            "records": [record.to_dict() for record in self.records],
            "manifest": _thaw_json(self.manifest_payload),
        }
