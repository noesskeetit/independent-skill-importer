"""Recursively discover skill roots and safely validate their YAML frontmatter."""

import math
from collections.abc import Mapping
from pathlib import PurePosixPath

import yaml
from yaml.nodes import MappingNode

from .models import (
    DecisionReason,
    Evidence,
    Inventory,
    PackageBoundary,
    ReasonCode,
    ResolvedSource,
    SkillCandidate,
    ValidationResult,
    build_candidate_id,
)

_ENTRYPOINT_NAMES = frozenset({"SKILL.md", "skill.md"})
_EVIDENCE_VALUE_LIMIT = 256
_MAX_YAML_EVENTS = 4096
_MAX_YAML_DEPTH = 64
_MAX_YAML_ALIASES = 64


class _FrontmatterError(ValueError):
    def __init__(self, message: str, *, field: str = "frontmatter", value: str = "invalid"):
        super().__init__(message)
        self.field = field
        self.value = value


class _NoMergeSafeLoader(yaml.SafeLoader):
    """SafeLoader variant that rejects YAML merge expansion before construction."""

    def flatten_mapping(self, node: MappingNode) -> None:
        if any(key_node.tag == "tag:yaml.org,2002:merge" for key_node, _ in node.value):
            raise _FrontmatterError("YAML merge keys are not allowed in skill frontmatter")
        super().flatten_mapping(node)


def _is_within(path: str, root: str) -> bool:
    return root == "." or path == root or path.startswith(f"{root}/")


def _boundary_depth(boundary: PackageBoundary) -> int:
    return 0 if boundary.root == "." else len(PurePosixPath(boundary.root).parts)


def _innermost_boundary(
    root: str,
    boundaries: tuple[PackageBoundary, ...],
) -> PackageBoundary | None:
    enclosing = [boundary for boundary in boundaries if _is_within(root, boundary.root)]
    if not enclosing:
        return None
    return sorted(enclosing, key=lambda item: (-_boundary_depth(item), item.manifest_path))[0]


def discover_candidates(
    resolved: ResolvedSource,
    inventory: Inventory,
    boundaries: tuple[PackageBoundary, ...],
) -> tuple[SkillCandidate, ...]:
    """Find all entrypoint directories in scope and attach their innermost boundary."""
    entrypoints_by_root: dict[str, dict[str, str]] = {}
    for entry in inventory.entries:
        name = PurePosixPath(entry.path).name
        # A named symlink is still a candidate. Validation and static analysis must
        # surface it as invalid/blocked instead of silently hiding it. Directories with
        # this name are ordinary containers and remain outside discovery.
        if entry.kind not in {"file", "symlink"} or name not in _ENTRYPOINT_NAMES:
            continue
        root = PurePosixPath(entry.path).parent.as_posix()
        entrypoints_by_root.setdefault(root, {})[name] = entry.path

    candidates: list[SkillCandidate] = []
    for root, entrypoints in sorted(entrypoints_by_root.items()):
        if resolved.discovery_scope != "." and not any(
            _is_within(path, resolved.discovery_scope) for path in entrypoints.values()
        ):
            continue
        entrypoint = entrypoints.get("SKILL.md", entrypoints.get("skill.md"))
        if entrypoint is None:  # Defensive: the grouping accepts only these two names.
            continue
        candidates.append(
            SkillCandidate(
                candidate_id=build_candidate_id(resolved, root),
                source=resolved,
                root=root,
                entrypoint=entrypoint,
                enclosing_boundary=_innermost_boundary(root, boundaries),
            )
        )
    return tuple(candidates)


def _bounded_value(value: object) -> str:
    rendered = repr(value)
    if len(rendered) <= _EVIDENCE_VALUE_LIMIT:
        return rendered
    return f"{rendered[: _EVIDENCE_VALUE_LIMIT - 3]}..."


def _invalid_reason(
    candidate: SkillCandidate,
    message: str,
    *,
    field: str,
    value: object,
    line: int = 1,
) -> DecisionReason:
    return DecisionReason(
        code=ReasonCode.INVALID_FRONTMATTER,
        message=message,
        evidence=(
            Evidence(
                path=candidate.entrypoint,
                line=line,
                field=field,
                value=_bounded_value(value),
                detector="validator.frontmatter",
            ),
        ),
    )


def _duplicate_entrypoint_warning(
    candidate: SkillCandidate,
    inventory: Inventory,
) -> tuple[DecisionReason, ...]:
    if PurePosixPath(candidate.entrypoint).name != "SKILL.md":
        return ()
    compatibility_path = "skill.md" if candidate.root == "." else f"{candidate.root}/skill.md"
    compatibility = inventory.by_path.get(compatibility_path)
    if compatibility is None or compatibility.kind != "file":
        return ()
    return (
        DecisionReason(
            code=ReasonCode.DUPLICATE_ENTRYPOINT,
            message="both SKILL.md and skill.md exist; canonical SKILL.md was selected",
            evidence=(
                Evidence(
                    path=compatibility_path,
                    line=1,
                    field="entrypoint",
                    value=f"ignored in favor of {candidate.entrypoint}",
                    detector="discovery.duplicate_entrypoint",
                ),
            ),
        ),
    )


def _preflight_yaml(document: str) -> None:
    depth = 0
    aliases = 0
    try:
        for count, event in enumerate(yaml.parse(document, Loader=yaml.SafeLoader), start=1):
            if count > _MAX_YAML_EVENTS:
                raise _FrontmatterError("frontmatter exceeds the YAML node limit")
            if isinstance(event, (yaml.MappingStartEvent, yaml.SequenceStartEvent)):
                depth += 1
                if depth > _MAX_YAML_DEPTH:
                    raise _FrontmatterError("frontmatter exceeds the YAML depth limit")
            elif isinstance(event, (yaml.MappingEndEvent, yaml.SequenceEndEvent)):
                depth -= 1
            elif isinstance(event, yaml.AliasEvent):
                aliases += 1
                if aliases > _MAX_YAML_ALIASES:
                    raise _FrontmatterError("frontmatter exceeds the YAML alias limit")
    except (yaml.YAMLError, RecursionError) as exc:
        raise _FrontmatterError("SKILL.md contains malformed YAML frontmatter") from exc


def _extract_frontmatter(content: str) -> object:
    lines = content.splitlines()
    if not lines or lines[0] != "---":
        raise _FrontmatterError("SKILL.md must start with YAML frontmatter", value="missing opener")
    closing_line = next((index for index in range(1, len(lines)) if lines[index] == "---"), None)
    if closing_line is None:
        raise _FrontmatterError("SKILL.md frontmatter is not closed", value="missing closer")
    document = "\n".join(lines[1:closing_line])
    _preflight_yaml(document)
    try:
        return yaml.load(document, Loader=_NoMergeSafeLoader)
    except _FrontmatterError:
        raise
    except (yaml.YAMLError, RecursionError, ValueError, OverflowError) as exc:
        raise _FrontmatterError("SKILL.md contains malformed YAML frontmatter") from exc


def _normalize_json(
    value: object,
    active: set[int] | None = None,
    budget: list[int] | None = None,
    *,
    depth: int = 0,
) -> object:
    if depth > _MAX_YAML_DEPTH:
        raise _FrontmatterError("frontmatter exceeds the normalized depth limit")
    budget = [0] if budget is None else budget
    budget[0] += 1
    if budget[0] > _MAX_YAML_EVENTS:
        raise _FrontmatterError("frontmatter exceeds the normalized node limit")
    if value is None or isinstance(value, (str, bool, int)):
        return value
    if isinstance(value, float):
        if math.isfinite(value):
            return value
        raise _FrontmatterError("frontmatter contains a non-finite number")

    active = set() if active is None else active
    if isinstance(value, Mapping):
        identity = id(value)
        if identity in active:
            raise _FrontmatterError("frontmatter contains a recursive YAML alias")
        active.add(identity)
        try:
            normalized: dict[str, object] = {}
            for key, item in value.items():
                if not isinstance(key, str):
                    raise _FrontmatterError("frontmatter mapping keys must be strings")
                normalized[key] = _normalize_json(item, active, budget, depth=depth + 1)
            return normalized
        finally:
            active.remove(identity)
    if isinstance(value, (list, tuple)):
        identity = id(value)
        if identity in active:
            raise _FrontmatterError("frontmatter contains a recursive YAML alias")
        active.add(identity)
        try:
            return [_normalize_json(item, active, budget, depth=depth + 1) for item in value]
        finally:
            active.remove(identity)
    raise _FrontmatterError(
        "frontmatter contains a non-JSON YAML value", value=type(value).__name__
    )


def _field_line(content: str, field: str) -> int:
    prefix = f"{field}:"
    for number, line in enumerate(content.splitlines(), start=1):
        if line.startswith(prefix):
            return number
    return 1


def _invalid_validation(
    candidate: SkillCandidate,
    inventory: Inventory,
    message: str,
    *,
    field: str,
    value: object,
    frontmatter: Mapping[str, object] | None = None,
    content: str = "",
) -> ValidationResult:
    name_value = frontmatter.get("name") if frontmatter is not None else None
    description_value = frontmatter.get("description") if frontmatter is not None else None
    return ValidationResult(
        valid=False,
        name=name_value if isinstance(name_value, str) else None,
        description=description_value if isinstance(description_value, str) else None,
        frontmatter=frontmatter or {},
        reasons=(
            _invalid_reason(
                candidate,
                message,
                field=field,
                value=value,
                line=_field_line(content, field) if field != "frontmatter" else 1,
            ),
        ),
        warnings=_duplicate_entrypoint_warning(candidate, inventory),
    )


def validate_candidate(candidate: SkillCandidate, inventory: Inventory) -> ValidationResult:
    """Safely parse one candidate; invalid input never aborts validation of siblings."""
    entry = inventory.by_path.get(candidate.entrypoint)
    if entry is None or entry.kind != "file" or entry.content is None:
        return _invalid_validation(
            candidate,
            inventory,
            "skill entrypoint is missing or is not UTF-8 text",
            field="frontmatter",
            value="missing or unreadable entrypoint",
        )

    try:
        loaded = _extract_frontmatter(entry.content)
    except _FrontmatterError as exc:
        return _invalid_validation(
            candidate,
            inventory,
            str(exc),
            field=exc.field,
            value=exc.value,
            content=entry.content,
        )

    if not isinstance(loaded, Mapping):
        return _invalid_validation(
            candidate,
            inventory,
            "frontmatter must be a YAML mapping",
            field="frontmatter",
            value=type(loaded).__name__,
            content=entry.content,
        )

    raw_name = loaded.get("name")
    if not isinstance(raw_name, str) or not raw_name.strip():
        return _invalid_validation(
            candidate,
            inventory,
            "frontmatter field 'name' must be a non-empty string",
            field="name",
            value=raw_name if "name" in loaded else "<missing>",
            content=entry.content,
        )
    raw_description = loaded.get("description")
    if not isinstance(raw_description, str) or not raw_description.strip():
        return _invalid_validation(
            candidate,
            inventory,
            "frontmatter field 'description' must be a non-empty string",
            field="description",
            value=raw_description if "description" in loaded else "<missing>",
            content=entry.content,
        )

    try:
        normalized = _normalize_json(loaded)
    except _FrontmatterError as exc:
        return _invalid_validation(
            candidate,
            inventory,
            str(exc),
            field=exc.field,
            value=exc.value,
            content=entry.content,
        )
    if not isinstance(normalized, Mapping):  # Narrowed by the input mapping, kept fail-closed.
        return _invalid_validation(
            candidate,
            inventory,
            "frontmatter must normalize to a JSON mapping",
            field="frontmatter",
            value=type(normalized).__name__,
            content=entry.content,
        )

    frontmatter = dict(normalized)
    name = frontmatter.get("name")
    if not isinstance(name, str) or not name.strip():
        return _invalid_validation(
            candidate,
            inventory,
            "frontmatter field 'name' must be a non-empty string",
            field="name",
            value=name if "name" in frontmatter else "<missing>",
            frontmatter=frontmatter,
            content=entry.content,
        )
    description = frontmatter.get("description")
    if not isinstance(description, str) or not description.strip():
        return _invalid_validation(
            candidate,
            inventory,
            "frontmatter field 'description' must be a non-empty string",
            field="description",
            value=description if "description" in frontmatter else "<missing>",
            frontmatter=frontmatter,
            content=entry.content,
        )
    return ValidationResult(
        valid=True,
        name=name,
        description=description,
        frontmatter=frontmatter,
        warnings=_duplicate_entrypoint_warning(candidate, inventory),
    )
