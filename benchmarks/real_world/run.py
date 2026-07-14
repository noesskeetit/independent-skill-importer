"""Run the pinned real-world corpus through the importer's public scan path."""

from __future__ import annotations

import argparse
import json
import re
import sys
import time
import unicodedata
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from urllib.parse import urlsplit

from skill_importer.errors import ImporterError
from skill_importer.models import Classification, ReasonCode, SourceSpec
from skill_importer.pipeline import ScanOptions, SkillImporterPipeline
from skill_importer.source import parse_source_spec

_SCHEMA_VERSION = "1.0"
_SHA_RE = re.compile(r"[0-9a-f]{40}")
_CASE_ID_RE = re.compile(r"C[0-9]{2}-[a-z0-9-]+")
_ERROR_CODE_RE = re.compile(r"[A-Z][A-Z0-9_]*")
_CLASSIFICATIONS = frozenset(item.value for item in Classification)
_REASON_CODES = frozenset(item.value for item in ReasonCode)
_COVERAGE_MODES = frozenset({"exact", "focused"})

type JsonObject = dict[str, object]
type ScanFunction = Callable[[SourceSpec, ScanOptions], Mapping[str, object]]
type Clock = Callable[[], float]


class ManifestValidationError(ValueError):
    """A stable, path-addressed benchmark manifest validation error."""


@dataclass(frozen=True, slots=True)
class CandidateExpectation:
    """Manual oracle for one candidate; actual scans never mutate it."""

    root: str
    name: str | None
    static_classification: str
    final_classification: str
    static_reason_codes: tuple[str, ...]
    final_reason_codes: tuple[str, ...]
    provenance_links: tuple[str, ...]

    def selected(self, *, use_llm: bool) -> SelectedCandidateExpectation:
        """Select the immutable static or FM oracle for one benchmark lane."""
        return SelectedCandidateExpectation(
            root=self.root,
            name=self.name,
            classification=(self.final_classification if use_llm else self.static_classification),
            reason_codes=(self.final_reason_codes if use_llm else self.static_reason_codes),
        )


@dataclass(frozen=True, slots=True)
class SourceDefinition:
    """Pinned public source used by one case."""

    input_url: str
    canonical_url: str
    commit_sha: str
    subpath: str | None


@dataclass(frozen=True, slots=True)
class ExpectedOutcome:
    """Manual operational and semantic oracle for one case."""

    operational_error: str | None
    candidates: tuple[CandidateExpectation, ...]


@dataclass(frozen=True, slots=True)
class BenchmarkCase:
    """One immutable source case."""

    case_id: str
    category: str
    coverage_mode: str
    source: SourceDefinition
    expected: ExpectedOutcome


@dataclass(frozen=True, slots=True)
class BenchmarkManifest:
    """Validated ten-case corpus."""

    schema_version: str
    cases: tuple[BenchmarkCase, ...]


@dataclass(frozen=True, slots=True)
class SelectedCandidateExpectation:
    """Lane-specific expected candidate summary."""

    root: str
    name: str | None
    classification: str
    reason_codes: tuple[str, ...]

    def to_dict(self) -> JsonObject:
        return {
            "root": self.root,
            "name": self.name,
            "classification": self.classification,
            "reasonCodes": list(self.reason_codes),
        }


@dataclass(frozen=True, slots=True)
class ActualCandidate:
    """Candidate fields consumed from the public scan JSON contract."""

    root: str
    name: str | None
    classification: str
    reason_codes: tuple[str, ...]

    def to_dict(self) -> JsonObject:
        return {
            "root": self.root,
            "name": self.name,
            "classification": self.classification,
            "reasonCodes": list(self.reason_codes),
        }


@dataclass(frozen=True, slots=True)
class ActualError:
    """Bounded public importer error recorded as benchmark data."""

    code: str
    message: str

    def to_dict(self) -> JsonObject:
        return {"code": self.code, "message": self.message}


@dataclass(frozen=True, slots=True)
class CaseResult:
    """Expected/actual comparison for one case."""

    case_id: str
    category: str
    mode: str
    source: SourceDefinition
    expected_error: str | None
    expected_candidates: tuple[SelectedCandidateExpectation, ...]
    actual_canonical_url: str | None
    resolved_commit_sha: str | None
    actual_candidates: tuple[ActualCandidate, ...]
    actual_error: ActualError | None
    source_agreement: bool | None
    sha_agreement: bool | None
    candidate_agreement: bool | None
    reason_code_match: bool | None
    error_agreement: bool
    agreement: bool
    duration_ms: float

    def to_dict(self) -> JsonObject:
        return {
            "id": self.case_id,
            "category": self.category,
            "mode": self.mode,
            "source": {
                "inputUrl": self.source.input_url,
                "canonicalUrl": self.source.canonical_url,
                "subpath": self.source.subpath,
            },
            "expectedCommitSha": self.source.commit_sha,
            "expected": {
                "operationalError": self.expected_error,
                "candidates": [item.to_dict() for item in self.expected_candidates],
            },
            "actual": {
                "canonicalUrl": self.actual_canonical_url,
                "resolvedCommitSha": self.resolved_commit_sha,
                "candidates": [item.to_dict() for item in self.actual_candidates],
                "error": self.actual_error.to_dict() if self.actual_error is not None else None,
            },
            "sourceAgreement": self.source_agreement,
            "shaAgreement": self.sha_agreement,
            "candidateAgreement": self.candidate_agreement,
            "reasonCodeMatch": self.reason_code_match,
            "errorAgreement": self.error_agreement,
            "agreement": self.agreement,
            "durationMs": self.duration_ms,
        }


@dataclass(frozen=True, slots=True)
class BenchmarkResult:
    """Complete machine-readable result."""

    mode: str
    cases: tuple[CaseResult, ...]

    def to_dict(self) -> JsonObject:
        agreed = sum(item.agreement for item in self.cases)
        return {
            "schemaVersion": _SCHEMA_VERSION,
            "mode": self.mode,
            "cases": [item.to_dict() for item in self.cases],
            "summary": {
                "total": len(self.cases),
                "agreed": agreed,
                "disagreed": len(self.cases) - agreed,
                "operationalErrors": sum(item.actual_error is not None for item in self.cases),
            },
        }


def _invalid(path: str, message: str) -> ManifestValidationError:
    return ManifestValidationError(f"{path}: {message}")


def _object(value: object, path: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or any(not isinstance(key, str) for key in value):
        raise _invalid(path, "must be a JSON object")
    return value


def _array(value: object, path: str) -> Sequence[object]:
    if not isinstance(value, list):
        raise _invalid(path, "must be a JSON array")
    return value


def _string(value: object, path: str) -> str:
    if not isinstance(value, str) or not value:
        raise _invalid(path, "must be a non-empty string")
    return value


def _nullable_string(value: object, path: str) -> str | None:
    if value is None:
        return None
    return _string(value, path)


def _keys(
    value: Mapping[str, object],
    path: str,
    *,
    required: frozenset[str],
    optional: frozenset[str] = frozenset(),
) -> None:
    missing = sorted(required - value.keys())
    unknown = sorted(value.keys() - required - optional)
    if missing:
        raise _invalid(path, f"missing keys: {', '.join(missing)}")
    if unknown:
        raise _invalid(path, f"unknown keys: {', '.join(unknown)}")


def _relative_path(value: object, path: str) -> str:
    text = _string(value, path)
    posix = PurePosixPath(text)
    if (
        text == "."
        or posix.is_absolute()
        or "\\" in text
        or ".." in posix.parts
        or posix.as_posix() != text
    ):
        raise _invalid(path, "must be a normalized non-root relative POSIX path")
    return text


def _https_url(
    value: object,
    path: str,
    *,
    canonical: bool = False,
    allow_fragment: bool = False,
) -> str:
    text = _string(value, path)
    parsed = urlsplit(text)
    allowed_hosts = {"github.com"} if canonical else {"github.com", "api.github.com"}
    if (
        parsed.scheme != "https"
        or parsed.hostname not in allowed_hosts
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or (parsed.fragment and not allow_fragment)
        or not parsed.path
    ):
        raise _invalid(path, "must be a safe HTTPS GitHub URL")
    if canonical and not parsed.path.endswith(".git"):
        raise _invalid(path, "canonicalUrl must end in .git")
    return text


def _github_path_parts(value: str, path: str) -> tuple[str, ...]:
    parsed = urlsplit(value)
    if parsed.hostname != "github.com" or "%" in parsed.path or "\\" in parsed.path:
        raise _invalid(path, "must use an unencoded github.com repository path")
    parts = tuple(part for part in parsed.path.split("/") if part)
    if len(parts) < 2 or any(part in {".", ".."} for part in parts):
        raise _invalid(path, "must identify a GitHub owner and repository")
    return parts


def _repository_identity(value: str, path: str, *, canonical: bool = False) -> tuple[str, str]:
    parts = _github_path_parts(value, path)
    repository = parts[1]
    if canonical:
        if len(parts) != 2 or not repository.endswith(".git"):
            raise _invalid(path, "must be an exact GitHub clone URL")
        repository = repository[:-4]
    elif repository.endswith(".git"):
        repository = repository[:-4]
    if not parts[0] or not repository:
        raise _invalid(path, "must identify a GitHub owner and repository")
    return parts[0].casefold(), repository.casefold()


def _validate_provenance(
    source: SourceDefinition,
    candidates: tuple[CandidateExpectation, ...],
    path: str,
) -> None:
    expected_identity = _repository_identity(
        source.canonical_url, f"{path}.source.canonicalUrl", canonical=True
    )
    for candidate_index, candidate in enumerate(candidates):
        for link_index, link in enumerate(candidate.provenance_links):
            link_path = (
                f"{path}.expected.candidates[{candidate_index}].provenanceLinks[{link_index}]"
            )
            if _repository_identity(link, link_path) != expected_identity:
                raise _invalid(link_path, "must reference the source repository")
            parts = _github_path_parts(link, link_path)
            if len(parts) < 4 or parts[2] not in {"blob", "tree"}:
                raise _invalid(link_path, "must be pinned to a blob/tree commit")
            if parts[3] != source.commit_sha:
                raise _invalid(link_path, "must use the source commitSha")


def _string_array(
    value: object, path: str, *, allowed: frozenset[str] | None = None
) -> tuple[str, ...]:
    items = _array(value, path)
    result: list[str] = []
    for index, item in enumerate(items):
        text = _string(item, f"{path}[{index}]")
        if allowed is not None and text not in allowed:
            raise _invalid(f"{path}[{index}]", f"unsupported value: {text}")
        result.append(text)
    if len(result) != len(set(result)):
        raise _invalid(path, "must not contain duplicates")
    return tuple(result)


def _parse_candidate(value: object, path: str) -> CandidateExpectation:
    payload = _object(value, path)
    _keys(
        payload,
        path,
        required=frozenset(
            {
                "root",
                "name",
                "staticClassification",
                "finalClassification",
                "staticReasonCodes",
                "finalReasonCodes",
                "provenanceLinks",
            }
        ),
    )
    root = _relative_path(payload["root"], f"{path}.root")
    name = _nullable_string(payload["name"], f"{path}.name")
    static_classification = _string(payload["staticClassification"], f"{path}.staticClassification")
    final_classification = _string(payload["finalClassification"], f"{path}.finalClassification")
    if static_classification not in _CLASSIFICATIONS:
        raise _invalid(f"{path}.staticClassification", "unsupported classification")
    if final_classification not in _CLASSIFICATIONS:
        raise _invalid(f"{path}.finalClassification", "unsupported classification")
    if static_classification != Classification.AMBIGUOUS.value and (
        final_classification != static_classification
    ):
        raise _invalid(path, "only an ambiguous static decision may change after FM review")
    static_reasons = _string_array(
        payload["staticReasonCodes"], f"{path}.staticReasonCodes", allowed=_REASON_CODES
    )
    final_reasons = _string_array(
        payload["finalReasonCodes"], f"{path}.finalReasonCodes", allowed=_REASON_CODES
    )
    if not static_reasons or not final_reasons:
        raise _invalid(path, "reason code lists must not be empty")
    links = _string_array(payload["provenanceLinks"], f"{path}.provenanceLinks")
    if not links:
        raise _invalid(f"{path}.provenanceLinks", "must not be empty")
    for index, link in enumerate(links):
        _https_url(link, f"{path}.provenanceLinks[{index}]", allow_fragment=True)
    return CandidateExpectation(
        root=root,
        name=name,
        static_classification=static_classification,
        final_classification=final_classification,
        static_reason_codes=static_reasons,
        final_reason_codes=final_reasons,
        provenance_links=links,
    )


def _parse_source(value: object, path: str) -> SourceDefinition:
    payload = _object(value, path)
    _keys(
        payload,
        path,
        required=frozenset({"inputUrl", "canonicalUrl", "commitSha"}),
        optional=frozenset({"subpath"}),
    )
    input_url = _https_url(payload["inputUrl"], f"{path}.inputUrl")
    canonical_url = _https_url(payload["canonicalUrl"], f"{path}.canonicalUrl", canonical=True)
    commit_sha = _string(payload["commitSha"], f"{path}.commitSha")
    if _SHA_RE.fullmatch(commit_sha) is None:
        raise _invalid(f"{path}.commitSha", "must be a 40-character lowercase commit SHA")
    input_identity = _repository_identity(input_url, f"{path}.inputUrl")
    canonical_identity = _repository_identity(canonical_url, f"{path}.canonicalUrl", canonical=True)
    if input_identity != canonical_identity:
        raise _invalid(f"{path}.canonicalUrl", "must identify the inputUrl repository")
    input_parts = _github_path_parts(input_url, f"{path}.inputUrl")
    route = input_parts[2:]
    if route:
        if len(route) < 2 or route[0] not in {"tree", "blob"}:
            raise _invalid(f"{path}.inputUrl", "must be a GitHub repository/tree/blob URL")
        if route[1] != commit_sha:
            raise _invalid(f"{path}.inputUrl", "tree/blob route must use commitSha, not a branch")
    subpath = None
    if "subpath" in payload:
        subpath = _relative_path(payload["subpath"], f"{path}.subpath")
    return SourceDefinition(
        input_url=input_url,
        canonical_url=canonical_url,
        commit_sha=commit_sha,
        subpath=subpath,
    )


def _parse_case(value: object, path: str) -> BenchmarkCase:
    payload = _object(value, path)
    _keys(
        payload,
        path,
        required=frozenset({"id", "category", "coverageMode", "source", "expected"}),
    )
    case_id = _string(payload["id"], f"{path}.id")
    if _CASE_ID_RE.fullmatch(case_id) is None:
        raise _invalid(f"{path}.id", "must match Cdd-lowercase-slug")
    category = _string(payload["category"], f"{path}.category")
    coverage_mode = _string(payload["coverageMode"], f"{path}.coverageMode")
    if coverage_mode not in _COVERAGE_MODES:
        raise _invalid(f"{path}.coverageMode", "must be exact or focused")
    expected_payload = _object(payload["expected"], f"{path}.expected")
    _keys(
        expected_payload,
        f"{path}.expected",
        required=frozenset({"operationalError", "candidates"}),
    )
    operational_error = _nullable_string(
        expected_payload["operationalError"], f"{path}.expected.operationalError"
    )
    if operational_error is not None and _ERROR_CODE_RE.fullmatch(operational_error) is None:
        raise _invalid(f"{path}.expected.operationalError", "must be an uppercase error code")
    source = _parse_source(payload["source"], f"{path}.source")
    candidate_values = _array(expected_payload["candidates"], f"{path}.expected.candidates")
    candidates = tuple(
        _parse_candidate(item, f"{path}.expected.candidates[{index}]")
        for index, item in enumerate(candidate_values)
    )
    if not candidates:
        raise _invalid(f"{path}.expected.candidates", "must not be empty")
    roots = [item.root for item in candidates]
    if len(roots) != len(set(roots)):
        raise _invalid(f"{path}.expected.candidates", "candidate roots must be unique")
    _validate_provenance(source, candidates, path)
    return BenchmarkCase(
        case_id=case_id,
        category=category,
        coverage_mode=coverage_mode,
        source=source,
        expected=ExpectedOutcome(
            operational_error=operational_error,
            candidates=candidates,
        ),
    )


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> JsonObject:
    result: JsonObject = {}
    for key, value in pairs:
        if key in result:
            raise ManifestValidationError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def load_manifest(path: Path) -> BenchmarkManifest:
    """Load and strictly validate the checked-in manual oracle."""
    try:
        with path.open(encoding="utf-8") as handle:
            raw: object = json.load(handle, object_pairs_hook=_reject_duplicate_keys)
    except (OSError, json.JSONDecodeError) as exc:
        raise ManifestValidationError(f"{path}: could not load benchmark manifest: {exc}") from exc
    payload = _object(raw, "manifest")
    _keys(payload, "manifest", required=frozenset({"schemaVersion", "cases"}))
    schema_version = _string(payload["schemaVersion"], "manifest.schemaVersion")
    if schema_version != _SCHEMA_VERSION:
        raise _invalid("manifest.schemaVersion", f"must be {_SCHEMA_VERSION}")
    case_values = _array(payload["cases"], "manifest.cases")
    if len(case_values) != 10:
        raise _invalid("manifest.cases", "must contain exactly 10 cases")
    cases = tuple(
        _parse_case(item, f"manifest.cases[{index}]") for index, item in enumerate(case_values)
    )
    case_ids = [item.case_id for item in cases]
    if len(case_ids) != len(set(case_ids)):
        raise _invalid("manifest.cases", "duplicate case id")
    return BenchmarkManifest(schema_version=schema_version, cases=cases)


def _public_scan(spec: SourceSpec, options: ScanOptions) -> Mapping[str, object]:
    """Use only the importer's public read-only scan API."""
    return SkillImporterPipeline().scan(spec, options).to_dict()


def _scan_object(value: object, path: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or any(not isinstance(key, str) for key in value):
        raise ValueError(f"public scan result {path} must be an object")
    return value


def _scan_array(value: object, path: str) -> Sequence[object]:
    if not isinstance(value, list):
        raise ValueError(f"public scan result {path} must be an array")
    return value


def _scan_string(value: object, path: str, *, nullable: bool = False) -> str | None:
    if nullable and value is None:
        return None
    if not isinstance(value, str) or not value:
        raise ValueError(f"public scan result {path} must be a non-empty string")
    return value


def _read_actual(
    report: Mapping[str, object], *, use_llm: bool
) -> tuple[str, str | None, tuple[ActualCandidate, ...]]:
    source = _scan_object(report.get("source"), "source")
    canonical_url = _scan_string(source.get("canonicalUrl"), "source.canonicalUrl")
    resolved_sha = _scan_string(
        source.get("resolvedCommitSha"), "source.resolvedCommitSha", nullable=True
    )
    skill_values = _scan_array(report.get("skills"), "skills")
    candidates: list[ActualCandidate] = []
    classification_field = "classification" if use_llm else "staticClassification"
    for index, value in enumerate(skill_values):
        path = f"skills[{index}]"
        skill = _scan_object(value, path)
        root = _scan_string(skill.get("root"), f"{path}.root")
        classification = _scan_string(
            skill.get(classification_field), f"{path}.{classification_field}"
        )
        name = _scan_string(skill.get("name"), f"{path}.name", nullable=True)
        reasons: list[str] = []
        for reason_index, reason_value in enumerate(
            _scan_array(skill.get("reasons"), f"{path}.reasons")
        ):
            reason = _scan_object(reason_value, f"{path}.reasons[{reason_index}]")
            code = _scan_string(reason.get("code"), f"{path}.reasons[{reason_index}].code")
            if code is None:  # pragma: no cover - guarded by _scan_string
                raise AssertionError("unreachable")
            reasons.append(code)
        if root is None or classification is None:  # pragma: no cover - guarded above
            raise AssertionError("unreachable")
        candidates.append(
            ActualCandidate(
                root=root,
                name=name,
                classification=classification,
                reason_codes=tuple(sorted(set(reasons))),
            )
        )
    if canonical_url is None:  # pragma: no cover - guarded by _scan_string
        raise AssertionError("unreachable")
    return canonical_url, resolved_sha, tuple(candidates)


def _compare_candidates(
    case: BenchmarkCase,
    expected: tuple[SelectedCandidateExpectation, ...],
    actual: tuple[ActualCandidate, ...],
) -> tuple[bool, bool]:
    expected_by_root = {item.root: item for item in expected}
    actual_by_root = {item.root: item for item in actual}
    if len(actual_by_root) != len(actual):
        return False, False
    expected_roots = set(expected_by_root)
    actual_roots = set(actual_by_root)
    roots_match = (
        expected_roots == actual_roots
        if case.coverage_mode == "exact"
        else expected_roots <= actual_roots
    )
    candidate_match = roots_match and all(
        actual_by_root[root].name == item.name
        and actual_by_root[root].classification == item.classification
        for root, item in expected_by_root.items()
        if root in actual_by_root
    )
    reason_match = expected_roots <= actual_roots and all(
        set(item.reason_codes) <= set(actual_by_root[root].reason_codes)
        for root, item in expected_by_root.items()
    )
    return candidate_match, reason_match


def run_benchmark(
    manifest: BenchmarkManifest,
    *,
    scan: ScanFunction | None = None,
    clock: Clock = time.perf_counter,
    use_llm: bool = False,
) -> BenchmarkResult:
    """Run all cases; injected scans keep ordinary tests fully offline."""
    scan_function = scan or _public_scan
    mode = "fm" if use_llm else "static"
    results: list[CaseResult] = []
    for case in manifest.cases:
        selected = tuple(item.selected(use_llm=use_llm) for item in case.expected.candidates)
        started = clock()
        try:
            spec = parse_source_spec(
                case.source.input_url,
                ref=case.source.commit_sha,
                subpath=case.source.subpath,
            )
            report = scan_function(spec, ScanOptions(use_llm=use_llm))
        except ImporterError as exc:
            duration_ms = round((clock() - started) * 1000, 3)
            error_agreement = case.expected.operational_error == exc.code
            results.append(
                CaseResult(
                    case_id=case.case_id,
                    category=case.category,
                    mode=mode,
                    source=case.source,
                    expected_error=case.expected.operational_error,
                    expected_candidates=selected,
                    actual_canonical_url=None,
                    resolved_commit_sha=None,
                    actual_candidates=(),
                    actual_error=ActualError(code=exc.code, message=exc.message),
                    source_agreement=None,
                    sha_agreement=None,
                    candidate_agreement=None,
                    reason_code_match=None,
                    error_agreement=error_agreement,
                    agreement=error_agreement,
                    duration_ms=duration_ms,
                )
            )
            continue

        duration_ms = round((clock() - started) * 1000, 3)
        actual_canonical_url, resolved_sha, actual_candidates = _read_actual(
            report, use_llm=use_llm
        )
        source_agreement = actual_canonical_url == case.source.canonical_url
        sha_agreement = resolved_sha == case.source.commit_sha
        candidate_agreement, reason_match = _compare_candidates(case, selected, actual_candidates)
        error_agreement = case.expected.operational_error is None
        results.append(
            CaseResult(
                case_id=case.case_id,
                category=case.category,
                mode=mode,
                source=case.source,
                expected_error=case.expected.operational_error,
                expected_candidates=selected,
                actual_canonical_url=actual_canonical_url,
                resolved_commit_sha=resolved_sha,
                actual_candidates=actual_candidates,
                actual_error=None,
                source_agreement=source_agreement,
                sha_agreement=sha_agreement,
                candidate_agreement=candidate_agreement,
                reason_code_match=reason_match,
                error_agreement=error_agreement,
                agreement=(
                    error_agreement
                    and source_agreement
                    and sha_agreement
                    and candidate_agreement
                    and reason_match
                ),
                duration_ms=duration_ms,
            )
        )
    return BenchmarkResult(mode=mode, cases=tuple(results))


def _markdown_text(value: object) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ")


def _candidate_text(
    expected: tuple[SelectedCandidateExpectation, ...],
    actual: tuple[ActualCandidate, ...],
    *,
    use_actual: bool,
) -> str:
    if not use_actual:
        return ", ".join(f"{item.root}:{item.classification}" for item in expected)
    expected_roots = {item.root for item in expected}
    focused = [item for item in actual if item.root in expected_roots]
    extras = len(actual) - len(focused)
    text = ", ".join(f"{item.root}:{item.classification}" for item in focused)
    if extras:
        text += f" (+{extras} other candidates)"
    return text or "—"


def render_markdown(result: BenchmarkResult) -> str:
    """Render a concise human summary without dropping the JSON detail."""
    payload = result.to_dict()
    summary = _scan_object(payload["summary"], "summary")
    lines = [
        "# Real-world skill importer benchmark",
        "",
        f"Mode: `{result.mode}`. Cases: {summary['total']}. "
        f"Agreement: {summary['agreed']}/{summary['total']}.",
        "",
        "| Case | SHA | Expected | Actual | Agreement | Reasons | Duration | Error |",
        "|---|---|---|---|---|---|---:|---|",
    ]
    for item in result.cases:
        actual_sha = item.resolved_commit_sha or "—"
        sha_text = (
            item.source.commit_sha
            if actual_sha == item.source.commit_sha
            else f"{item.source.commit_sha} / {actual_sha}"
        )
        error_text = item.actual_error.code if item.actual_error is not None else "—"
        lines.append(
            "| "
            + " | ".join(
                (
                    _markdown_text(item.case_id),
                    _markdown_text(sha_text),
                    _markdown_text(
                        _candidate_text(
                            item.expected_candidates, item.actual_candidates, use_actual=False
                        )
                    ),
                    _markdown_text(
                        _candidate_text(
                            item.expected_candidates, item.actual_candidates, use_actual=True
                        )
                    ),
                    "yes" if item.agreement else "no",
                    (
                        "n/a"
                        if item.reason_code_match is None
                        else ("match" if item.reason_code_match else "mismatch")
                    ),
                    f"{item.duration_ms:.3f} ms",
                    _markdown_text(error_text),
                )
            )
            + " |"
        )
    lines.append("")
    lines.append(
        "Full candidates, expected labels, actual labels and errors are preserved in JSON."
    )
    lines.append("")
    return "\n".join(lines)


def write_outputs(
    result: BenchmarkResult,
    *,
    json_path: Path,
    markdown_path: Path,
) -> None:
    """Write deterministic JSON and Markdown result files."""
    _ensure_distinct_paths((("JSON", json_path), ("Markdown", markdown_path)))
    json_path.parent.mkdir(parents=True, exist_ok=True)
    markdown_path.parent.mkdir(parents=True, exist_ok=True)
    json_path.write_text(
        json.dumps(
            result.to_dict(),
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
            allow_nan=False,
        )
        + "\n",
        encoding="utf-8",
    )
    markdown_path.write_text(render_markdown(result), encoding="utf-8")


def _ensure_distinct_paths(named_paths: Sequence[tuple[str, Path]]) -> None:
    resolved = [
        (
            label,
            path,
            path.expanduser().resolve(strict=False),
            unicodedata.normalize("NFC", str(path.expanduser().resolve(strict=False))).casefold(),
        )
        for label, path in named_paths
    ]
    for index, (left_label, left_path, left_resolved, left_portable_key) in enumerate(resolved):
        for right_label, right_path, right_resolved, right_portable_key in resolved[index + 1 :]:
            aliases = left_resolved == right_resolved or left_portable_key == right_portable_key
            if not aliases and left_path.exists() and right_path.exists():
                try:
                    aliases = left_path.samefile(right_path)
                except OSError:
                    aliases = False
            if aliases:
                labels = f"{left_label}, {right_label}"
                raise ValueError(f"{labels} paths must resolve to distinct files")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run ten pinned GitHub cases through the public read-only scan API."
    )
    parser.add_argument(
        "--online",
        action="store_true",
        required=True,
        help="Acknowledge that this command fetches public Git repositories.",
    )
    parser.add_argument(
        "--manifest",
        type=Path,
        default=Path(__file__).with_name("cases.json"),
    )
    parser.add_argument("--json-out", type=Path, required=True)
    parser.add_argument("--markdown-out", type=Path, required=True)
    parser.add_argument(
        "--with-llm",
        action="store_true",
        help="Review only statically ambiguous candidates using configured FM transport.",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """CLI entry point; network access is impossible without explicit --online."""
    args = _parser().parse_args(argv)
    try:
        _ensure_distinct_paths(
            (
                ("manifest", args.manifest),
                ("JSON", args.json_out),
                ("Markdown", args.markdown_out),
            )
        )
        manifest = load_manifest(args.manifest)
        result = run_benchmark(manifest, use_llm=args.with_llm)
        write_outputs(result, json_path=args.json_out, markdown_path=args.markdown_out)
    except (ManifestValidationError, OSError, ValueError) as exc:
        print(f"benchmark failed: {exc}", file=sys.stderr)
        return 2
    summary = _scan_object(result.to_dict()["summary"], "summary")
    print(
        f"benchmark complete: {summary['agreed']}/{summary['total']} cases agree; "
        f"JSON={args.json_out} Markdown={args.markdown_out}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
