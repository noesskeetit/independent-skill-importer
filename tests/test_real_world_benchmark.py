from __future__ import annotations

import json
import re
import sys
from collections.abc import Callable, Iterator, Mapping
from pathlib import Path
from typing import Any, cast

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from benchmarks.real_world import run as benchmark_runner  # noqa: E402
from benchmarks.real_world.run import (  # noqa: E402
    ManifestValidationError,
    load_manifest,
    render_markdown,
    run_benchmark,
    write_outputs,
)
from benchmarks.real_world.run import (  # noqa: E402
    main as benchmark_main,
)
from skill_importer.errors import ImporterError  # noqa: E402
from skill_importer.models import SourceSpec  # noqa: E402
from skill_importer.pipeline import ScanOptions  # noqa: E402

CASES_PATH = ROOT / "benchmarks" / "real_world" / "cases.json"
SHA = "0123456789abcdef0123456789abcdef01234567"


def _expected_candidate(
    root: str,
    *,
    name: str | None = None,
    classification: str = "portable",
    reason: str = "STANDALONE_NO_PLUGIN_BOUNDARY",
) -> dict[str, object]:
    return {
        "root": root,
        "name": name if name is not None else root,
        "staticClassification": classification,
        "finalClassification": classification,
        "staticReasonCodes": [reason],
        "finalReasonCodes": [reason],
        "provenanceLinks": [f"https://github.com/example/skills/blob/{SHA}/{root}/SKILL.md#L1-L3"],
    }


def _case(index: int, *, expected_error: str | None = None) -> dict[str, object]:
    root = "scale" if expected_error is not None else f"skill-{index:02d}"
    candidate = (
        _expected_candidate(
            root,
            name="invalid-candidate",
            classification="invalid",
            reason="INVALID_FRONTMATTER",
        )
        if expected_error is not None
        else _expected_candidate(root)
    )
    return {
        "id": f"C{index:02d}-offline-case",
        "category": "scale" if expected_error is not None else "standalone",
        "coverageMode": "exact",
        "source": {
            "inputUrl": "https://github.com/example/skills",
            "canonicalUrl": "https://github.com/example/skills.git",
            "commitSha": SHA,
            "subpath": root,
        },
        "expected": {
            "operationalError": expected_error,
            "candidates": [candidate],
        },
    }


def _manifest_payload() -> dict[str, Any]:
    cases = [_case(index) for index in range(1, 10)]
    cases.append(_case(10, expected_error="SCAN_LIMIT_EXCEEDED"))
    return {"schemaVersion": "1.0", "cases": cases}


def _write_manifest(tmp_path: Path, payload: Mapping[str, object]) -> Path:
    path = tmp_path / "cases.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def _scan_payload(
    spec: SourceSpec,
    *,
    classification: str = "portable",
    reason: str = "STANDALONE_NO_PLUGIN_BOUNDARY",
    resolved_sha: str | None = None,
) -> dict[str, Any]:
    root = spec.subpath or "skill"
    return {
        "schemaVersion": "1.0",
        "source": {
            "kind": "github",
            "input": spec.value,
            "canonicalUrl": "https://github.com/example/skills.git",
            "resolvedCommitSha": resolved_sha or spec.ref,
            "snapshotSha256": "0" * 64,
            "discoveryScope": root,
        },
        "skills": [
            {
                "root": root,
                "name": root,
                "staticClassification": classification,
                "classification": classification,
                "reasons": [
                    {
                        "code": reason,
                        "message": "offline fixture",
                        "evidence": [],
                    }
                ],
            }
        ],
        "duplicateGroups": [],
        "nameConflictGroups": [],
        "counts": {
            "total": 1,
            "portable": int(classification == "portable"),
            "plugin_bound": int(classification == "plugin_bound"),
            "ambiguous": int(classification == "ambiguous"),
            "invalid": int(classification == "invalid"),
            "blocked": int(classification == "blocked"),
        },
    }


def _clock() -> Callable[[], float]:
    values: Iterator[float] = iter(float(index) for index in range(100))
    return lambda: next(values)


def test_checked_in_manifest_contains_exactly_ten_pinned_research_cases() -> None:
    manifest = load_manifest(CASES_PATH)

    assert manifest.schema_version == "1.0"
    assert [case.case_id for case in manifest.cases] == [
        "C01-openai-blob-parent",
        "C02-openai-system-monorepo",
        "C03-anthropic-skills-only",
        "C04-anthropic-mixed-independent",
        "C05-openai-reverse-dependency",
        "C06-openai-figma-plugin-bound",
        "C07-openai-outside-boundary",
        "C08-openclaw-scale-invalid",
        "C09-microsoft-duplicate-layout",
        "C10-huggingface-complex-ambiguous",
    ]
    assert len(manifest.cases) == 10
    assert all(re.fullmatch(r"[0-9a-f]{40}", case.source.commit_sha) for case in manifest.cases)
    assert all(case.expected.candidates for case in manifest.cases)
    assert all(
        candidate.provenance_links
        for case in manifest.cases
        for candidate in case.expected.candidates
    )
    scale_case = manifest.cases[7]
    assert scale_case.expected.operational_error == "SCAN_LIMIT_EXCEEDED"
    assert scale_case.expected.candidates[0].static_classification == "invalid"


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (
            lambda payload: payload["cases"][0]["source"].update(commitSha="main"),
            "commitSha",
        ),
        (
            lambda payload: payload["cases"][1].update(id=payload["cases"][0]["id"]),
            "duplicate case id",
        ),
        (
            lambda payload: payload["cases"][0]["expected"]["candidates"][0].update(
                staticClassification="maybe"
            ),
            "staticClassification",
        ),
        (
            lambda payload: payload["cases"][0]["source"].update(
                canonicalUrl="https://github.com/other/skills.git"
            ),
            "canonicalUrl",
        ),
        (
            lambda payload: payload["cases"][0]["expected"]["candidates"][0].update(
                provenanceLinks=[f"https://github.com/other/skills/blob/{SHA}/skill-01/SKILL.md#L1"]
            ),
            "provenanceLinks",
        ),
        (
            lambda payload: payload["cases"][0]["expected"]["candidates"][0].update(
                provenanceLinks=[
                    f"https://github.com/example/skills/blob/{'f' * 40}/skill-01/SKILL.md#L1"
                ]
            ),
            "provenanceLinks",
        ),
        (
            lambda payload: payload["cases"][0]["expected"]["candidates"][0].update(
                provenanceLinks=[
                    f"https://github.com/example/skills/blob/{SHA}/../../tree/main/SKILL.md#L1"
                ]
            ),
            "provenanceLinks",
        ),
        (
            lambda payload: payload["cases"][0]["expected"]["candidates"][0].update(
                provenanceLinks=[
                    f"https://github.com/example/skills/blob/{SHA}\\..\\tree\\main\\SKILL.md#L1"
                ]
            ),
            "provenanceLinks",
        ),
    ],
)
def test_manifest_validation_rejects_invalid_or_mutable_oracle(
    tmp_path: Path,
    mutate: Callable[[dict[str, Any]], object],
    message: str,
) -> None:
    payload = _manifest_payload()
    mutate(payload)

    with pytest.raises(ManifestValidationError, match=message):
        load_manifest(_write_manifest(tmp_path, payload))


def test_runner_uses_injected_scan_offline_and_reports_expected_operational_error(
    tmp_path: Path,
) -> None:
    manifest = load_manifest(_write_manifest(tmp_path, _manifest_payload()))
    calls: list[tuple[SourceSpec, ScanOptions]] = []

    def fake_scan(spec: SourceSpec, options: ScanOptions) -> Mapping[str, object]:
        calls.append((spec, options))
        if spec.subpath == "scale":
            raise ImporterError("SCAN_LIMIT_EXCEEDED", "offline scale fixture")
        return _scan_payload(spec)

    result = run_benchmark(manifest, scan=fake_scan, clock=_clock(), use_llm=False)
    payload = cast(dict[str, Any], result.to_dict())

    assert len(calls) == 10
    assert all(spec.ref == SHA for spec, _options in calls)
    assert all(not options.use_llm for _spec, options in calls)
    assert payload["summary"] == {
        "total": 10,
        "sourceSemanticVerified": 9,
        "expectedOperationalGuards": 1,
        "disagreed": 0,
        "operationalErrors": 1,
    }
    assert payload["cases"][0]["durationMs"] == 1000.0
    error_case = payload["cases"][-1]
    assert error_case["actual"]["error"]["code"] == "SCAN_LIMIT_EXCEEDED"
    assert error_case["actual"]["resolvedCommitSha"] is None
    assert error_case["candidateAgreement"] is None
    assert error_case["reasonCodeMatch"] is None
    assert error_case["errorAgreement"] is True
    assert error_case["agreement"] is None


def test_runner_preserves_manual_labels_and_surfaces_disagreement(tmp_path: Path) -> None:
    manifest_path = _write_manifest(tmp_path, _manifest_payload())
    manifest = load_manifest(manifest_path)

    def fake_scan(spec: SourceSpec, options: ScanOptions) -> Mapping[str, object]:
        del options
        if spec.subpath == "scale":
            raise ImporterError("SCAN_LIMIT_EXCEEDED", "offline scale fixture")
        if spec.subpath == "skill-01":
            return _scan_payload(
                spec,
                classification="plugin_bound",
                reason="REFERENCE_OUTSIDE_SKILL_ROOT",
                resolved_sha="f" * 40,
            )
        return _scan_payload(spec)

    result = run_benchmark(manifest, scan=fake_scan, clock=_clock(), use_llm=False)
    first = cast(dict[str, Any], result.to_dict())["cases"][0]

    assert first["expected"]["candidates"][0]["classification"] == "portable"
    assert first["actual"]["candidates"][0]["classification"] == "plugin_bound"
    assert first["shaAgreement"] is False
    assert first["candidateAgreement"] is False
    assert first["reasonCodeMatch"] is False
    assert first["agreement"] is False
    reloaded = load_manifest(manifest_path)
    assert reloaded.cases[0].expected.candidates[0].static_classification == "portable"


def test_runner_rejects_actual_source_identity_mismatch(tmp_path: Path) -> None:
    manifest = load_manifest(_write_manifest(tmp_path, _manifest_payload()))

    def fake_scan(spec: SourceSpec, options: ScanOptions) -> Mapping[str, object]:
        del options
        if spec.subpath == "scale":
            raise ImporterError("SCAN_LIMIT_EXCEEDED", "offline scale fixture")
        payload = _scan_payload(spec)
        if spec.subpath == "skill-01":
            payload["source"]["canonicalUrl"] = "https://github.com/other/skills.git"
        return payload

    result = run_benchmark(manifest, scan=fake_scan, clock=_clock(), use_llm=False)
    first = cast(dict[str, Any], result.to_dict())["cases"][0]

    assert first["actual"]["canonicalUrl"] == "https://github.com/other/skills.git"
    assert first["sourceAgreement"] is False
    assert first["agreement"] is False


def test_runner_requires_exact_reason_codes_for_expected_candidates(tmp_path: Path) -> None:
    manifest = load_manifest(_write_manifest(tmp_path, _manifest_payload()))

    def fake_scan(spec: SourceSpec, options: ScanOptions) -> Mapping[str, object]:
        del options
        if spec.subpath == "scale":
            raise ImporterError("SCAN_LIMIT_EXCEEDED", "offline scale fixture")
        payload = _scan_payload(spec)
        if spec.subpath == "skill-01":
            payload["skills"][0]["reasons"].append(
                {
                    "code": "NAME_CONFLICT",
                    "message": "unexpected extra reason",
                    "evidence": [],
                }
            )
        return payload

    result = run_benchmark(manifest, scan=fake_scan, clock=_clock(), use_llm=False)
    first = cast(dict[str, Any], result.to_dict())["cases"][0]

    assert first["candidateAgreement"] is True
    assert first["reasonCodeMatch"] is False
    assert first["agreement"] is False


def test_json_and_markdown_outputs_include_required_benchmark_fields(tmp_path: Path) -> None:
    manifest = load_manifest(_write_manifest(tmp_path, _manifest_payload()))

    def fake_scan(spec: SourceSpec, options: ScanOptions) -> Mapping[str, object]:
        del options
        if spec.subpath == "scale":
            raise ImporterError("SCAN_LIMIT_EXCEEDED", "offline scale fixture")
        return _scan_payload(spec)

    result = run_benchmark(manifest, scan=fake_scan, clock=_clock(), use_llm=False)
    json_path = tmp_path / "result.json"
    markdown_path = tmp_path / "result.md"

    write_outputs(result, json_path=json_path, markdown_path=markdown_path)

    written = json.loads(json_path.read_text(encoding="utf-8"))
    assert written["cases"][0]["expectedCommitSha"] == SHA
    assert written["cases"][0]["actual"]["candidates"][0]["root"] == "skill-01"
    assert written["summary"]["sourceSemanticVerified"] == 9
    assert written["summary"]["expectedOperationalGuards"] == 1
    markdown = markdown_path.read_text(encoding="utf-8")
    assert markdown == render_markdown(result)
    assert "Source/semantic verified: 9/10. Expected operational guards: 1." in markdown
    assert "| Case | SHA | Expected | Actual | Outcome | Reasons | Duration | Error |" in markdown
    assert SHA in markdown
    assert "skill-01" in markdown
    assert "SCAN_LIMIT_EXCEEDED" in markdown
    assert "guard match" in markdown


def test_output_write_rejects_symlink_to_protected_manifest(tmp_path: Path) -> None:
    manifest_path = _write_manifest(tmp_path, _manifest_payload())
    original_manifest = manifest_path.read_bytes()
    manifest = load_manifest(manifest_path)

    def fake_scan(spec: SourceSpec, options: ScanOptions) -> Mapping[str, object]:
        del options
        if spec.subpath == "scale":
            raise ImporterError("SCAN_LIMIT_EXCEEDED", "offline scale fixture")
        return _scan_payload(spec)

    result = run_benchmark(manifest, scan=fake_scan, clock=_clock(), use_llm=False)
    json_path = tmp_path / "result.json"
    markdown_path = tmp_path / "result.md"
    json_path.symlink_to(manifest_path)

    with pytest.raises(ValueError, match="must resolve to distinct files"):
        write_outputs(
            result,
            json_path=json_path,
            markdown_path=markdown_path,
            protected_paths=(("manifest", manifest_path),),
        )

    assert manifest_path.read_bytes() == original_manifest
    assert json_path.is_symlink()


def test_output_write_does_not_follow_parent_swapped_after_protected_path_check(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    manifest_directory = tmp_path / "manual"
    manifest_directory.mkdir()
    manifest_path = _write_manifest(manifest_directory, _manifest_payload())
    original_manifest = manifest_path.read_bytes()
    manifest = load_manifest(manifest_path)

    def fake_scan(spec: SourceSpec, options: ScanOptions) -> Mapping[str, object]:
        del options
        if spec.subpath == "scale":
            raise ImporterError("SCAN_LIMIT_EXCEEDED", "offline scale fixture")
        return _scan_payload(spec)

    result = run_benchmark(manifest, scan=fake_scan, clock=_clock(), use_llm=False)
    output_directory = tmp_path / "output"
    output_directory.mkdir()
    json_path = output_directory / manifest_path.name
    markdown_path = output_directory / "result.md"
    original_check = benchmark_runner._ensure_distinct_paths
    swapped = False

    def swap_parent_after_check(named_paths: object) -> None:
        nonlocal swapped
        original_check(cast(Any, named_paths))
        if swapped:
            return
        swapped = True
        output_directory.rmdir()
        output_directory.symlink_to(manifest_directory, target_is_directory=True)

    monkeypatch.setattr(
        benchmark_runner,
        "_ensure_distinct_paths",
        swap_parent_after_check,
    )

    with pytest.raises((OSError, ValueError)):
        write_outputs(
            result,
            json_path=json_path,
            markdown_path=markdown_path,
            protected_paths=(("manifest", manifest_path),),
        )

    assert manifest_path.read_bytes() == original_manifest
    assert output_directory.is_symlink()


def test_output_write_rejects_output_path_swapped_after_parent_is_pinned(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    manifest_directory = tmp_path / "manual"
    manifest_directory.mkdir()
    manifest_path = _write_manifest(manifest_directory, _manifest_payload())
    original_manifest = manifest_path.read_bytes()
    manifest = load_manifest(manifest_path)

    def fake_scan(spec: SourceSpec, options: ScanOptions) -> Mapping[str, object]:
        del options
        if spec.subpath == "scale":
            raise ImporterError("SCAN_LIMIT_EXCEEDED", "offline scale fixture")
        return _scan_payload(spec)

    result = run_benchmark(manifest, scan=fake_scan, clock=_clock(), use_llm=False)
    json_directory = tmp_path / "json-output"
    json_directory.mkdir()
    pinned_directory = tmp_path / "pinned-json-output"
    json_path = json_directory / manifest_path.name
    markdown_path = tmp_path / "markdown-output" / "result.md"
    original_pin = benchmark_runner._pin_output_parent
    pin_calls = 0

    def swap_path_after_parent_is_pinned(path: Path) -> tuple[Path, int]:
        nonlocal pin_calls
        target, descriptor = original_pin(path)
        pin_calls += 1
        if pin_calls == 1:
            json_directory.rename(pinned_directory)
            json_directory.symlink_to(manifest_directory, target_is_directory=True)
        return target, descriptor

    monkeypatch.setattr(
        benchmark_runner,
        "_pin_output_parent",
        swap_path_after_parent_is_pinned,
    )

    with pytest.raises(ValueError, match="must resolve to distinct files"):
        write_outputs(
            result,
            json_path=json_path,
            markdown_path=markdown_path,
            protected_paths=(("manifest", manifest_path),),
        )

    assert manifest_path.read_bytes() == original_manifest
    assert json_directory.is_symlink()
    assert not (pinned_directory / manifest_path.name).exists()


def test_output_write_supports_a_stable_symlink_in_parent_path(tmp_path: Path) -> None:
    manifest = load_manifest(_write_manifest(tmp_path, _manifest_payload()))

    def fake_scan(spec: SourceSpec, options: ScanOptions) -> Mapping[str, object]:
        del options
        if spec.subpath == "scale":
            raise ImporterError("SCAN_LIMIT_EXCEEDED", "offline scale fixture")
        return _scan_payload(spec)

    result = run_benchmark(manifest, scan=fake_scan, clock=_clock(), use_llm=False)
    real_parent = tmp_path / "real-output"
    real_parent.mkdir()
    alias_parent = tmp_path / "output-alias"
    alias_parent.symlink_to(real_parent, target_is_directory=True)

    write_outputs(
        result,
        json_path=alias_parent / "result.json",
        markdown_path=alias_parent / "result.md",
    )

    assert (real_parent / "result.json").is_file()
    assert (real_parent / "result.md").is_file()


def test_output_paths_must_not_alias_each_other_or_manifest(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    manifest_path = _write_manifest(tmp_path, _manifest_payload())
    original_manifest = manifest_path.read_bytes()
    shared_output = tmp_path / "result"

    exit_code = benchmark_main(
        [
            "--online",
            "--manifest",
            str(manifest_path),
            "--json-out",
            str(shared_output),
            "--markdown-out",
            str(shared_output),
        ]
    )

    assert exit_code == 2
    assert "must resolve to distinct files" in capsys.readouterr().err
    assert not shared_output.exists()

    exit_code = benchmark_main(
        [
            "--online",
            "--manifest",
            str(manifest_path),
            "--json-out",
            str(manifest_path),
            "--markdown-out",
            str(tmp_path / "result.md"),
        ]
    )

    assert exit_code == 2
    assert manifest_path.read_bytes() == original_manifest

    case_variant = tmp_path / "Result"
    exit_code = benchmark_main(
        [
            "--online",
            "--manifest",
            str(manifest_path),
            "--json-out",
            str(case_variant),
            "--markdown-out",
            str(tmp_path / "result"),
        ]
    )

    assert exit_code == 2
    assert not case_variant.exists()


def test_fm_mode_compares_final_labels_without_changing_static_oracle(tmp_path: Path) -> None:
    payload = _manifest_payload()
    candidate = payload["cases"][0]["expected"]["candidates"][0]
    candidate["staticClassification"] = "ambiguous"
    candidate["finalClassification"] = "portable"
    candidate["staticReasonCodes"] = ["MIXED_PLUGIN_AUTONOMY_UNPROVEN"]
    candidate["finalReasonCodes"] = [
        "MIXED_PLUGIN_AUTONOMY_UNPROVEN",
        "FM_PORTABLE_VERIFIED",
    ]
    manifest = load_manifest(_write_manifest(tmp_path, payload))

    def fake_scan(spec: SourceSpec, options: ScanOptions) -> Mapping[str, object]:
        if spec.subpath == "scale":
            raise ImporterError("SCAN_LIMIT_EXCEEDED", "offline scale fixture")
        if spec.subpath == "skill-01":
            assert options.use_llm
            result = _scan_payload(spec)
            skill = result["skills"][0]
            skill["staticClassification"] = "ambiguous"
            skill["reasons"] = [
                {
                    "code": "MIXED_PLUGIN_AUTONOMY_UNPROVEN",
                    "message": "offline fixture",
                    "evidence": [],
                },
                {
                    "code": "FM_PORTABLE_VERIFIED",
                    "message": "offline fixture",
                    "evidence": [],
                },
            ]
            return result
        return _scan_payload(spec)

    result = run_benchmark(manifest, scan=fake_scan, clock=_clock(), use_llm=True)
    first = cast(dict[str, Any], result.to_dict())["cases"][0]

    assert first["mode"] == "fm"
    assert first["expected"]["candidates"][0]["classification"] == "portable"
    assert first["agreement"] is True
    assert manifest.cases[0].expected.candidates[0].static_classification == "ambiguous"
