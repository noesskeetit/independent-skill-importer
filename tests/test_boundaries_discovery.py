"""Plugin-boundary discovery and safe skill frontmatter validation."""

import hashlib
import json
from collections.abc import Callable, Mapping
from dataclasses import replace
from pathlib import Path

import pytest

from skill_importer.boundaries import detect_boundaries
from skill_importer.discovery import discover_candidates, validate_candidate
from skill_importer.inventory import build_inventory
from skill_importer.limits import Limits
from skill_importer.models import (
    Inventory,
    InventoryEntry,
    PackageBoundary,
    ReasonCode,
    ResolvedSource,
    SourceSpec,
)
from skill_importer.source import snapshot_local

FixtureLoader = Callable[[str], tuple[ResolvedSource, Inventory]]
FIXTURES = Path(__file__).parent / "fixtures"


def _file(path: str, content: str) -> InventoryEntry:
    encoded = content.encode()
    return InventoryEntry(
        path=path,
        kind="file",
        size=len(encoded),
        sha256=hashlib.sha256(encoded).hexdigest(),
        content=content,
    )


def _inventory(files: Mapping[str, str]) -> Inventory:
    return Inventory(entries=tuple(_file(path, content) for path, content in sorted(files.items())))


def _resolved(tmp_path: Path, *, discovery_scope: str = ".") -> ResolvedSource:
    return ResolvedSource(
        spec=SourceSpec.local(tmp_path),
        canonical_url=tmp_path.as_uri(),
        snapshot_root=tmp_path.resolve(),
        snapshot_sha256="0" * 64,
        discovery_scope=discovery_scope,
    )


@pytest.fixture
def load_fixture(tmp_path: Path) -> FixtureLoader:
    calls = 0

    def load(name: str) -> tuple[ResolvedSource, Inventory]:
        nonlocal calls
        calls += 1
        resolved = snapshot_local(FIXTURES / name, tmp_path / f"snapshot-{calls}", Limits())
        return resolved, build_inventory(resolved, Limits())

    return load


@pytest.mark.parametrize(
    ("manifest_path", "expected_root"),
    [
        ("package/.plugin/plugin.json", "package"),
        ("package/.claude-plugin/plugin.json", "package"),
        ("package/.codex-plugin/plugin.json", "package"),
        ("package/.cursor-plugin/plugin.json", "package"),
        ("package/.github/plugin/plugin.json", "package"),
        ("package/plugin.json", "package"),
        ("package/gemini-extension.json", "package"),
        ("package/openclaw.plugin.json", "package"),
    ],
)
def test_all_manifest_paths_create_boundary_at_package_root(
    manifest_path: str,
    expected_root: str,
) -> None:
    inventory = _inventory(
        {
            manifest_path: "{}",
            "package/skills/example/SKILL.md": ("---\nname: example\ndescription: Example\n---\n"),
        }
    )

    boundaries = detect_boundaries(inventory)

    assert [(item.manifest_path, item.root) for item in boundaries] == [
        (manifest_path, expected_root)
    ]


def test_metadata_manifest_boundary_is_package_parent(load_fixture: FixtureLoader) -> None:
    _, inventory = load_fixture("skills_only_plugin")

    boundaries = detect_boundaries(inventory)

    assert boundaries[0].manifest_path == ".claude-plugin/plugin.json"
    assert boundaries[0].root == "."
    assert boundaries[0].package_kind == "skills_only"


@pytest.mark.parametrize(
    "marker",
    [
        {"openclaw": {}},
        {"claudePlugin": {}},
        {"codexPlugin": {}},
        {"cursorPlugin": {}},
        {"geminiExtension": {}},
        {"plugin": {}},
        {"claude": {"extensions": ["skills"]}},
        {"codex": {"extensions": {"skills": "skills"}}},
        {"cursor": {"extensions": []}},
        {"gemini": {"extensions": []}},
    ],
)
def test_known_package_json_plugin_markers_create_boundary(marker: object) -> None:
    inventory = _inventory(
        {
            "package/package.json": json.dumps(marker),
            "package/skill/SKILL.md": "---\nname: x\ndescription: x\n---\n",
        }
    )

    boundaries = detect_boundaries(inventory)

    assert len(boundaries) == 1
    assert boundaries[0].root == "package"
    assert boundaries[0].manifest_path == "package/package.json"


@pytest.mark.parametrize(
    "content",
    [
        '{"name": "ordinary-library", "scripts": {"test": "pytest"}}',
        '{"extensions": []}',
        '{"claude": {"other": true}}',
        "{broken json",
        '["plugin"]',
    ],
)
def test_ordinary_or_invalid_package_json_is_not_plugin_boundary(content: str) -> None:
    inventory = _inventory({"package/package.json": content})

    assert detect_boundaries(inventory) == ()


def test_nested_candidate_uses_innermost_enclosing_boundary(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    files = {
        "plugin.json": "{}",
        "outer-skill/SKILL.md": "---\nname: outer\ndescription: outer\n---\n",
        "nested/.cursor-plugin/plugin.json": "{}",
        "nested/inner-skill/SKILL.md": "---\nname: inner\ndescription: inner\n---\n",
    }
    for path, content in files.items():
        destination = source / path
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(content, encoding="utf-8")
    resolved = snapshot_local(source, tmp_path / "snapshot", Limits())
    inventory = build_inventory(resolved, Limits())

    boundaries = detect_boundaries(inventory)
    candidates = discover_candidates(resolved, inventory, boundaries)

    by_root = {candidate.root: candidate for candidate in candidates}
    assert by_root["outer-skill"].enclosing_boundary is not None
    assert by_root["outer-skill"].enclosing_boundary.root == "."
    assert by_root["nested/inner-skill"].enclosing_boundary is not None
    assert by_root["nested/inner-skill"].enclosing_boundary.root == "nested"


def test_package_kind_distinguishes_skills_only_from_mixed(
    load_fixture: FixtureLoader,
) -> None:
    _, skills_inventory = load_fixture("skills_only_plugin")
    _, mixed_inventory = load_fixture("mixed_plugin")

    skills_only = detect_boundaries(skills_inventory)
    mixed = detect_boundaries(mixed_inventory)

    assert skills_only[0].package_kind == "skills_only"
    assert mixed[0].package_kind == "mixed"


def test_discovery_recurses_outside_conventional_skills_directory(
    load_fixture: FixtureLoader,
) -> None:
    resolved, inventory = load_fixture("monorepo")

    candidates = discover_candidates(resolved, inventory, detect_boundaries(inventory))

    assert [candidate.root for candidate in candidates] == [
        "apps/editor/custom-skill",
        "packages/ops/nested/skill-two",
    ]


def test_discovery_scope_filters_candidates_but_keeps_full_boundary_context(
    load_fixture: FixtureLoader,
) -> None:
    resolved, inventory = load_fixture("mixed_plugin")
    scoped = replace(resolved, discovery_scope="skills/alpha")

    candidates = discover_candidates(scoped, inventory, detect_boundaries(inventory))

    assert [candidate.root for candidate in candidates] == ["skills/alpha"]
    assert candidates[0].enclosing_boundary is not None
    assert candidates[0].enclosing_boundary.root == "."
    assert candidates[0].enclosing_boundary.package_kind == "mixed"


def test_skill_outside_adjacent_plugin_boundary_is_standalone(
    load_fixture: FixtureLoader,
) -> None:
    resolved, inventory = load_fixture("adjacent_plugin")

    candidates = discover_candidates(resolved, inventory, detect_boundaries(inventory))

    assert len(candidates) == 1
    assert candidates[0].root == "standalone"
    assert candidates[0].enclosing_boundary is None


@pytest.mark.parametrize(
    ("fixture_name", "expected_entrypoint"),
    [
        ("standalone_skill", "tooling/deep/alpha/SKILL.md"),
        ("lowercase_entrypoint", "tool/skill.md"),
    ],
)
def test_discovery_supports_canonical_and_compatibility_entrypoints(
    fixture_name: str,
    expected_entrypoint: str,
    load_fixture: FixtureLoader,
) -> None:
    resolved, inventory = load_fixture(fixture_name)

    candidates = discover_candidates(resolved, inventory, detect_boundaries(inventory))

    assert [candidate.entrypoint for candidate in candidates] == [expected_entrypoint]


def test_uppercase_entrypoint_wins_and_duplicate_has_warning_evidence(
    tmp_path: Path,
) -> None:
    resolved = _resolved(tmp_path)
    inventory = _inventory(
        {
            "skill/SKILL.md": "---\nname: canonical\ndescription: canonical\n---\n",
            "skill/skill.md": "---\nname: compatibility\ndescription: compatibility\n---\n",
        }
    )

    candidate = discover_candidates(resolved, inventory, detect_boundaries(inventory))[0]
    validation = validate_candidate(candidate, inventory)

    assert candidate.entrypoint == "skill/SKILL.md"
    assert len(validation.warnings) == 1
    assert validation.warnings[0].code is ReasonCode.DUPLICATE_ENTRYPOINT
    assert validation.warnings[0].evidence
    assert validation.warnings[0].evidence[0].path == "skill/skill.md"


def test_invalid_frontmatter_does_not_abort_other_candidates(
    load_fixture: FixtureLoader,
) -> None:
    resolved, inventory = load_fixture("invalid_and_valid")
    candidates = discover_candidates(resolved, inventory, detect_boundaries(inventory))

    validations = [validate_candidate(item, inventory) for item in candidates]

    assert [item.valid for item in validations] == [False, True]
    assert validations[0].reasons[0].code is ReasonCode.INVALID_FRONTMATTER
    assert validations[1].name == "valid"


@pytest.mark.parametrize(
    ("frontmatter", "expected_field"),
    [
        ("name: [", "frontmatter"),
        ("- name\n- description", "frontmatter"),
        ("name: only-name", "description"),
        ("description: only-description", "name"),
        ("name: 7\ndescription: valid", "name"),
        ("name: valid\ndescription: false", "description"),
        ("", "frontmatter"),
        ("name: !!python/object/apply:os.system ['false']\ndescription: x", "frontmatter"),
        ("name: x\ndescription: 2026-07-13", "description"),
    ],
)
def test_frontmatter_validation_is_fail_closed_and_precise(
    frontmatter: str,
    expected_field: str,
    tmp_path: Path,
) -> None:
    content = f"---\n{frontmatter}\n---\nbody\n"
    source = tmp_path / "source"
    source.mkdir()
    (source / "SKILL.md").write_text(content, encoding="utf-8")
    resolved = snapshot_local(source, tmp_path / "snapshot", Limits())
    inventory = build_inventory(resolved, Limits())
    candidate = discover_candidates(resolved, inventory, ())[0]

    validation = validate_candidate(candidate, inventory)

    assert validation.valid is False
    assert validation.reasons[0].code is ReasonCode.INVALID_FRONTMATTER
    assert validation.reasons[0].evidence[0].field == expected_field


@pytest.mark.parametrize(
    "content",
    [
        "name: x\ndescription: x\n",
        "---\nname: x\ndescription: x\n",
        "\ufeff---\nname: x\ndescription: x\n---\n",
    ],
)
def test_missing_or_unclosed_frontmatter_is_invalid(content: str, tmp_path: Path) -> None:
    inventory = _inventory({"SKILL.md": content})
    resolved = _resolved(tmp_path)
    candidate = discover_candidates(resolved, inventory, ())[0]

    validation = validate_candidate(candidate, inventory)

    assert validation.valid is False
    assert validation.reasons[0].code is ReasonCode.INVALID_FRONTMATTER


def test_deep_yaml_candidate_does_not_abort_valid_sibling(tmp_path: Path) -> None:
    deep_value = "[" * 200 + "x" + "]" * 200
    inventory = _inventory(
        {
            "00-deep/SKILL.md": (
                f"---\nname: deep\ndescription: deep\nmetadata: {deep_value}\n---\n"
            ),
            "10-valid/SKILL.md": "---\nname: valid\ndescription: valid\n---\n",
        }
    )
    resolved = _resolved(tmp_path)
    candidates = discover_candidates(resolved, inventory, ())

    validations = [validate_candidate(candidate, inventory) for candidate in candidates]

    assert [item.valid for item in validations] == [False, True]
    assert validations[0].reasons[0].code is ReasonCode.INVALID_FRONTMATTER


def test_recursive_yaml_alias_is_invalid_without_recursing_forever(tmp_path: Path) -> None:
    inventory = _inventory(
        {
            "SKILL.md": (
                "---\nname: recursive\ndescription: recursive\nmetadata: &loop [*loop]\n---\n"
            )
        }
    )
    resolved = _resolved(tmp_path)
    candidate = discover_candidates(resolved, inventory, ())[0]

    validation = validate_candidate(candidate, inventory)

    assert validation.valid is False
    assert validation.reasons[0].code is ReasonCode.INVALID_FRONTMATTER


def test_markdown_body_after_frontmatter_does_not_create_second_yaml_document(
    tmp_path: Path,
) -> None:
    inventory = _inventory(
        {
            "SKILL.md": (
                "---\nname: valid\ndescription: valid\n---\n"
                "name: this is ordinary Markdown body content\n"
            )
        }
    )
    resolved = _resolved(tmp_path)
    candidate = discover_candidates(resolved, inventory, ())[0]

    validation = validate_candidate(candidate, inventory)

    assert validation.valid is True
    assert validation.name == "valid"


def test_valid_frontmatter_is_safe_mapping_with_required_strings(
    load_fixture: FixtureLoader,
) -> None:
    resolved, inventory = load_fixture("standalone_skill")
    candidate = discover_candidates(resolved, inventory, ())[0]

    validation = validate_candidate(candidate, inventory)

    assert validation.valid is True
    assert validation.name == "alpha"
    assert validation.description == "Standalone alpha skill"
    assert dict(validation.frontmatter) == {
        "name": "alpha",
        "description": "Standalone alpha skill",
        "metadata": {"tags": ("safe", "portable")},
    }


def test_candidates_keep_distinct_identity_when_names_match(
    load_fixture: FixtureLoader,
) -> None:
    resolved, inventory = load_fixture("monorepo")

    candidates = discover_candidates(resolved, inventory, ())
    validations = [validate_candidate(candidate, inventory) for candidate in candidates]

    assert [item.name for item in validations] == ["shared-name", "shared-name"]
    assert candidates[0].candidate_id != candidates[1].candidate_id


def test_boundary_output_is_deterministic_for_multiple_manifests_at_same_root() -> None:
    inventory = _inventory(
        {
            ".claude-plugin/plugin.json": "{}",
            "plugin.json": "{}",
            "skill/SKILL.md": "---\nname: x\ndescription: x\n---\n",
        }
    )

    first = detect_boundaries(inventory)
    second = detect_boundaries(inventory)

    assert first == second
    assert [item.manifest_path for item in first] == [
        ".claude-plugin/plugin.json",
        "plugin.json",
    ]


def test_discovery_ignores_directory_named_skill_entrypoint(tmp_path: Path) -> None:
    inventory = Inventory(entries=(InventoryEntry(path="SKILL.md", kind="directory", size=0),))

    assert discover_candidates(_resolved(tmp_path), inventory, ()) == ()


def test_validation_handles_missing_inventory_entry_without_aborting(tmp_path: Path) -> None:
    inventory = _inventory({"SKILL.md": "---\nname: x\ndescription: x\n---\n"})
    resolved = _resolved(tmp_path)
    candidate = discover_candidates(resolved, inventory, ())[0]

    validation = validate_candidate(candidate, Inventory(entries=()))

    assert validation.valid is False
    assert validation.reasons[0].code is ReasonCode.INVALID_FRONTMATTER


def test_package_boundary_type_contract_is_preserved() -> None:
    boundary = detect_boundaries(
        _inventory(
            {
                "plugin.json": "{}",
                "skill/SKILL.md": "---\nname: x\ndescription: x\n---\n",
            }
        )
    )[0]

    assert isinstance(boundary, PackageBoundary)
