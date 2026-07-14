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


def _unreadable_file(path: str) -> InventoryEntry:
    content = b"\xff"
    return InventoryEntry(
        path=path,
        kind="file",
        size=len(content),
        sha256=hashlib.sha256(content).hexdigest(),
        content=None,
    )


def _directory(path: str) -> InventoryEntry:
    return InventoryEntry(path=path, kind="directory", size=0)


def _symlink(path: str, target: str = "outside") -> InventoryEntry:
    return InventoryEntry(
        path=path,
        kind="symlink",
        size=len(target.encode()),
        symlink_target=target,
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


@pytest.mark.parametrize(
    "runtime_key",
    [
        "mcp",
        "mcpServers",
        "hooks",
        "commands",
        "agents",
        "providers",
        "provider",
        "main",
        "bin",
        "runtime",
        "scripts",
        "server",
        "servers",
        "src",
        "entrypoint",
        "extensionPath",
    ],
)
@pytest.mark.parametrize(
    ("manifest_path", "base_manifest"),
    [
        ("plugin.json", {"name": "plugin", "skills": ["skills/x"]}),
        ("package.json", {"name": "plugin", "plugin": {"skills": ["skills/x"]}}),
    ],
)
def test_runtime_declaration_in_manifest_makes_package_mixed(
    runtime_key: str,
    manifest_path: str,
    base_manifest: Mapping[str, object],
) -> None:
    manifest = dict(base_manifest)
    manifest[runtime_key] = {}
    inventory = _inventory(
        {
            manifest_path: json.dumps(manifest),
            "skills/x/SKILL.md": "---\nname: x\ndescription: x\n---\n",
        }
    )

    boundaries = detect_boundaries(inventory)

    assert len(boundaries) == 1
    assert boundaries[0].package_kind == "mixed"


def test_nested_runtime_declaration_in_manifest_makes_package_mixed() -> None:
    inventory = _inventory(
        {
            "plugin.json": json.dumps(
                {
                    "name": "plugin",
                    "description": "metadata",
                    "skills": ["skills/x"],
                    "metadata": {"mcpServers": {}},
                }
            ),
            "skills/x/SKILL.md": "---\nname: x\ndescription: x\n---\n",
        }
    )

    assert detect_boundaries(inventory)[0].package_kind == "mixed"


def test_skills_only_manifest_declarations_remain_skills_only() -> None:
    inventory = _inventory(
        {
            "plugin.json": json.dumps(
                {
                    "name": "plugin",
                    "description": "skills only",
                    "version": "1.0.0",
                    "skills": ["skills/x"],
                }
            ),
            "skills/x/SKILL.md": "---\nname: x\ndescription: x\n---\n",
        }
    )

    assert detect_boundaries(inventory)[0].package_kind == "skills_only"


def test_root_skill_with_metadata_only_plugin_manifest_is_skills_only() -> None:
    inventory = _inventory(
        {
            "plugin.json": "{}",
            "SKILL.md": "---\nname: x\ndescription: x\n---\n",
        }
    )

    assert detect_boundaries(inventory)[0].package_kind == "skills_only"


def test_root_skill_local_scripts_are_payload_without_manifest_runtime_declaration() -> None:
    inventory = _inventory(
        {
            "plugin.json": '{"name":"metadata-only"}',
            "SKILL.md": "---\nname: x\ndescription: x\n---\nRun `scripts/tool.sh`.\n",
            "scripts/tool.sh": "#!/bin/sh\nexit 0\n",
        }
    )

    assert detect_boundaries(inventory)[0].package_kind == "skills_only"


def test_root_skill_conventional_payload_directories_remain_skills_only() -> None:
    inventory = _inventory(
        {
            "openclaw.plugin.json": '{"id":"metadata-only"}',
            "SKILL.md": "---\nname: x\ndescription: x\n---\n",
            "assets/data.json": "{}",
            "references/helper.py": "EXAMPLE = True\n",
            "scripts/tool.ts": "export const run = () => undefined;\n",
        }
    )

    assert detect_boundaries(inventory)[0].package_kind == "skills_only"


def test_nested_skill_code_payload_does_not_make_root_package_mixed() -> None:
    inventory = _inventory(
        {
            "openclaw.plugin.json": '{"id":"metadata-only"}',
            "SKILL.md": "---\nname: root\ndescription: root\n---\n",
            "nested/SKILL.md": "---\nname: nested\ndescription: nested\n---\n",
            "nested/scripts/tool.py": "print('skill payload')\n",
        }
    )

    assert detect_boundaries(inventory)[0].package_kind == "skills_only"


@pytest.mark.parametrize("runtime_path", ["index.ts", "main.py"])
def test_root_skill_undeclared_code_source_keeps_package_mixed(runtime_path: str) -> None:
    inventory = _inventory(
        {
            "openclaw.plugin.json": '{"id":"root-plugin"}',
            "SKILL.md": "---\nname: x\ndescription: x\n---\n",
            runtime_path: "PLUGIN_RUNTIME = True\n",
        }
    )

    assert detect_boundaries(inventory)[0].package_kind == "mixed"


@pytest.mark.parametrize(
    ("runtime_path", "kind"),
    [
        ("vendor/scripts/tool.sh", "file"),
        ("script-s/tool.sh", "file"),
        ("scripts", "file"),
    ],
)
def test_root_skill_script_exception_is_limited_to_top_level_directories(
    runtime_path: str,
    kind: str,
) -> None:
    runtime_entry = (
        _directory(runtime_path) if kind == "directory" else _file(runtime_path, "runtime")
    )
    inventory = Inventory(
        entries=(
            _file("plugin.json", '{"name":"metadata-only"}'),
            _file("SKILL.md", "---\nname: x\ndescription: x\n---\n"),
            runtime_entry,
        )
    )

    assert detect_boundaries(inventory)[0].package_kind == "mixed"


def test_root_skill_manifest_runtime_declaration_keeps_package_mixed() -> None:
    inventory = _inventory(
        {
            "plugin.json": json.dumps({"runtime": "runtime.py"}),
            "runtime.py": "pass",
            "SKILL.md": "---\nname: x\ndescription: x\n---\n",
        }
    )

    assert detect_boundaries(inventory)[0].package_kind == "mixed"


def test_root_openclaw_extension_declaration_keeps_package_mixed() -> None:
    inventory = _inventory(
        {
            "openclaw.plugin.json": json.dumps({"id": "root-plugin"}),
            "package.json": json.dumps({"openclaw": {"extensions": ["./index.ts"]}}),
            "index.ts": "export default {};\n",
            "SKILL.md": "---\nname: x\ndescription: x\n---\n",
        }
    )

    assert detect_boundaries(inventory)[0].package_kind == "mixed"


def test_root_skill_known_runtime_directory_keeps_package_mixed() -> None:
    inventory = _inventory(
        {
            "plugin.json": "{}",
            "runtime/engine.py": "pass",
            "SKILL.md": "---\nname: x\ndescription: x\n---\n",
        }
    )

    assert detect_boundaries(inventory)[0].package_kind == "mixed"


@pytest.mark.parametrize(
    "manifest_path",
    [
        ".plugin/plugin.json",
        ".claude-plugin/plugin.json",
        ".codex-plugin/plugin.json",
        ".cursor-plugin/plugin.json",
        ".github/plugin/plugin.json",
        "plugin.json",
        "gemini-extension.json",
        "openclaw.plugin.json",
    ],
)
def test_malformed_recognized_manifest_makes_package_mixed(manifest_path: str) -> None:
    inventory = _inventory(
        {
            manifest_path: "{broken",
            "skills/x/SKILL.md": "---\nname: x\ndescription: x\n---\n",
        }
    )

    boundaries = detect_boundaries(inventory)

    assert len(boundaries) == 1
    assert boundaries[0].package_kind == "mixed"


def test_unreadable_recognized_manifest_makes_package_mixed() -> None:
    inventory = Inventory(
        entries=(
            _unreadable_file(".claude-plugin/plugin.json"),
            _file("skills/x/SKILL.md", "---\nname: x\ndescription: x\n---\n"),
        )
    )

    assert detect_boundaries(inventory)[0].package_kind == "mixed"


@pytest.mark.parametrize(
    "manifest_path",
    [
        ".plugin/plugin.json",
        ".claude-plugin/plugin.json",
        ".codex-plugin/plugin.json",
        ".cursor-plugin/plugin.json",
        ".github/plugin/plugin.json",
        "plugin.json",
        "gemini-extension.json",
        "openclaw.plugin.json",
    ],
)
def test_symlink_recognized_manifest_keeps_fail_closed_boundary(
    manifest_path: str,
    tmp_path: Path,
) -> None:
    inventory = Inventory(
        entries=(
            _symlink(manifest_path),
            _file("skills/x/SKILL.md", "---\nname: x\ndescription: x\n---\n"),
        )
    )

    boundaries = detect_boundaries(inventory)
    candidates = discover_candidates(_resolved(tmp_path), inventory, boundaries)

    assert len(boundaries) == 1
    assert boundaries[0].package_kind == "mixed"
    assert candidates[0].enclosing_boundary == boundaries[0]


@pytest.mark.parametrize("entry_kind", ["symlink", "directory"])
def test_non_regular_package_json_creates_unknown_mixed_boundary(
    entry_kind: str,
    tmp_path: Path,
) -> None:
    package_entry = (
        _symlink("package.json") if entry_kind == "symlink" else _directory("package.json")
    )
    inventory = Inventory(
        entries=(
            package_entry,
            _file("skills/x/SKILL.md", "---\nname: x\ndescription: x\n---\n"),
        )
    )

    boundaries = detect_boundaries(inventory)
    candidates = discover_candidates(_resolved(tmp_path), inventory, boundaries)

    assert len(boundaries) == 1
    assert boundaries[0].manifest_kind == "package_json"
    assert boundaries[0].package_kind == "mixed"
    assert candidates[0].enclosing_boundary == boundaries[0]


@pytest.mark.parametrize(
    "component_directory",
    [
        "mcp",
        "mcp-server",
        "mcp-servers",
        "mcp.server",
        "mcp_server",
        "mcp_servers",
        "mcpserver",
        "mcpservers",
        "hook",
        "hooks",
        "command",
        "commands",
        "agent",
        "agents",
        "source",
        "src",
        "server",
        "servers",
        "runtime",
        "script",
        "scripts",
        "provider",
        "providers",
        "bin",
        "executable",
        "executables",
        "entrypoint",
        "entry-point",
    ],
)
def test_known_empty_component_directory_makes_package_mixed(
    component_directory: str,
) -> None:
    inventory = Inventory(
        entries=(
            _file("plugin.json", "{}"),
            _directory(component_directory),
            _file("skills/x/SKILL.md", "---\nname: x\ndescription: x\n---\n"),
        )
    )

    assert detect_boundaries(inventory)[0].package_kind == "mixed"


def test_runtime_named_directory_below_docs_remains_documentation() -> None:
    inventory = Inventory(
        entries=(
            _file("plugin.json", "{}"),
            _directory("docs"),
            _directory("docs/hooks"),
            _file("skills/x/SKILL.md", "---\nname: x\ndescription: x\n---\n"),
        )
    )

    assert detect_boundaries(inventory)[0].package_kind == "skills_only"


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


def test_yaml_merge_chain_is_rejected_before_constructor_expansion(tmp_path: Path) -> None:
    merge_chain = "\n".join(
        [
            "base: &base {one: 1, two: 2}",
            "level1: &level1 {<<: [*base, *base]}",
            "level2: &level2 {<<: [*level1, *level1]}",
            "level3: {<<: [*level2, *level2]}",
        ]
    )
    inventory = _inventory(
        {
            "00-merge/SKILL.md": (
                "---\nname: merge\ndescription: merge\n" + merge_chain + "\n---\n"
            ),
            "10-valid/SKILL.md": "---\nname: valid\ndescription: valid\n---\n",
        }
    )
    candidates = discover_candidates(_resolved(tmp_path), inventory, ())

    validations = [validate_candidate(candidate, inventory) for candidate in candidates]

    assert [item.valid for item in validations] == [False, True]
    assert "merge" in validations[0].reasons[0].message.lower()


@pytest.mark.parametrize(
    "unsafe_value",
    [
        "2026-99-99",
        "0001-01-01 00:00:00+23:59",
        "9" * 5000,
    ],
)
def test_yaml_constructor_exception_isolated_from_valid_sibling(
    unsafe_value: str,
    tmp_path: Path,
) -> None:
    inventory = _inventory(
        {
            "00-invalid/SKILL.md": (
                f"---\nname: invalid\ndescription: invalid\nmetadata: {unsafe_value}\n---\n"
            ),
            "10-valid/SKILL.md": "---\nname: valid\ndescription: valid\n---\n",
        }
    )
    candidates = discover_candidates(_resolved(tmp_path), inventory, ())

    validations = [validate_candidate(candidate, inventory) for candidate in candidates]

    assert [item.valid for item in validations] == [False, True]
    assert validations[0].reasons[0].code is ReasonCode.INVALID_FRONTMATTER


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


def test_missing_top_level_name_evidence_does_not_point_to_nested_name(tmp_path: Path) -> None:
    inventory = _inventory(
        {"SKILL.md": ("---\nmetadata:\n  name: nested-only\ndescription: valid\n---\n")}
    )
    candidate = discover_candidates(_resolved(tmp_path), inventory, ())[0]

    validation = validate_candidate(candidate, inventory)

    assert validation.valid is False
    assert validation.reasons[0].evidence[0].field == "name"
    assert validation.reasons[0].evidence[0].line == 1


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


def test_discovery_keeps_symlink_entrypoint_for_fail_closed_analysis(tmp_path: Path) -> None:
    inventory = Inventory(entries=(_symlink("skill/SKILL.md", "../outside.md"),))

    candidates = discover_candidates(_resolved(tmp_path), inventory, ())

    assert [candidate.root for candidate in candidates] == ["skill"]
    validation = validate_candidate(candidates[0], inventory)
    assert validation.valid is False
    assert validation.reasons[0].code is ReasonCode.INVALID_FRONTMATTER


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
