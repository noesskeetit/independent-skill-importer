"""Evidence-first static portability analysis."""

import hashlib
import json
from collections.abc import Mapping
from pathlib import Path

import pytest

import skill_importer.static_analysis as static_analysis_module
from skill_importer.boundaries import detect_boundaries
from skill_importer.discovery import discover_candidates, validate_candidate
from skill_importer.models import (
    Classification,
    Inventory,
    InventoryEntry,
    ReasonCode,
    ResolvedSource,
    SourceSpec,
)
from skill_importer.static_analysis import StaticAnalysisResult, analyze_static


def _file(path: str, content: str, *, executable: bool = False) -> InventoryEntry:
    encoded = content.encode()
    return InventoryEntry(
        path=path,
        kind="file",
        size=len(encoded),
        executable=executable,
        sha256=hashlib.sha256(encoded).hexdigest(),
        content=content,
    )


def _symlink(path: str, target: str) -> InventoryEntry:
    return InventoryEntry(
        path=path,
        kind="symlink",
        size=len(target.encode()),
        symlink_target=target,
    )


def _directory(path: str) -> InventoryEntry:
    return InventoryEntry(path=path, kind="directory", size=0)


def _inventory(
    files: Mapping[str, str],
    *,
    symlinks: Mapping[str, str] | None = None,
    executables: frozenset[str] = frozenset(),
    directories: frozenset[str] = frozenset(),
) -> Inventory:
    entries = [
        _file(path, content, executable=path in executables) for path, content in files.items()
    ]
    entries.extend(_symlink(path, target) for path, target in (symlinks or {}).items())
    entries.extend(_directory(path) for path in directories)
    return Inventory(entries=tuple(sorted(entries, key=lambda item: item.path)))


def _resolved(tmp_path: Path) -> ResolvedSource:
    return ResolvedSource(
        spec=SourceSpec.local(tmp_path),
        canonical_url=tmp_path.as_uri(),
        snapshot_root=tmp_path.resolve(),
        snapshot_sha256="0" * 64,
        discovery_scope=".",
    )


def _skill(body: str = "", *, name: str = "alpha", extra: str = "") -> str:
    return f"---\nname: {name}\ndescription: test\n{extra}---\n{body}"


def _analyze(
    tmp_path: Path,
    files: Mapping[str, str],
    *,
    root: str = "skills/alpha",
    symlinks: Mapping[str, str] | None = None,
    executables: frozenset[str] = frozenset(),
    directories: frozenset[str] = frozenset(),
) -> StaticAnalysisResult:
    inventory = _inventory(
        files,
        symlinks=symlinks,
        executables=executables,
        directories=directories,
    )
    boundaries = detect_boundaries(inventory)
    candidates = discover_candidates(_resolved(tmp_path), inventory, boundaries)
    candidate = next(item for item in candidates if item.root == root)
    validation = validate_candidate(candidate, inventory)
    return analyze_static(candidate, validation, inventory, boundaries)


def _reason(result: StaticAnalysisResult, code: ReasonCode):
    return next(reason for reason in result.reasons if reason.code is code)


def test_static_analysis_module_contract_exists() -> None:
    assert callable(analyze_static)
    assert StaticAnalysisResult.__name__ == "StaticAnalysisResult"


def test_standalone_safe_skill_is_portable(tmp_path: Path) -> None:
    result = _analyze(
        tmp_path,
        {"skills/alpha/SKILL.md": _skill("```sh\ngit status\n```\n")},
    )

    assert result.classification is Classification.PORTABLE
    assert result.reason_codes == frozenset({ReasonCode.STANDALONE_NO_PLUGIN_BOUNDARY})
    assert result.external_requirements.binaries == ("git",)


def test_standalone_internal_resource_is_portable(tmp_path: Path) -> None:
    result = _analyze(
        tmp_path,
        {
            "skills/alpha/SKILL.md": _skill("Read [the guide](references/guide.md).\n"),
            "skills/alpha/references/guide.md": "guide",
        },
    )

    assert result.classification is Classification.PORTABLE
    assert ReasonCode.MISSING_LOCAL_RESOURCE not in result.reason_codes


def test_natural_language_slash_is_not_treated_as_a_filesystem_reference(tmp_path: Path) -> None:
    result = _analyze(
        tmp_path,
        {"skills/alpha/SKILL.md": _skill("Explain read/write and input/output behavior.\n")},
    )

    assert result.classification is Classification.PORTABLE
    assert ReasonCode.MISSING_LOCAL_RESOURCE not in result.reason_codes


def test_skills_only_plugin_skill_is_portable(tmp_path: Path) -> None:
    result = _analyze(
        tmp_path,
        {
            ".claude-plugin/plugin.json": json.dumps({"skills": ["skills/alpha"]}),
            "skills/alpha/SKILL.md": _skill(),
        },
    )

    assert result.classification is Classification.PORTABLE
    assert result.reason_codes == frozenset({ReasonCode.SKILLS_ONLY_PACKAGE})


def test_package_json_plugin_skill_registration_is_packaging_only(tmp_path: Path) -> None:
    result = _analyze(
        tmp_path,
        {
            "package.json": json.dumps(
                {"name": "distribution", "plugin": {"skills": ["skills/alpha"]}}
            ),
            "skills/alpha/SKILL.md": _skill(),
        },
    )

    assert result.classification is Classification.PORTABLE
    assert ReasonCode.REFERENCED_BY_PLUGIN_RUNTIME not in result.reason_codes


@pytest.mark.parametrize("manifest", ["{", "[]"])
def test_unparseable_enclosing_manifest_is_nonportable(
    manifest: str,
    tmp_path: Path,
) -> None:
    result = _analyze(
        tmp_path,
        {
            "plugin.json": manifest,
            "skills/alpha/SKILL.md": _skill(),
        },
    )

    assert result.classification is Classification.PLUGIN_BOUND
    evidence = _reason(result, ReasonCode.DYNAMIC_REFERENCE_UNRESOLVED).evidence[0]
    assert evidence.path == "plugin.json"
    assert evidence.field == "manifest"
    assert evidence.detector == "static.boundary.unresolved_manifest"


def test_unparseable_outer_manifest_binds_nested_skills_only_candidate(tmp_path: Path) -> None:
    result = _analyze(
        tmp_path,
        {
            "plugin.json": "{",
            "packages/b/plugin.json": json.dumps({"skills": ["skills/x"]}),
            "packages/b/skills/x/SKILL.md": _skill(),
        },
        root="packages/b/skills/x",
    )

    assert result.classification is Classification.PLUGIN_BOUND
    evidence = _reason(result, ReasonCode.DYNAMIC_REFERENCE_UNRESOLVED).evidence[0]
    assert evidence.path == "plugin.json"


def test_symlink_enclosing_manifest_is_nonportable_even_when_target_is_valid(
    tmp_path: Path,
) -> None:
    result = _analyze(
        tmp_path,
        {
            "actual-plugin.json": json.dumps({}),
            "skills/alpha/SKILL.md": _skill(),
        },
        symlinks={"plugin.json": "actual-plugin.json"},
    )

    assert result.classification is Classification.PLUGIN_BOUND
    evidence = _reason(result, ReasonCode.DYNAMIC_REFERENCE_UNRESOLVED).evidence[0]
    assert evidence.path == "plugin.json"
    assert evidence.field == "manifest"


def test_unparseable_unrelated_manifest_does_not_bind_candidate(tmp_path: Path) -> None:
    result = _analyze(
        tmp_path,
        {
            "packages/a/plugin.json": "{",
            "packages/b/plugin.json": json.dumps({"skills": ["skills/x"]}),
            "packages/b/skills/x/SKILL.md": _skill(),
        },
        root="packages/b/skills/x",
    )

    assert result.classification is Classification.PORTABLE
    assert ReasonCode.DYNAMIC_REFERENCE_UNRESOLVED not in result.reason_codes


def test_mixed_plugin_without_proven_autonomy_is_ambiguous(tmp_path: Path) -> None:
    result = _analyze(
        tmp_path,
        {
            "plugin.json": json.dumps({"mcpServers": {"docs": {"command": "node"}}}),
            "server.js": "export const ok = true;",
            "skills/alpha/SKILL.md": _skill("This skill is self-contained.\n"),
        },
    )

    assert result.classification is Classification.AMBIGUOUS
    assert result.reason_codes == frozenset({ReasonCode.MIXED_PLUGIN_AUTONOMY_UNPROVEN})


def test_invalid_validation_is_invalid_and_retains_validator_evidence(tmp_path: Path) -> None:
    result = _analyze(
        tmp_path,
        {"skills/alpha/SKILL.md": "---\nname: [broken\n---\n"},
    )

    assert result.classification is Classification.INVALID
    assert ReasonCode.INVALID_FRONTMATTER in result.reason_codes
    evidence = _reason(result, ReasonCode.INVALID_FRONTMATTER).evidence[0]
    assert evidence.path == "skills/alpha/SKILL.md"
    assert evidence.field == "frontmatter"


def test_blocked_signal_is_stronger_than_invalid_but_both_reasons_survive(
    tmp_path: Path,
) -> None:
    result = _analyze(
        tmp_path,
        {"skills/alpha/SKILL.md": "invalid"},
        symlinks={"skills/alpha/escape": "../../shared"},
    )

    assert result.classification is Classification.BLOCKED
    assert result.reason_codes == frozenset(
        {ReasonCode.INVALID_FRONTMATTER, ReasonCode.SYMLINK_ESCAPE}
    )


@pytest.mark.parametrize(
    "variable",
    [
        "${PLUGIN_ROOT}",
        "${CLAUDE_PLUGIN_ROOT}",
        "$PLUGIN_DIR",
        "$CLAUDE_PLUGIN_PATH",
        "$EXTENSION_ROOT",
        "${PLUGIN_ROOT:?plugin required}",
        "${CLAUDE_PLUGIN_ROOT:-}",
        "${PLUGIN_ROOT%/}",
        "${PLUGIN_ROOT-default}",
        "${PLUGIN_ROOT?plugin required}",
        "${PLUGIN_ROOT+alternate}",
        "${PLUGIN_ROOT=default}",
        "${PLUGIN_ROOT/foo/bar}",
        "${PLUGIN_ROOT^}",
        "${#PLUGIN_ROOT}",
        "${!PLUGIN_ROOT}",
        "${env:PLUGIN_ROOT}",
        "%PLUGIN_ROOT:~0,-1%",
        "extensionPath",
    ],
)
def test_plugin_root_variable_is_plugin_bound(variable: str, tmp_path: Path) -> None:
    result = _analyze(
        tmp_path,
        {
            "plugin.json": json.dumps({"scripts": {"tool": "scripts/tool.py"}}),
            "scripts/tool.py": "pass",
            "skills/alpha/SKILL.md": _skill(f"Run `{variable}/scripts/tool.py`.\n"),
        },
    )

    assert result.classification is Classification.PLUGIN_BOUND
    assert ReasonCode.PLUGIN_ROOT_VARIABLE in result.reason_codes
    reason = _reason(result, ReasonCode.PLUGIN_ROOT_VARIABLE)
    assert len(reason.evidence) == 1
    evidence = reason.evidence[0]
    assert (evidence.path, evidence.line, evidence.field) == (
        "skills/alpha/SKILL.md",
        5,
        "text",
    )
    assert evidence.value == variable


@pytest.mark.parametrize(
    ("expression", "evidence_value"),
    [
        ("process.env.PLUGIN_ROOT", "process.env.PLUGIN_ROOT"),
        ('Path(os.environ["CLAUDE_PLUGIN_ROOT"])', 'os.environ["CLAUDE_PLUGIN_ROOT"]'),
        ('env.get("CODEX_PLUGIN_DIR")', 'env.get("CODEX_PLUGIN_DIR")'),
        ("$env:CURSOR_PLUGIN_PATH", "$env:CURSOR_PLUGIN_PATH"),
        ("%EXTENSION_ROOT%", "%EXTENSION_ROOT%"),
        ('std::env::var("GEMINI_PLUGIN_DIR")', 'std::env::var("GEMINI_PLUGIN_DIR")'),
        ('System.getenv("OPENCLAW_PLUGIN_ROOT")', 'System.getenv("OPENCLAW_PLUGIN_ROOT")'),
        ('getenv("PLUGIN_PATH")', 'getenv("PLUGIN_PATH")'),
        ('ENV["CLAUDE_PLUGIN_DIR"]', 'ENV["CLAUDE_PLUGIN_DIR"]'),
    ],
)
def test_plugin_root_environment_access_is_plugin_bound(
    expression: str,
    evidence_value: str,
    tmp_path: Path,
) -> None:
    result = _analyze(
        tmp_path,
        {"skills/alpha/SKILL.md": _skill(f"Resolve `{expression}`.\n")},
    )

    assert result.classification is Classification.PLUGIN_BOUND
    reason = _reason(result, ReasonCode.PLUGIN_ROOT_VARIABLE)
    assert len(reason.evidence) == 1
    assert reason.evidence[0].path == "skills/alpha/SKILL.md"
    assert reason.evidence[0].line == 5
    assert reason.evidence[0].value == evidence_value


@pytest.mark.parametrize(
    "text",
    [
        "Read `process.env.HOME`.",
        "Read `${OTHER-default}`.",
        "Read `${PLUGIN_ROOT_BACKUP}`.",
        "The PLUGIN_ROOT identifier is mentioned only as prose.",
    ],
)
def test_ordinary_environment_or_prose_identifier_is_not_plugin_root_dependency(
    text: str,
    tmp_path: Path,
) -> None:
    result = _analyze(
        tmp_path,
        {"skills/alpha/SKILL.md": _skill(f"{text}\n")},
    )

    assert result.classification is Classification.PORTABLE
    assert ReasonCode.PLUGIN_ROOT_VARIABLE not in result.reason_codes


def test_metadata_only_root_plugin_can_package_a_self_contained_script(tmp_path: Path) -> None:
    result = _analyze(
        tmp_path,
        {
            "plugin.json": json.dumps({"name": "metadata-only"}),
            "SKILL.md": _skill("Run `scripts/tool.sh`.\n"),
            "scripts/tool.sh": "#!/bin/sh\nexit 0\n",
        },
        root=".",
        executables=frozenset({"scripts/tool.sh"}),
    )

    assert result.classification is Classification.PORTABLE
    assert result.reason_codes == frozenset({ReasonCode.SKILLS_ONLY_PACKAGE})


@pytest.mark.parametrize(
    "instruction",
    [
        "This skill requires the plugin to be installed.",
        "The plugin must be enabled.",
        "You must install the plugin.",
        "You must enable the plugin.",
        "Do not proceed without installing the plugin.",
        "Never use this skill without enabling the plugin.",
        "This skill cannot run without the plugin installed.",
        "Not only does this skill require the plugin to be installed, it also needs setup.",
        "This skill does not require the plugin to be installed unless cloud mode is active.",
        (
            "This skill does not require the plugin to be installed, "
            "but the plugin must already be enabled."
        ),
        (
            "This skill does not require the plugin locally, "
            "but cloud mode requires the plugin enabled."
        ),
        "It is false that this skill does not require the plugin to be installed.",
    ],
)
def test_affirmative_plugin_install_instruction_is_plugin_bound(
    instruction: str,
    tmp_path: Path,
) -> None:
    result = _analyze(
        tmp_path,
        {"skills/alpha/SKILL.md": _skill(f"{instruction}\n")},
    )

    assert result.classification is Classification.PLUGIN_BOUND
    assert ReasonCode.PLUGIN_RUNTIME_FILE_REFERENCE in result.reason_codes


@pytest.mark.parametrize(
    "instruction",
    [
        "This skill does not require the plugin to be installed.",
        "You do not need to install any plugin.",
    ],
)
def test_negated_plugin_install_instruction_is_not_plugin_bound(
    instruction: str,
    tmp_path: Path,
) -> None:
    result = _analyze(
        tmp_path,
        {"skills/alpha/SKILL.md": _skill(f"{instruction}\n")},
    )

    assert result.classification is Classification.PORTABLE
    assert ReasonCode.PLUGIN_RUNTIME_FILE_REFERENCE not in result.reason_codes


@pytest.mark.parametrize(
    "instruction",
    [
        pytest.param(
            "It is false that "
            + " " * 300
            + "this skill does not require the plugin to be installed.",
            id="negation_before_bounded_window",
        ),
        pytest.param(
            "This skill does not require the plugin to be installed"
            + " " * 300
            + "unless cloud mode is active.",
            id="condition_after_bounded_window",
        ),
    ],
)
def test_plugin_independence_requires_complete_bounded_sentence(
    instruction: str,
    tmp_path: Path,
) -> None:
    result = _analyze(
        tmp_path,
        {"skills/alpha/SKILL.md": _skill(f"{instruction}\n")},
    )

    assert result.classification is Classification.PLUGIN_BOUND
    assert ReasonCode.PLUGIN_RUNTIME_FILE_REFERENCE in result.reason_codes


def test_negated_plugin_install_instruction_keeps_mixed_package_ambiguous(
    tmp_path: Path,
) -> None:
    result = _analyze(
        tmp_path,
        {
            "plugin.json": json.dumps({"runtime": "runtime.py"}),
            "runtime.py": "pass",
            "skills/alpha/SKILL.md": _skill(
                "This skill does not require the plugin to be installed.\n"
            ),
        },
    )

    assert result.classification is Classification.AMBIGUOUS
    assert ReasonCode.PLUGIN_RUNTIME_FILE_REFERENCE not in result.reason_codes


def test_repository_root_relative_reference_inside_candidate_is_internal(
    tmp_path: Path,
) -> None:
    result = _analyze(
        tmp_path,
        {
            "skills/session-viewer/SKILL.md": _skill(
                "Run `skills/session-viewer/scripts/session-viewer.ts`.\n"
            ),
            "skills/session-viewer/scripts/session-viewer.ts": "export {};\n",
        },
        root="skills/session-viewer",
    )

    assert result.classification is Classification.PORTABLE, result.reasons
    assert ReasonCode.MISSING_LOCAL_RESOURCE not in result.reason_codes
    assert ReasonCode.REFERENCE_OUTSIDE_SKILL_ROOT not in result.reason_codes


def test_repository_root_relative_reference_outside_candidate_is_nonportable(
    tmp_path: Path,
) -> None:
    result = _analyze(
        tmp_path,
        {
            "shared/session-schema.json": "{}",
            "skills/session-viewer/SKILL.md": _skill(
                "Read [schema](shared/session-schema.json).\n"
            ),
        },
        root="skills/session-viewer",
    )

    assert result.classification is Classification.PLUGIN_BOUND
    assert ReasonCode.MISSING_LOCAL_RESOURCE not in result.reason_codes
    evidence = _reason(result, ReasonCode.REFERENCE_OUTSIDE_SKILL_ROOT).evidence[0]
    assert evidence.value == "shared/session-schema.json -> shared/session-schema.json"


def test_repository_root_relative_resolution_preserves_entry_relative_precedence(
    tmp_path: Path,
) -> None:
    result = _analyze(
        tmp_path,
        {
            "references/guide.md": "repository guide",
            "skills/session-viewer/SKILL.md": _skill(
                "Read [guide](references/guide.md).\n"
            ),
            "skills/session-viewer/references/guide.md": "skill guide",
        },
        root="skills/session-viewer",
    )

    assert result.classification is Classification.PORTABLE
    assert ReasonCode.MISSING_LOCAL_RESOURCE not in result.reason_codes
    assert ReasonCode.REFERENCE_OUTSIDE_SKILL_ROOT not in result.reason_codes


def test_repository_root_relative_resolution_keeps_snapshot_traversal_blocked(
    tmp_path: Path,
) -> None:
    result = _analyze(
        tmp_path,
        {
            "skills/session-viewer/SKILL.md": _skill(
                "Read [passwd](../../../../etc/passwd).\n"
            )
        },
        root="skills/session-viewer",
    )

    assert result.classification is Classification.BLOCKED
    assert ReasonCode.PATH_TRAVERSAL in result.reason_codes


def test_existing_parent_resource_is_outside_skill_and_nonportable(tmp_path: Path) -> None:
    result = _analyze(
        tmp_path,
        {
            "skills/alpha/SKILL.md": _skill("Read [shared](../shared/resource.txt).\n"),
            "skills/shared/resource.txt": "shared",
        },
    )

    assert result.classification is Classification.PLUGIN_BOUND
    assert ReasonCode.REFERENCE_OUTSIDE_SKILL_ROOT in result.reason_codes
    evidence = _reason(result, ReasonCode.REFERENCE_OUTSIDE_SKILL_ROOT).evidence[0]
    assert evidence.value == "../shared/resource.txt -> skills/shared/resource.txt"


def test_reference_traversing_beyond_snapshot_is_blocked(tmp_path: Path) -> None:
    result = _analyze(
        tmp_path,
        {"skills/alpha/SKILL.md": _skill("Read [passwd](../../../../etc/passwd).\n")},
    )

    assert result.classification is Classification.BLOCKED
    assert ReasonCode.PATH_TRAVERSAL in result.reason_codes


@pytest.mark.parametrize(
    "reference",
    [
        "/etc/passwd",
        r"C:\\Users\\alice\\secret.txt",
        "file:///etc/passwd",
        "file://localhost/etc/passwd",
        "%2e%2e/%2e%2e/%2e%2e/etc/passwd",
        "..%2f..%2f..%2fetc/passwd",
    ],
)
def test_explicit_host_or_encoded_traversal_reference_is_blocked(
    reference: str,
    tmp_path: Path,
) -> None:
    result = _analyze(
        tmp_path,
        {"skills/alpha/SKILL.md": _skill(f"Read [host file]({reference}).\n")},
    )

    assert result.classification is Classification.BLOCKED
    assert ReasonCode.PATH_TRAVERSAL in result.reason_codes


@pytest.mark.parametrize("shebang", ["#!/bin/sh", "#! /usr/bin/env sh"])
def test_first_line_shebang_interpreter_is_not_a_resource_path(
    shebang: str,
    tmp_path: Path,
) -> None:
    script_path = "skills/alpha/scripts/never-run.sh"
    result = _analyze(
        tmp_path,
        {
            "skills/alpha/SKILL.md": _skill(),
            script_path: f"{shebang}\nexit 97\n",
        },
        executables=frozenset({script_path}),
    )

    assert result.classification is Classification.PORTABLE
    assert ReasonCode.PATH_TRAVERSAL not in result.reason_codes


@pytest.mark.parametrize(
    "script",
    [
        "#!/bin/sh\ncat /etc/passwd\n",
        "#!/usr/bin/env /etc/passwd\n",
    ],
)
def test_non_interpreter_host_path_in_script_remains_blocked(
    script: str,
    tmp_path: Path,
) -> None:
    result = _analyze(
        tmp_path,
        {
            "skills/alpha/SKILL.md": _skill(),
            "skills/alpha/scripts/unsafe.sh": script,
        },
    )

    assert result.classification is Classification.BLOCKED
    assert any(
        evidence.value == "/etc/passwd"
        for evidence in _reason(result, ReasonCode.PATH_TRAVERSAL).evidence
    )


def test_plugin_root_variable_in_shebang_remains_plugin_bound(tmp_path: Path) -> None:
    result = _analyze(
        tmp_path,
        {
            "skills/alpha/SKILL.md": _skill(),
            "skills/alpha/scripts/plugin-tool": "#!${PLUGIN_ROOT}/scripts/tool\n",
        },
    )

    assert result.classification is Classification.PLUGIN_BOUND
    assert ReasonCode.PLUGIN_ROOT_VARIABLE in result.reason_codes


@pytest.mark.parametrize(
    "body",
    [
        "Run `cat /etc/passwd`.\n",
        '```python\nopen("/Users/alice/.ssh/id_rsa")\n```\n',
        r'```python\nopen("C:\\Users\\alice\\secret.txt")\n```\n',
        '```javascript\nload("file:///etc/passwd")\n```\n',
    ],
)
def test_host_paths_in_code_are_blocked(body: str, tmp_path: Path) -> None:
    result = _analyze(
        tmp_path,
        {"skills/alpha/SKILL.md": _skill(body)},
    )

    assert result.classification is Classification.BLOCKED
    assert ReasonCode.PATH_TRAVERSAL in result.reason_codes


@pytest.mark.parametrize(
    "body",
    [
        "Read `~/.ssh/id_rsa`.\n",
        r'```python\nopen("..\shared\resource.txt")\n```\n',
        "---ignored---",
    ],
)
def test_home_and_backslash_host_paths_are_blocked(body: str, tmp_path: Path) -> None:
    if body == "---ignored---":
        skill = _skill(extra="config:\n  path: /etc/passwd\n")
    else:
        skill = _skill(body)
    result = _analyze(tmp_path, {"skills/alpha/SKILL.md": skill})

    assert result.classification is Classification.BLOCKED
    assert ReasonCode.PATH_TRAVERSAL in result.reason_codes


def test_https_reference_remains_external_and_is_not_path_traversal(tmp_path: Path) -> None:
    result = _analyze(
        tmp_path,
        {"skills/alpha/SKILL.md": _skill("Read [docs](https://example.com/a/b/c).\n")},
    )

    assert result.classification is Classification.PORTABLE
    assert ReasonCode.PATH_TRAVERSAL not in result.reason_codes


def test_https_tilde_path_is_not_mistaken_for_local_home_path(tmp_path: Path) -> None:
    result = _analyze(
        tmp_path,
        {"skills/alpha/SKILL.md": _skill("Read [user docs](https://example.com/~user/config).\n")},
    )

    assert result.classification is Classification.PORTABLE
    assert ReasonCode.PATH_TRAVERSAL not in result.reason_codes


@pytest.mark.parametrize(
    "body",
    [
        '```python\nopen("/etc")\n```\n',
        '```python\nPath("~/.env")\n```\n',
        "```sh\nsource ~/config\n```\n",
    ],
)
def test_contextual_one_segment_host_path_is_blocked(body: str, tmp_path: Path) -> None:
    result = _analyze(tmp_path, {"skills/alpha/SKILL.md": _skill(body)})

    assert result.classification is Classification.BLOCKED
    assert ReasonCode.PATH_TRAVERSAL in result.reason_codes


def test_slash_command_is_not_mistaken_for_one_segment_host_path(tmp_path: Path) -> None:
    result = _analyze(
        tmp_path,
        {"skills/alpha/SKILL.md": _skill("Run `/deploy` when requested.\n")},
    )

    assert result.classification is Classification.PORTABLE
    assert ReasonCode.PATH_TRAVERSAL not in result.reason_codes


def test_missing_local_reference_is_nonportable(tmp_path: Path) -> None:
    result = _analyze(
        tmp_path,
        {"skills/alpha/SKILL.md": _skill("Read [guide](references/missing.md).\n")},
    )

    assert result.classification is Classification.PLUGIN_BOUND
    assert result.reason_codes == frozenset({ReasonCode.MISSING_LOCAL_RESOURCE})


def test_dynamic_local_reference_is_nonportable(tmp_path: Path) -> None:
    result = _analyze(
        tmp_path,
        {"skills/alpha/SKILL.md": _skill("Read [data](${RESOURCE_DIR}/data.json).\n")},
    )

    assert result.classification is Classification.PLUGIN_BOUND
    assert ReasonCode.DYNAMIC_REFERENCE_UNRESOLVED in result.reason_codes


def test_plugin_runtime_script_reference_records_both_dependency_facts(tmp_path: Path) -> None:
    result = _analyze(
        tmp_path,
        {
            "plugin.json": json.dumps({"scripts": {"tool": "scripts/tool.py"}}),
            "scripts/tool.py": "pass",
            "skills/alpha/SKILL.md": _skill("Run `../../scripts/tool.py`.\n"),
        },
    )

    assert result.classification is Classification.PLUGIN_BOUND
    assert {
        ReasonCode.REFERENCE_OUTSIDE_SKILL_ROOT,
        ReasonCode.PLUGIN_RUNTIME_FILE_REFERENCE,
    } <= result.reason_codes


def test_boundary_relative_runtime_script_is_detected_when_skill_relative_path_is_missing(
    tmp_path: Path,
) -> None:
    result = _analyze(
        tmp_path,
        {
            "plugin.json": json.dumps({"scripts": {"tool": "scripts/tool.py"}}),
            "scripts/tool.py": "pass",
            "skills/alpha/SKILL.md": _skill("Run `scripts/tool.py`.\n"),
        },
    )

    assert result.classification is Classification.PLUGIN_BOUND
    assert ReasonCode.PLUGIN_RUNTIME_FILE_REFERENCE in result.reason_codes
    assert ReasonCode.MISSING_LOCAL_RESOURCE not in result.reason_codes


def test_boundary_relative_nonruntime_file_is_only_an_outside_dependency(tmp_path: Path) -> None:
    result = _analyze(
        tmp_path,
        {
            "plugin.json": json.dumps({"runtime": "runtime.py"}),
            "runtime.py": "pass",
            "data/schema.json": "{}",
            "skills/alpha/SKILL.md": _skill("Read [schema](data/schema.json).\n"),
        },
    )

    assert result.classification is Classification.PLUGIN_BOUND
    assert ReasonCode.REFERENCE_OUTSIDE_SKILL_ROOT in result.reason_codes
    assert ReasonCode.PLUGIN_RUNTIME_FILE_REFERENCE not in result.reason_codes


def test_internal_file_with_plugin_runtime_basename_is_not_misattributed(tmp_path: Path) -> None:
    result = _analyze(
        tmp_path,
        {
            "plugin.json": json.dumps({"scripts": {"tool": "scripts/tool.py"}}),
            "scripts/tool.py": "plugin tool",
            "skills/alpha/SKILL.md": _skill("Run `scripts/tool.py`.\n"),
            "skills/alpha/scripts/tool.py": "skill tool",
        },
    )

    assert result.classification is Classification.AMBIGUOUS
    assert ReasonCode.PLUGIN_RUNTIME_FILE_REFERENCE not in result.reason_codes


def test_import_of_plugin_runtime_module_is_plugin_bound(tmp_path: Path) -> None:
    result = _analyze(
        tmp_path,
        {
            "plugin.json": json.dumps({"runtime": "src/acme_runtime.py"}),
            "src/acme_runtime.py": "pass",
            "skills/alpha/SKILL.md": _skill("```python\nfrom acme_runtime import run\n```\n"),
        },
    )

    assert result.classification is Classification.PLUGIN_BOUND
    assert ReasonCode.PLUGIN_RUNTIME_FILE_REFERENCE in result.reason_codes


def test_arbitrary_test_module_is_not_plugin_owned_runtime(tmp_path: Path) -> None:
    result = _analyze(
        tmp_path,
        {
            "plugin.json": json.dumps({"runtime": "runtime/engine.py"}),
            "runtime/engine.py": "pass",
            "tests/json.py": "pass",
            "skills/alpha/SKILL.md": _skill("```python\nimport json\n```\n"),
        },
    )

    assert result.classification is Classification.AMBIGUOUS
    assert ReasonCode.PLUGIN_RUNTIME_FILE_REFERENCE not in result.reason_codes


@pytest.mark.parametrize(
    "statement",
    [
        'import { run } from "acme-runtime";',
        'const runtime = require("acme-runtime");',
        'const runtime = await import("acme-runtime");',
        'const runtime = load("acme-runtime");',
    ],
)
def test_javascript_runtime_module_import_is_plugin_bound(
    statement: str,
    tmp_path: Path,
) -> None:
    result = _analyze(
        tmp_path,
        {
            "plugin.json": json.dumps({"runtime": "src/acme-runtime.ts"}),
            "src/acme-runtime.ts": "export const run = () => {};",
            "skills/alpha/SKILL.md": _skill(f"```javascript\n{statement}\n```\n"),
        },
    )

    assert result.classification is Classification.PLUGIN_BOUND
    assert ReasonCode.PLUGIN_RUNTIME_FILE_REFERENCE in result.reason_codes


def test_owned_plugin_binary_is_plugin_bound(tmp_path: Path) -> None:
    result = _analyze(
        tmp_path,
        {
            "package.json": json.dumps(
                {"plugin": {"skills": ["skills/alpha"]}, "bin": {"acme-tool": "bin/tool.py"}}
            ),
            "bin/tool.py": "pass",
            "skills/alpha/SKILL.md": _skill("```sh\nacme-tool run\n```\n"),
        },
        executables=frozenset({"bin/tool.py"}),
    )

    assert result.classification is Classification.PLUGIN_BOUND
    assert ReasonCode.PLUGIN_RUNTIME_FILE_REFERENCE in result.reason_codes


def test_structured_requirement_for_plugin_owned_binary_is_plugin_bound(tmp_path: Path) -> None:
    result = _analyze(
        tmp_path,
        {
            "package.json": json.dumps(
                {"plugin": {"skills": ["skills/alpha"]}, "bin": {"acme-tool": "bin/tool.py"}}
            ),
            "bin/tool.py": "pass",
            "skills/alpha/SKILL.md": _skill(extra="requires:\n  bins: [acme-tool]\n"),
        },
        executables=frozenset({"bin/tool.py"}),
    )

    assert result.classification is Classification.PLUGIN_BOUND
    assert ReasonCode.PLUGIN_RUNTIME_FILE_REFERENCE in result.reason_codes


def test_plugin_owned_mcp_tool_is_derived_from_manifest(tmp_path: Path) -> None:
    result = _analyze(
        tmp_path,
        {
            "plugin.json": json.dumps({"mcpServers": {"docs": {"command": "node"}}}),
            "server.js": "pass",
            "skills/alpha/SKILL.md": _skill("Call `mcp__docs__search` with the query.\n"),
        },
    )

    assert result.classification is Classification.PLUGIN_BOUND
    reason = _reason(result, ReasonCode.PLUGIN_OWNED_MCP_TOOL)
    assert reason.evidence[0].value == "mcp__docs__search"


def test_outer_plugin_owned_mcp_tool_is_visible_through_nested_skill_package(
    tmp_path: Path,
) -> None:
    result = _analyze(
        tmp_path,
        {
            "plugin.json": json.dumps({"mcpServers": {"outer": {"command": "node"}}}),
            "packages/b/plugin.json": json.dumps({"name": "skill-pack"}),
            "packages/b/skills/x/SKILL.md": _skill("Call `mcp__outer__do` now.\n"),
        },
        root="packages/b/skills/x",
    )

    assert result.classification is Classification.PLUGIN_BOUND
    reason = _reason(result, ReasonCode.PLUGIN_OWNED_MCP_TOOL)
    assert reason.evidence[0].path == "packages/b/skills/x/SKILL.md"
    assert reason.evidence[0].value == "mcp__outer__do"


def test_unowned_mcp_tool_does_not_create_plugin_dependency(tmp_path: Path) -> None:
    result = _analyze(
        tmp_path,
        {
            "plugin.json": json.dumps({"mcpServers": {"docs": {"command": "node"}}}),
            "server.js": "pass",
            "skills/alpha/SKILL.md": _skill("Call `mcp__other__search`.\n"),
        },
    )

    assert result.classification is Classification.AMBIGUOUS
    assert ReasonCode.PLUGIN_OWNED_MCP_TOOL not in result.reason_codes


def test_plugin_command_reference_is_derived_from_manifest(tmp_path: Path) -> None:
    result = _analyze(
        tmp_path,
        {
            "plugin.json": json.dumps({"commands": {"deploy": "commands/deploy.md"}}),
            "commands/deploy.md": "deploy",
            "skills/alpha/SKILL.md": _skill("Run `/deploy` now.\n"),
        },
    )

    assert result.classification is Classification.PLUGIN_BOUND
    assert ReasonCode.PLUGIN_COMMAND_REFERENCE in result.reason_codes


@pytest.mark.parametrize(
    ("component", "symbol", "instruction"),
    [
        ("agents", "reviewer", "agent: reviewer"),
        ("hooks", "preflight", "hook: preflight"),
        ("providers", "cloud", "provider: cloud"),
    ],
)
def test_other_plugin_owned_components_are_plugin_bound(
    component: str,
    symbol: str,
    instruction: str,
    tmp_path: Path,
) -> None:
    component_path = f"{component}/{symbol}.py"
    result = _analyze(
        tmp_path,
        {
            "plugin.json": json.dumps({component: {symbol: component_path}}),
            component_path: "pass",
            "skills/alpha/SKILL.md": _skill(f"Use `{instruction}`.\n"),
        },
    )

    assert result.classification is Classification.PLUGIN_BOUND
    assert ReasonCode.PLUGIN_RUNTIME_FILE_REFERENCE in result.reason_codes


def test_reverse_exact_skill_path_from_runtime_is_plugin_bound(tmp_path: Path) -> None:
    result = _analyze(
        tmp_path,
        {
            "plugin.json": json.dumps({"runtime": "runtime/engine.py"}),
            "runtime/engine.py": 'open("skills/alpha/SKILL.md")',
            "skills/alpha/SKILL.md": _skill(),
        },
    )

    assert result.classification is Classification.PLUGIN_BOUND
    evidence = _reason(result, ReasonCode.REFERENCED_BY_PLUGIN_RUNTIME).evidence[0]
    assert (evidence.path, evidence.line) == ("runtime/engine.py", 1)
    assert "skills/alpha/SKILL.md" in evidence.value


def test_outer_plugin_runtime_reference_reaches_nested_skill_package(tmp_path: Path) -> None:
    result = _analyze(
        tmp_path,
        {
            "plugin.json": json.dumps({"runtime": "src/runtime.py"}),
            "src/runtime.py": 'open("packages/b/skills/x/SKILL.md")',
            "packages/b/plugin.json": json.dumps({"name": "skill-pack"}),
            "packages/b/skills/x/SKILL.md": _skill(),
        },
        root="packages/b/skills/x",
    )

    assert result.classification is Classification.PLUGIN_BOUND
    reason = _reason(result, ReasonCode.REFERENCED_BY_PLUGIN_RUNTIME)
    assert reason.evidence[0].path == "src/runtime.py"
    assert reason.evidence[0].line == 1
    assert "packages/b/skills/x/SKILL.md" in reason.evidence[0].value


def test_outer_manifest_declared_runtime_inside_nested_boundary_references_skill(
    tmp_path: Path,
) -> None:
    result = _analyze(
        tmp_path,
        {
            "plugin.json": json.dumps({"runtime": "packages/b/lib/tool.py"}),
            "packages/b/plugin.json": json.dumps({}),
            "packages/b/lib/tool.py": 'open("packages/b/skills/x/SKILL.md")',
            "packages/b/skills/x/SKILL.md": _skill(),
        },
        root="packages/b/skills/x",
    )

    assert result.classification is Classification.PLUGIN_BOUND
    reason = _reason(result, ReasonCode.REFERENCED_BY_PLUGIN_RUNTIME)
    assert reason.evidence[0].path == "packages/b/lib/tool.py"
    assert "packages/b/skills/x/SKILL.md" in reason.evidence[0].value


def test_outer_manifest_declared_runtime_directory_owns_nested_descendant(
    tmp_path: Path,
) -> None:
    result = _analyze(
        tmp_path,
        {
            "plugin.json": json.dumps({"runtime": "packages/b/lib"}),
            "packages/b/plugin.json": json.dumps({}),
            "packages/b/lib/tool.py": 'open("packages/b/skills/x/SKILL.md")',
            "packages/b/skills/x/SKILL.md": _skill(),
        },
        root="packages/b/skills/x",
        directories=frozenset({"packages/b/lib"}),
    )

    assert result.classification is Classification.PLUGIN_BOUND
    reason = _reason(result, ReasonCode.REFERENCED_BY_PLUGIN_RUNTIME)
    assert reason.evidence[0].path == "packages/b/lib/tool.py"


@pytest.mark.parametrize(
    ("runtime_root", "directories"),
    [
        pytest.param("packages/b", frozenset({"packages/b"}), id="candidate_ancestor"),
        pytest.param(".", frozenset(), id="boundary_root"),
    ],
)
def test_outer_manifest_declared_runtime_root_contains_nested_candidate(
    runtime_root: str,
    directories: frozenset[str],
    tmp_path: Path,
) -> None:
    result = _analyze(
        tmp_path,
        {
            "plugin.json": json.dumps({"runtime": runtime_root}),
            "packages/b/plugin.json": json.dumps({"name": "skill-pack"}),
            "packages/b/skills/x/SKILL.md": _skill(),
        },
        root="packages/b/skills/x",
        directories=directories,
    )

    assert result.classification is Classification.PLUGIN_BOUND
    reason = _reason(result, ReasonCode.REFERENCED_BY_PLUGIN_RUNTIME)
    assert reason.evidence[0].path == "plugin.json"
    assert reason.evidence[0].field == "runtime"
    assert reason.evidence[0].value == runtime_root


def test_outer_manifest_declared_runtime_inside_sibling_skill_owns_file(
    tmp_path: Path,
) -> None:
    result = _analyze(
        tmp_path,
        {
            "plugin.json": json.dumps({"runtime": "skills/internal/scripts/runtime.py"}),
            "skills/internal/SKILL.md": _skill(name="internal"),
            "skills/internal/scripts/runtime.py": ('open("packages/b/skills/x/SKILL.md")'),
            "packages/b/plugin.json": json.dumps({"name": "skill-pack"}),
            "packages/b/skills/x/SKILL.md": _skill(),
        },
        root="packages/b/skills/x",
    )

    assert result.classification is Classification.PLUGIN_BOUND
    reason = _reason(result, ReasonCode.REFERENCED_BY_PLUGIN_RUNTIME)
    assert reason.evidence[0].path == "skills/internal/scripts/runtime.py"


def test_undeclared_sibling_skill_file_is_not_reverse_dependency(tmp_path: Path) -> None:
    result = _analyze(
        tmp_path,
        {
            "plugin.json": json.dumps({"runtime": "src/runtime.py"}),
            "src/runtime.py": "pass",
            "skills/internal/SKILL.md": _skill(name="internal"),
            "skills/internal/scripts/runtime.py": ('open("packages/b/skills/x/SKILL.md")'),
            "packages/b/plugin.json": json.dumps({"name": "skill-pack"}),
            "packages/b/skills/x/SKILL.md": _skill(),
        },
        root="packages/b/skills/x",
    )

    assert result.classification is Classification.PORTABLE
    assert ReasonCode.REFERENCED_BY_PLUGIN_RUNTIME not in result.reason_codes


def test_outer_manifest_declared_runtime_directory_overrides_documentation_exclusion(
    tmp_path: Path,
) -> None:
    result = _analyze(
        tmp_path,
        {
            "plugin.json": json.dumps({"runtime": "examples/runtime"}),
            "examples/runtime/tool.py": 'open("packages/b/skills/x/SKILL.md")',
            "packages/b/plugin.json": json.dumps({"name": "skill-pack"}),
            "packages/b/skills/x/SKILL.md": _skill(),
        },
        root="packages/b/skills/x",
        directories=frozenset({"examples/runtime"}),
    )

    assert result.classification is Classification.PLUGIN_BOUND
    reason = _reason(result, ReasonCode.REFERENCED_BY_PLUGIN_RUNTIME)
    assert reason.evidence[0].path == "examples/runtime/tool.py"


def test_package_plugin_wrapper_source_declares_runtime_inside_nested_docs(
    tmp_path: Path,
) -> None:
    result = _analyze(
        tmp_path,
        {
            "package.json": json.dumps(
                {"plugin": {"source": "packages/b/examples/runtime/tool.ts"}}
            ),
            "packages/b/examples/runtime/tool.ts": ('open("packages/b/skills/x/SKILL.md")'),
            "packages/b/plugin.json": json.dumps({"name": "skill-pack"}),
            "packages/b/skills/x/SKILL.md": _skill(),
        },
        root="packages/b/skills/x",
    )

    assert result.classification is Classification.PLUGIN_BOUND
    reason = _reason(result, ReasonCode.REFERENCED_BY_PLUGIN_RUNTIME)
    assert reason.evidence[0].path == "packages/b/examples/runtime/tool.ts"


@pytest.mark.parametrize("field", ["source", "src"])
def test_package_top_level_exact_source_file_is_plugin_runtime(
    field: str,
    tmp_path: Path,
) -> None:
    result = _analyze(
        tmp_path,
        {
            "package.json": json.dumps(
                {
                    field: "packages/b/examples/runtime/tool.ts",
                    "plugin": {"skills": ["packages/b/skills/x"]},
                }
            ),
            "packages/b/examples/runtime/tool.ts": ('open("packages/b/skills/x/SKILL.md")'),
            "packages/b/plugin.json": json.dumps({"name": "skill-pack"}),
            "packages/b/skills/x/SKILL.md": _skill(),
        },
        root="packages/b/skills/x",
    )

    assert result.classification is Classification.PLUGIN_BOUND
    reason = _reason(result, ReasonCode.REFERENCED_BY_PLUGIN_RUNTIME)
    assert reason.evidence[0].path == "packages/b/examples/runtime/tool.ts"


@pytest.mark.parametrize("field", ["source", "src"])
def test_package_top_level_source_directory_does_not_own_descendants(
    field: str,
    tmp_path: Path,
) -> None:
    result = _analyze(
        tmp_path,
        {
            "package.json": json.dumps(
                {
                    field: "packages/b/examples/runtime",
                    "plugin": {"skills": ["packages/b/skills/x"]},
                }
            ),
            "packages/b/examples/runtime/tool.ts": ('open("packages/b/skills/x/SKILL.md")'),
            "packages/b/plugin.json": json.dumps({"name": "skill-pack"}),
            "packages/b/skills/x/SKILL.md": _skill(),
        },
        root="packages/b/skills/x",
        directories=frozenset({"packages/b/examples/runtime"}),
    )

    assert result.classification is Classification.PORTABLE
    assert ReasonCode.REFERENCED_BY_PLUGIN_RUNTIME not in result.reason_codes


@pytest.mark.parametrize("field", ["source", "src"])
def test_package_exact_source_symlink_resolves_owned_runtime_file(
    field: str,
    tmp_path: Path,
) -> None:
    result = _analyze(
        tmp_path,
        {
            "package.json": json.dumps(
                {
                    field: "docs/runtime-link.py",
                    "plugin": {"skills": ["packages/b/skills/x"]},
                }
            ),
            "docs/actual.py": 'open("packages/b/skills/x/SKILL.md")',
            "packages/b/plugin.json": json.dumps({"name": "skill-pack"}),
            "packages/b/skills/x/SKILL.md": _skill(),
        },
        root="packages/b/skills/x",
        symlinks={"docs/runtime-link.py": "actual.py"},
    )

    assert result.classification is Classification.PLUGIN_BOUND
    reason = _reason(result, ReasonCode.REFERENCED_BY_PLUGIN_RUNTIME)
    assert reason.evidence[0].path == "docs/actual.py"


def test_declared_runtime_symlink_resolves_owned_runtime_directory(
    tmp_path: Path,
) -> None:
    result = _analyze(
        tmp_path,
        {
            "plugin.json": json.dumps({"runtime": "docs/runtime-link"}),
            "docs/actual/tool.py": 'open("packages/b/skills/x/SKILL.md")',
            "packages/b/plugin.json": json.dumps({"name": "skill-pack"}),
            "packages/b/skills/x/SKILL.md": _skill(),
        },
        root="packages/b/skills/x",
        symlinks={"docs/runtime-link": "actual"},
        directories=frozenset({"docs/actual"}),
    )

    assert result.classification is Classification.PLUGIN_BOUND
    reason = _reason(result, ReasonCode.REFERENCED_BY_PLUGIN_RUNTIME)
    assert reason.evidence[0].path == "docs/actual/tool.py"


def test_package_source_symlink_to_directory_does_not_own_descendants(
    tmp_path: Path,
) -> None:
    result = _analyze(
        tmp_path,
        {
            "package.json": json.dumps(
                {
                    "source": "docs/runtime-link",
                    "plugin": {"skills": ["packages/b/skills/x"]},
                }
            ),
            "docs/actual/tool.py": 'open("packages/b/skills/x/SKILL.md")',
            "packages/b/plugin.json": json.dumps({"name": "skill-pack"}),
            "packages/b/skills/x/SKILL.md": _skill(),
        },
        root="packages/b/skills/x",
        symlinks={"docs/runtime-link": "actual"},
        directories=frozenset({"docs/actual"}),
    )

    assert result.classification is Classification.PORTABLE
    assert ReasonCode.REFERENCED_BY_PLUGIN_RUNTIME not in result.reason_codes


def test_manifest_runtime_path_resolves_symlinked_prefix(tmp_path: Path) -> None:
    result = _analyze(
        tmp_path,
        {
            "plugin.json": json.dumps({"runtime": "alias/tool.py"}),
            "examples/runtime/tool.py": 'open("skills/alpha/SKILL.md")',
            "skills/alpha/SKILL.md": _skill(),
        },
        symlinks={"alias": "examples/runtime"},
        directories=frozenset({"examples/runtime"}),
    )

    assert result.classification is Classification.PLUGIN_BOUND
    reason = _reason(result, ReasonCode.REFERENCED_BY_PLUGIN_RUNTIME)
    assert reason.evidence[0].path == "examples/runtime/tool.py"


def test_declared_runtime_directory_resolves_owned_symlink_descendant(
    tmp_path: Path,
) -> None:
    result = _analyze(
        tmp_path,
        {
            "plugin.json": json.dumps({"runtime": "runtime"}),
            "examples/worker.py": 'open("skills/alpha/SKILL.md")',
            "skills/alpha/SKILL.md": _skill(),
        },
        symlinks={"runtime/alias.py": "../examples/worker.py"},
        directories=frozenset({"runtime"}),
    )

    assert result.classification is Classification.PLUGIN_BOUND
    reason = _reason(result, ReasonCode.REFERENCED_BY_PLUGIN_RUNTIME)
    assert reason.evidence[0].path == "examples/worker.py"


def test_explicit_runtime_symlink_target_inside_nested_plugin_is_owned(
    tmp_path: Path,
) -> None:
    result = _analyze(
        tmp_path,
        {
            "plugin.json": json.dumps({"runtime": "alias.py"}),
            "vendor/plugin.json": json.dumps({}),
            "vendor/worker.py": 'open("skills/alpha/SKILL.md")',
            "skills/alpha/SKILL.md": _skill(),
        },
        symlinks={"alias.py": "vendor/worker.py"},
    )

    assert result.classification is Classification.PLUGIN_BOUND
    reason = _reason(result, ReasonCode.REFERENCED_BY_PLUGIN_RUNTIME)
    assert reason.evidence[0].path == "vendor/worker.py"


def test_conventional_runtime_symlink_target_is_owned(tmp_path: Path) -> None:
    result = _analyze(
        tmp_path,
        {
            "plugin.json": json.dumps({}),
            "examples/worker.py": 'open("skills/alpha/SKILL.md")',
            "skills/alpha/SKILL.md": _skill(),
        },
        symlinks={"runtime/alias.py": "../examples/worker.py"},
    )

    assert result.classification is Classification.PLUGIN_BOUND
    reason = _reason(result, ReasonCode.REFERENCED_BY_PLUGIN_RUNTIME)
    assert reason.evidence[0].path == "examples/worker.py"


def test_direct_explicit_runtime_outside_package_boundary_is_owned(tmp_path: Path) -> None:
    result = _analyze(
        tmp_path,
        {
            "packages/a/plugin.json": json.dumps({"runtime": "../../shared/worker.py"}),
            "shared/worker.py": 'open("packages/a/skills/x/SKILL.md")',
            "packages/a/skills/x/SKILL.md": _skill(),
        },
        root="packages/a/skills/x",
    )

    assert result.classification is Classification.PLUGIN_BOUND
    reason = _reason(result, ReasonCode.REFERENCED_BY_PLUGIN_RUNTIME)
    assert reason.evidence[0].path == "shared/worker.py"


def test_direct_runtime_outside_boundary_is_retained_for_fm_review(tmp_path: Path) -> None:
    result = _analyze(
        tmp_path,
        {
            "packages/a/plugin.json": json.dumps({"runtime": "../../shared/worker.py"}),
            "shared/worker.py": "def activate():\n    return None\n",
            "packages/a/skills/x/SKILL.md": _skill(),
        },
        root="packages/a/skills/x",
    )

    assert result.classification is Classification.AMBIGUOUS
    assert "shared/worker.py" in result.review_paths


def test_nested_symlink_runtime_target_is_retained_for_fm_review(tmp_path: Path) -> None:
    result = _analyze(
        tmp_path,
        {
            "plugin.json": json.dumps({"runtime": "alias.py"}),
            "vendor/plugin.json": json.dumps({}),
            "vendor/worker.py": "def activate():\n    return None\n",
            "skills/alpha/SKILL.md": _skill(),
        },
        symlinks={"alias.py": "vendor/worker.py"},
    )

    assert result.classification is Classification.AMBIGUOUS
    assert {"alias.py", "vendor/worker.py"}.issubset(result.review_paths)


def test_undeclared_sibling_plugin_symlink_is_not_outer_runtime(tmp_path: Path) -> None:
    result = _analyze(
        tmp_path,
        {
            "plugin.json": json.dumps({"runtime": "src/runtime.py"}),
            "src/runtime.py": "pass",
            "packages/a/plugin.json": json.dumps({}),
            "packages/a/worker.py": 'open("packages/b/skills/x/SKILL.md")',
            "packages/b/plugin.json": json.dumps({"name": "skill-pack"}),
            "packages/b/skills/x/SKILL.md": _skill(),
        },
        root="packages/b/skills/x",
        symlinks={"packages/a/runtime/alias.py": "../worker.py"},
    )

    assert result.classification is Classification.PORTABLE
    assert ReasonCode.REFERENCED_BY_PLUGIN_RUNTIME not in result.reason_codes


def test_exact_source_symlink_target_outside_package_boundary_is_owned(
    tmp_path: Path,
) -> None:
    result = _analyze(
        tmp_path,
        {
            "packages/b/package.json": json.dumps(
                {
                    "source": "docs/runtime-link.py",
                    "plugin": {"skills": ["skills/x"]},
                }
            ),
            "shared/actual.py": 'open("packages/b/skills/x/SKILL.md")',
            "packages/b/skills/x/SKILL.md": _skill(),
        },
        root="packages/b/skills/x",
        symlinks={"packages/b/docs/runtime-link.py": "../../../shared/actual.py"},
    )

    assert result.classification is Classification.PLUGIN_BOUND
    reason = _reason(result, ReasonCode.REFERENCED_BY_PLUGIN_RUNTIME)
    assert reason.evidence[0].path == "shared/actual.py"


def test_exact_runtime_symlink_terminal_inside_candidate_binds_skill(tmp_path: Path) -> None:
    result = _analyze(
        tmp_path,
        {
            "package.json": json.dumps(
                {
                    "source": "docs/runtime-link.py",
                    "plugin": {"skills": ["packages/b/skills/x"]},
                }
            ),
            "packages/b/plugin.json": json.dumps({"name": "skill-pack"}),
            "packages/b/skills/x/SKILL.md": _skill(),
            "packages/b/skills/x/runtime.py": "pass",
        },
        root="packages/b/skills/x",
        symlinks={
            "docs/runtime-link.py": "../packages/b/skills/x/runtime.py",
        },
    )

    assert result.classification is Classification.PLUGIN_BOUND
    evidence = _reason(result, ReasonCode.REFERENCED_BY_PLUGIN_RUNTIME).evidence[0]
    assert evidence.path == "docs/runtime-link.py"
    assert evidence.field == "symlinkTarget"
    assert "packages/b/skills/x/runtime.py" in evidence.value


def test_exact_runtime_symlink_directory_containing_candidate_binds_skill(
    tmp_path: Path,
) -> None:
    result = _analyze(
        tmp_path,
        {
            "package.json": json.dumps(
                {
                    "source": "docs/runtime-link",
                    "plugin": {"skills": ["packages/b/skills/x"]},
                }
            ),
            "packages/b/plugin.json": json.dumps({"name": "skill-pack"}),
            "packages/b/skills/x/SKILL.md": _skill(),
        },
        root="packages/b/skills/x",
        symlinks={"docs/runtime-link": "../packages/b"},
        directories=frozenset({"packages/b"}),
    )

    assert result.classification is Classification.PLUGIN_BOUND
    evidence = _reason(result, ReasonCode.REFERENCED_BY_PLUGIN_RUNTIME).evidence[0]
    assert evidence.path == "docs/runtime-link"
    assert evidence.field == "symlinkTarget"
    assert evidence.value.endswith("-> packages/b")


def test_undeclared_documentation_symlink_is_not_plugin_runtime(tmp_path: Path) -> None:
    result = _analyze(
        tmp_path,
        {
            "package.json": json.dumps({"plugin": {"skills": ["packages/b/skills/x"]}}),
            "docs/actual.py": 'open("packages/b/skills/x/SKILL.md")',
            "packages/b/plugin.json": json.dumps({"name": "skill-pack"}),
            "packages/b/skills/x/SKILL.md": _skill(),
        },
        root="packages/b/skills/x",
        symlinks={"docs/runtime-link.py": "actual.py"},
    )

    assert result.classification is Classification.PORTABLE
    assert ReasonCode.REFERENCED_BY_PLUGIN_RUNTIME not in result.reason_codes


@pytest.mark.parametrize(
    ("symlinks", "classification", "reason_code"),
    [
        pytest.param(
            {"docs/runtime-link.py": "missing.py"},
            Classification.PLUGIN_BOUND,
            ReasonCode.MISSING_LOCAL_RESOURCE,
            id="dangling",
        ),
        pytest.param(
            {
                "docs/runtime-link.py": "runtime-next.py",
                "docs/runtime-next.py": "runtime-link.py",
            },
            Classification.PLUGIN_BOUND,
            ReasonCode.DYNAMIC_REFERENCE_UNRESOLVED,
            id="cycle",
        ),
        pytest.param(
            {"docs/runtime-link.py": "/etc/passwd"},
            Classification.BLOCKED,
            ReasonCode.SYMLINK_ESCAPE,
            id="host_escape",
        ),
        pytest.param(
            {"docs/runtime-link.py": "../../outside.py"},
            Classification.BLOCKED,
            ReasonCode.SYMLINK_ESCAPE,
            id="snapshot_escape",
        ),
    ],
)
def test_explicit_runtime_symlink_failure_is_nonportable(
    symlinks: Mapping[str, str],
    classification: Classification,
    reason_code: ReasonCode,
    tmp_path: Path,
) -> None:
    result = _analyze(
        tmp_path,
        {
            "package.json": json.dumps(
                {
                    "source": "docs/runtime-link.py",
                    "plugin": {"skills": ["packages/b/skills/x"]},
                }
            ),
            "packages/b/plugin.json": json.dumps({"name": "skill-pack"}),
            "packages/b/skills/x/SKILL.md": _skill(),
        },
        root="packages/b/skills/x",
        symlinks=symlinks,
    )

    assert result.classification is classification
    evidence = _reason(result, reason_code).evidence[0]
    assert evidence.path == "docs/runtime-link.py"
    assert evidence.field == "symlinkTarget"


def test_manifest_runtime_symlink_prefix_with_missing_suffix_is_nonportable(
    tmp_path: Path,
) -> None:
    result = _analyze(
        tmp_path,
        {
            "plugin.json": json.dumps({"runtime": "alias/missing.py"}),
            "skills/alpha/SKILL.md": _skill(),
        },
        symlinks={"alias": "docs"},
        directories=frozenset({"docs"}),
    )

    assert result.classification is Classification.PLUGIN_BOUND
    evidence = _reason(result, ReasonCode.MISSING_LOCAL_RESOURCE).evidence[0]
    assert evidence.path == "alias"
    assert evidence.field == "symlinkTarget"
    assert evidence.value.endswith("-> docs/missing.py")


def test_reverse_structured_skill_name_is_plugin_bound(tmp_path: Path) -> None:
    result = _analyze(
        tmp_path,
        {
            "plugin.json": json.dumps({"runtime": "runtime/workflow.json"}),
            "runtime/workflow.json": json.dumps({"steps": [{"skill": "alpha"}]}),
            "skills/alpha/SKILL.md": _skill(),
        },
    )

    assert result.classification is Classification.PLUGIN_BOUND
    assert ReasonCode.REFERENCED_BY_PLUGIN_RUNTIME in result.reason_codes


def test_reverse_internal_orchestration_call_is_plugin_bound(tmp_path: Path) -> None:
    result = _analyze(
        tmp_path,
        {
            "plugin.json": json.dumps({"runtime": "runtime/workflow.js"}),
            "runtime/workflow.js": 'runSkill("alpha")',
            "skills/alpha/SKILL.md": _skill(),
        },
    )

    assert result.classification is Classification.PLUGIN_BOUND
    assert ReasonCode.REFERENCED_BY_PLUGIN_RUNTIME in result.reason_codes


def test_nested_manifest_runtime_skills_are_not_mistaken_for_packaging(tmp_path: Path) -> None:
    result = _analyze(
        tmp_path,
        {
            "plugin.json": json.dumps(
                {"skills": ["skills/alpha"], "runtime": {"skills": ["alpha"]}}
            ),
            "skills/alpha/SKILL.md": _skill(),
        },
    )

    assert result.classification is Classification.PLUGIN_BOUND
    assert ReasonCode.REFERENCED_BY_PLUGIN_RUNTIME in result.reason_codes


def test_reverse_resource_read_is_plugin_bound(tmp_path: Path) -> None:
    result = _analyze(
        tmp_path,
        {
            "plugin.json": json.dumps({"runtime": "runtime/engine.js"}),
            "runtime/engine.js": 'readFileSync("skills/alpha/references/prompt.md")',
            "skills/alpha/SKILL.md": _skill("Read [prompt](references/prompt.md).\n"),
            "skills/alpha/references/prompt.md": "prompt",
        },
    )

    assert result.classification is Classification.PLUGIN_BOUND
    assert ReasonCode.REFERENCED_BY_PLUGIN_RUNTIME in result.reason_codes


def test_documentation_reference_is_not_reverse_dependency(tmp_path: Path) -> None:
    result = _analyze(
        tmp_path,
        {
            "plugin.json": json.dumps({"runtime": "runtime.py"}),
            "runtime.py": "pass",
            "README.md": "See skills/alpha/SKILL.md and use alpha.",
            "docs/guide.md": "skills/alpha/references/prompt.md",
            "skills/alpha/SKILL.md": _skill(),
        },
    )

    assert result.classification is Classification.AMBIGUOUS
    assert ReasonCode.REFERENCED_BY_PLUGIN_RUNTIME not in result.reason_codes


@pytest.mark.parametrize(
    "path",
    ["tests/test_registration.py", "CONTRIBUTING.md", "ARCHITECTURE.md"],
)
def test_unproven_nonruntime_text_is_not_reverse_dependency(path: str, tmp_path: Path) -> None:
    result = _analyze(
        tmp_path,
        {
            "plugin.json": json.dumps({"runtime": "runtime/engine.py"}),
            "runtime/engine.py": "pass",
            path: 'open("skills/alpha/SKILL.md")',
            "skills/alpha/SKILL.md": _skill(),
        },
    )

    assert result.classification is Classification.AMBIGUOUS
    assert ReasonCode.REFERENCED_BY_PLUGIN_RUNTIME not in result.reason_codes


@pytest.mark.parametrize(
    ("path", "content"),
    [
        ("config/workflow.yaml", "skills: [alpha]\n"),
        ("config/workflow.toml", 'skills = ["alpha"]\n'),
    ],
)
def test_plural_skill_list_in_runtime_config_is_reverse_dependency(
    path: str,
    content: str,
    tmp_path: Path,
) -> None:
    result = _analyze(
        tmp_path,
        {
            "plugin.json": json.dumps({"runtime": path}),
            path: content,
            "skills/alpha/SKILL.md": _skill(),
        },
    )

    assert result.classification is Classification.PLUGIN_BOUND
    assert ReasonCode.REFERENCED_BY_PLUGIN_RUNTIME in result.reason_codes


def test_bare_prose_name_in_runtime_is_not_reverse_dependency(tmp_path: Path) -> None:
    result = _analyze(
        tmp_path,
        {
            "plugin.json": json.dumps({"runtime": "runtime.py"}),
            "runtime.py": "# alpha is a useful concept\n",
            "skills/alpha/SKILL.md": _skill(),
        },
    )

    assert result.classification is Classification.AMBIGUOUS
    assert ReasonCode.REFERENCED_BY_PLUGIN_RUNTIME not in result.reason_codes


def test_packaging_only_skill_registration_is_not_reverse_dependency(tmp_path: Path) -> None:
    result = _analyze(
        tmp_path,
        {
            "plugin.json": json.dumps(
                {
                    "skills": ["skills/alpha"],
                    "mcpServers": {"docs": {"command": "node"}},
                }
            ),
            "server.js": "pass",
            "skills/alpha/SKILL.md": _skill(),
        },
    )

    assert result.classification is Classification.AMBIGUOUS
    assert ReasonCode.REFERENCED_BY_PLUGIN_RUNTIME not in result.reason_codes


def test_outer_packaging_registration_is_not_nested_skill_runtime_dependency(
    tmp_path: Path,
) -> None:
    result = _analyze(
        tmp_path,
        {
            "plugin.json": json.dumps(
                {
                    "runtime": "src/runtime.py",
                    "skills": ["packages/b/skills/x"],
                }
            ),
            "src/runtime.py": "pass",
            "packages/b/plugin.json": json.dumps({"name": "skill-pack"}),
            "packages/b/skills/x/SKILL.md": _skill(),
        },
        root="packages/b/skills/x",
    )

    assert result.classification is Classification.PORTABLE
    assert ReasonCode.REFERENCED_BY_PLUGIN_RUNTIME not in result.reason_codes


def test_outer_documentation_reference_is_not_nested_skill_runtime_dependency(
    tmp_path: Path,
) -> None:
    result = _analyze(
        tmp_path,
        {
            "plugin.json": json.dumps({"runtime": "src/runtime.py"}),
            "src/runtime.py": "pass",
            "docs/guide.md": "See packages/b/skills/x/SKILL.md.",
            "packages/b/plugin.json": json.dumps({"name": "skill-pack"}),
            "packages/b/skills/x/SKILL.md": _skill(),
        },
        root="packages/b/skills/x",
    )

    assert result.classification is Classification.PORTABLE
    assert ReasonCode.REFERENCED_BY_PLUGIN_RUNTIME not in result.reason_codes


def test_skill_root_equal_to_mixed_plugin_root_is_plugin_bound(tmp_path: Path) -> None:
    result = _analyze(
        tmp_path,
        {
            "plugin.json": json.dumps({"runtime": "runtime.py"}),
            "runtime.py": "pass",
            "SKILL.md": _skill(),
        },
        root=".",
    )

    assert result.classification is Classification.PLUGIN_BOUND
    assert ReasonCode.PLUGIN_RUNTIME_INSIDE_SKILL_ROOT in result.reason_codes


def test_skill_root_equal_to_truly_skills_only_plugin_root_is_portable(tmp_path: Path) -> None:
    result = _analyze(
        tmp_path,
        {"plugin.json": "{}", "SKILL.md": _skill()},
        root=".",
    )

    assert result.classification is Classification.PORTABLE
    assert result.reason_codes == frozenset({ReasonCode.SKILLS_ONLY_PACKAGE})


def test_nested_plugin_components_are_not_owned_by_outer_boundary(tmp_path: Path) -> None:
    result = _analyze(
        tmp_path,
        {
            "outer/plugin.json": json.dumps({"runtime": "runtime.py"}),
            "outer/runtime.py": "pass",
            "outer/skills/alpha/SKILL.md": _skill("Run `/deploy`.\n"),
            "outer/vendor/plugin.json": json.dumps({"commands": {"deploy": "commands/deploy.md"}}),
            "outer/vendor/commands/deploy.md": "deploy",
        },
        root="outer/skills/alpha",
    )

    assert result.classification is Classification.AMBIGUOUS
    assert ReasonCode.PLUGIN_COMMAND_REFERENCE not in result.reason_codes


def test_nested_plugin_runtime_is_not_reverse_dependency_of_outer_plugin(tmp_path: Path) -> None:
    result = _analyze(
        tmp_path,
        {
            "outer/plugin.json": json.dumps({"runtime": "runtime.py"}),
            "outer/runtime.py": "pass",
            "outer/skills/alpha/SKILL.md": _skill(),
            "outer/vendor/plugin.json": json.dumps({"runtime": "runtime.py"}),
            "outer/vendor/runtime.py": 'open("outer/skills/alpha/SKILL.md")',
        },
        root="outer/skills/alpha",
    )

    assert result.classification is Classification.AMBIGUOUS
    assert ReasonCode.REFERENCED_BY_PLUGIN_RUNTIME not in result.reason_codes


def test_sibling_nested_plugin_components_are_not_owned_by_outer_or_inner_boundary(
    tmp_path: Path,
) -> None:
    result = _analyze(
        tmp_path,
        {
            "plugin.json": json.dumps({"runtime": "src/runtime.py"}),
            "src/runtime.py": "pass",
            "packages/a/plugin.json": json.dumps({"mcpServers": {"sibling": {"command": "node"}}}),
            "packages/b/plugin.json": json.dumps({"name": "skill-pack"}),
            "packages/b/skills/x/SKILL.md": _skill("Call `mcp__sibling__do`.\n"),
        },
        root="packages/b/skills/x",
    )

    assert result.classification is Classification.PORTABLE
    assert ReasonCode.PLUGIN_OWNED_MCP_TOOL not in result.reason_codes


def test_sibling_nested_plugin_runtime_is_not_outer_reverse_dependency(
    tmp_path: Path,
) -> None:
    result = _analyze(
        tmp_path,
        {
            "plugin.json": json.dumps({"runtime": "src/runtime.py"}),
            "src/runtime.py": "pass",
            "packages/a/plugin.json": json.dumps({"runtime": "runtime.py"}),
            "packages/a/runtime.py": 'open("packages/b/skills/x/SKILL.md")',
            "packages/b/plugin.json": json.dumps({"name": "skill-pack"}),
            "packages/b/skills/x/SKILL.md": _skill(),
        },
        root="packages/b/skills/x",
    )

    assert result.classification is Classification.PORTABLE
    assert ReasonCode.REFERENCED_BY_PLUGIN_RUNTIME not in result.reason_codes


def test_outer_boundary_does_not_claim_undeclared_conventional_nested_runtime(
    tmp_path: Path,
) -> None:
    result = _analyze(
        tmp_path,
        {
            "plugin.json": json.dumps({"runtime": "src/runtime.py"}),
            "src/runtime.py": "pass",
            "packages/a/plugin.json": json.dumps({}),
            "packages/a/runtime/tool.py": 'open("packages/b/skills/x/SKILL.md")',
            "packages/b/plugin.json": json.dumps({"name": "skill-pack"}),
            "packages/b/skills/x/SKILL.md": _skill(),
        },
        root="packages/b/skills/x",
    )

    assert result.classification is Classification.PORTABLE
    assert ReasonCode.REFERENCED_BY_PLUGIN_RUNTIME not in result.reason_codes


def test_forward_path_does_not_reclaim_nested_plugin_runtime_as_outer_owned(
    tmp_path: Path,
) -> None:
    result = _analyze(
        tmp_path,
        {
            "plugin.json": json.dumps({"runtime": "src/runtime.py"}),
            "src/runtime.py": "pass",
            "runtime/a/plugin.json": json.dumps({"runtime": "runtime.py"}),
            "runtime/a/runtime.py": "pass",
            "packages/b/plugin.json": json.dumps({"name": "skill-pack"}),
            "packages/b/skills/x/SKILL.md": _skill(
                "Read [sibling](../../../../runtime/a/runtime.py).\n"
            ),
        },
        root="packages/b/skills/x",
    )

    assert ReasonCode.REFERENCE_OUTSIDE_SKILL_ROOT in result.reason_codes
    assert ReasonCode.PLUGIN_RUNTIME_FILE_REFERENCE not in result.reason_codes


def test_forward_path_does_not_reclaim_other_skill_runtime_as_plugin_owned(
    tmp_path: Path,
) -> None:
    result = _analyze(
        tmp_path,
        {
            "plugin.json": json.dumps({"runtime": "src/runtime.py"}),
            "src/runtime.py": "pass",
            "runtime/other/SKILL.md": _skill(name="other"),
            "runtime/other/runtime.py": "pass",
            "packages/b/plugin.json": json.dumps({"name": "skill-pack"}),
            "packages/b/skills/x/SKILL.md": _skill(
                "Read [other](../../../../runtime/other/runtime.py).\n"
            ),
        },
        root="packages/b/skills/x",
    )

    assert ReasonCode.REFERENCE_OUTSIDE_SKILL_ROOT in result.reason_codes
    assert ReasonCode.PLUGIN_RUNTIME_FILE_REFERENCE not in result.reason_codes


def test_root_skill_does_not_shadow_reverse_dependency_of_nested_candidate(tmp_path: Path) -> None:
    result = _analyze(
        tmp_path,
        {
            "plugin.json": json.dumps({"runtime": "runtime/workflow.js"}),
            "runtime/workflow.js": 'runSkill("alpha")',
            "SKILL.md": _skill(name="root"),
            "skills/alpha/SKILL.md": _skill(),
        },
    )

    assert result.classification is Classification.PLUGIN_BOUND
    assert ReasonCode.REFERENCED_BY_PLUGIN_RUNTIME in result.reason_codes


def test_root_skill_does_not_shadow_owned_components_of_nested_candidate(tmp_path: Path) -> None:
    result = _analyze(
        tmp_path,
        {
            "plugin.json": "{}",
            "commands/deploy.md": "deploy",
            "mcp/docs/server.js": "pass",
            "SKILL.md": _skill(name="root"),
            "skills/alpha/SKILL.md": _skill("Run `/deploy`, then call `mcp__docs__search`.\n"),
        },
    )

    assert result.classification is Classification.PLUGIN_BOUND
    assert ReasonCode.PLUGIN_COMMAND_REFERENCE in result.reason_codes
    assert ReasonCode.PLUGIN_OWNED_MCP_TOOL in result.reason_codes


def test_internal_relative_symlink_is_safe(tmp_path: Path) -> None:
    result = _analyze(
        tmp_path,
        {
            "skills/alpha/SKILL.md": _skill("Read [alias](alias.md).\n"),
            "skills/alpha/references/guide.md": "guide",
        },
        symlinks={"skills/alpha/alias.md": "references/guide.md"},
    )

    assert result.classification is Classification.PORTABLE
    assert ReasonCode.SYMLINK_ESCAPE not in result.reason_codes
    assert ReasonCode.MISSING_LOCAL_RESOURCE not in result.reason_codes


@pytest.mark.parametrize(
    "target", ["/etc/passwd", "../../shared/resource.md", r"..\shared\resource.md"]
)
def test_absolute_or_outside_symlink_is_blocked(target: str, tmp_path: Path) -> None:
    result = _analyze(
        tmp_path,
        {"skills/alpha/SKILL.md": _skill()},
        symlinks={"skills/alpha/escape": target},
    )

    assert result.classification is Classification.BLOCKED
    assert result.reason_codes == frozenset({ReasonCode.SYMLINK_ESCAPE})


def test_dangling_internal_symlink_is_nonportable(tmp_path: Path) -> None:
    result = _analyze(
        tmp_path,
        {"skills/alpha/SKILL.md": _skill()},
        symlinks={"skills/alpha/missing": "references/nope.md"},
    )

    assert result.classification is Classification.PLUGIN_BOUND
    assert result.reason_codes == frozenset({ReasonCode.MISSING_LOCAL_RESOURCE})


def test_structured_and_clear_external_requirements_do_not_bind_plugin(tmp_path: Path) -> None:
    result = _analyze(
        tmp_path,
        {
            "skills/alpha/SKILL.md": _skill(
                "```sh\n"
                "docker run example\n"
                "gh repo view\n"
                "git status\n"
                "python scripts/local.py\n"
                "```\n",
                extra=("requires:\n  bins: [docker, jq]\n  env: [API_TOKEN, REGION]\n"),
            ),
            "skills/alpha/scripts/local.py": "pass",
        },
    )

    assert result.classification is Classification.PORTABLE
    assert result.external_requirements.binaries == ("docker", "gh", "git", "jq", "python")
    assert result.external_requirements.environment == ("API_TOKEN", "REGION")


def test_plugin_owned_binary_is_not_reported_as_external_requirement(tmp_path: Path) -> None:
    result = _analyze(
        tmp_path,
        {
            "package.json": json.dumps(
                {"plugin": {"skills": ["skills/alpha"]}, "bin": {"acme-tool": "bin/tool.py"}}
            ),
            "bin/tool.py": "pass",
            "skills/alpha/SKILL.md": _skill(extra="requires:\n  bins: [acme-tool]\n"),
        },
        executables=frozenset({"bin/tool.py"}),
    )

    assert result.classification is Classification.PLUGIN_BOUND
    assert "acme-tool" not in result.external_requirements.binaries


def test_reasons_and_evidence_are_deterministic_bounded_and_source_addressable(
    tmp_path: Path,
) -> None:
    files = {
        "plugin.json": json.dumps({"scripts": {"tool": "scripts/tool.py"}}),
        "scripts/tool.py": "pass",
        "skills/alpha/SKILL.md": _skill(
            "Run `${PLUGIN_ROOT}/scripts/tool.py`.\nRead [missing](references/missing.md).\n"
        ),
    }

    first = _analyze(tmp_path, files)
    second = _analyze(tmp_path, dict(reversed(tuple(files.items()))))

    assert first == second
    assert tuple(reason.code.value for reason in first.reasons) == tuple(
        sorted(reason.code.value for reason in first.reasons)
    )
    assert all(reason.evidence for reason in first.reasons)
    assert all(
        evidence.path and evidence.detector and len(evidence.value) <= 256
        for reason in first.reasons
        for evidence in reason.evidence
    )


def test_deep_manifest_is_bounded_and_does_not_abort_scan(tmp_path: Path) -> None:
    nested: object = "leaf"
    for index in range(80):
        nested = {f"level{index}": nested}
    result = _analyze(
        tmp_path,
        {
            "plugin.json": json.dumps({"plugin": nested}),
            "runtime.py": "pass",
            "skills/alpha/SKILL.md": _skill(),
        },
    )

    assert result.classification is Classification.AMBIGUOUS


def test_repeated_evidence_is_bounded(tmp_path: Path) -> None:
    body = "".join(
        f"`${{PLUGIN_ROOT}}/scripts/tool.py` occurrence {index}\n" for index in range(200)
    )
    result = _analyze(
        tmp_path,
        {
            "plugin.json": json.dumps({"scripts": {"tool": "scripts/tool.py"}}),
            "scripts/tool.py": "pass",
            "skills/alpha/SKILL.md": _skill(body),
        },
    )

    assert result.classification is Classification.PLUGIN_BOUND
    assert len(_reason(result, ReasonCode.PLUGIN_ROOT_VARIABLE).evidence) <= 64


def test_evidence_builder_stops_after_reason_cap(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    calls = 0
    original = static_analysis_module._text_evidence

    def counting_evidence(*args: object, **kwargs: object):
        nonlocal calls
        calls += 1
        return original(*args, **kwargs)

    monkeypatch.setattr(static_analysis_module, "_text_evidence", counting_evidence)
    body = " ".join("`${PLUGIN_ROOT}/tool`" for _ in range(5000))

    result = _analyze(tmp_path, {"skills/alpha/SKILL.md": _skill(body)})

    assert result.classification is Classification.PLUGIN_BOUND
    assert calls <= 64


def test_overlong_internal_symlink_chain_fails_closed(tmp_path: Path) -> None:
    symlinks = {f"skills/alpha/link{index}": f"link{index + 1}" for index in range(80)}
    symlinks["skills/alpha/link80"] = "target.txt"
    result = _analyze(
        tmp_path,
        {
            "skills/alpha/SKILL.md": _skill(),
            "skills/alpha/target.txt": "target",
        },
        symlinks=symlinks,
    )

    assert result.classification is Classification.PLUGIN_BOUND
    assert ReasonCode.DYNAMIC_REFERENCE_UNRESOLVED in result.reason_codes
