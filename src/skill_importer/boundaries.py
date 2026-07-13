"""Detect plugin package boundaries without treating plugins as import candidates."""

import json
from collections.abc import Mapping
from pathlib import PurePosixPath

from .models import Inventory, InventoryEntry, PackageBoundary

MANIFEST_PATHS = frozenset(
    {
        ".plugin/plugin.json",
        ".claude-plugin/plugin.json",
        ".codex-plugin/plugin.json",
        ".cursor-plugin/plugin.json",
        ".github/plugin/plugin.json",
        "plugin.json",
        "gemini-extension.json",
        "openclaw.plugin.json",
    }
)

_METADATA_MANIFESTS = {
    (".plugin", "plugin.json"): "plugin_metadata",
    (".claude-plugin", "plugin.json"): "claude_plugin",
    (".codex-plugin", "plugin.json"): "codex_plugin",
    (".cursor-plugin", "plugin.json"): "cursor_plugin",
    (".github", "plugin", "plugin.json"): "github_plugin",
}
_ROOT_MANIFESTS = {
    "plugin.json": "plugin",
    "gemini-extension.json": "gemini_extension",
    "openclaw.plugin.json": "openclaw_plugin",
}
_PACKAGE_MARKERS = frozenset(
    {"openclaw", "claudePlugin", "codexPlugin", "cursorPlugin", "geminiExtension", "plugin"}
)
_PLATFORM_CONTAINERS = frozenset({"claude", "codex", "cursor", "gemini"})
_DOC_DIRECTORIES = frozenset({"docs", "examples"})
_METADATA_DIRECTORIES = frozenset(
    {".plugin", ".claude-plugin", ".codex-plugin", ".cursor-plugin", ".github"}
)
_MARKETPLACE_NAMES = frozenset({"marketplace.json", "marketplace.yaml", "marketplace.yml"})
_RUNTIME_DECLARATION_KEYS = frozenset(
    {
        "agent",
        "agents",
        "bin",
        "command",
        "commands",
        "entrypoint",
        "executable",
        "executables",
        "extensionpath",
        "hook",
        "hooks",
        "main",
        "mcp",
        "mcpserver",
        "mcpservers",
        "provider",
        "providers",
        "runtime",
        "script",
        "scripts",
        "server",
        "servers",
        "source",
        "src",
    }
)
_RUNTIME_DIRECTORY_NAMES = frozenset(
    {
        "agents",
        "bin",
        "commands",
        "hooks",
        "mcp",
        "mcpservers",
        "providers",
        "runtime",
        "scripts",
        "servers",
        "src",
    }
)
_MAX_MANIFEST_NODES = 4096


def _root_before_suffix(parts: tuple[str, ...], suffix: tuple[str, ...]) -> str:
    root_parts = parts[: -len(suffix)]
    return PurePosixPath(*root_parts).as_posix() if root_parts else "."


def _load_manifest_mapping(entry: InventoryEntry) -> Mapping[object, object] | None:
    if entry.kind != "file" or entry.content is None:
        return None
    try:
        parsed: object = json.loads(entry.content)
    except (ValueError, OverflowError, RecursionError):
        return None
    if not isinstance(parsed, Mapping):
        return None
    return parsed


def _package_json_has_plugin_marker(entry: InventoryEntry) -> bool:
    parsed = _load_manifest_mapping(entry)
    if parsed is None:
        return False
    if any(marker in parsed for marker in _PACKAGE_MARKERS):
        return True
    for platform in _PLATFORM_CONTAINERS:
        platform_config = parsed.get(platform)
        if isinstance(platform_config, Mapping) and "extensions" in platform_config:
            return True
    return False


def _normalized_component_name(value: str) -> str:
    return "".join(character for character in value.casefold() if character.isalnum())


def _manifest_is_invalid_or_runtime(entry: InventoryEntry) -> bool:
    parsed = _load_manifest_mapping(entry)
    if parsed is None:
        return True

    pending: list[object] = [parsed]
    visited = 0
    while pending:
        value = pending.pop()
        visited += 1
        if visited > _MAX_MANIFEST_NODES:
            return True
        if isinstance(value, Mapping):
            for key, item in value.items():
                if not isinstance(key, str):
                    return True
                if _normalized_component_name(key) in _RUNTIME_DECLARATION_KEYS:
                    return True
                pending.append(item)
        elif isinstance(value, (list, tuple)):
            pending.extend(value)
        elif value is not None and not isinstance(value, (str, bool, int, float)):
            return True
    return False


def _manifest_descriptor(entry: InventoryEntry) -> tuple[str, str] | None:
    parts = PurePosixPath(entry.path).parts
    for suffix, kind in _METADATA_MANIFESTS.items():
        if len(parts) >= len(suffix) and parts[-len(suffix) :] == suffix:
            return _root_before_suffix(parts, suffix), kind

    name = parts[-1]
    if name in _ROOT_MANIFESTS:
        root = PurePosixPath(*parts[:-1]).as_posix() if len(parts) > 1 else "."
        return root, _ROOT_MANIFESTS[name]
    if entry.kind == "file" and name == "package.json" and _package_json_has_plugin_marker(entry):
        root = PurePosixPath(*parts[:-1]).as_posix() if len(parts) > 1 else "."
        return root, "package_json"
    return None


def _is_within(path: str, root: str) -> bool:
    return root == "." or path == root or path.startswith(f"{root}/")


def _skill_roots(inventory: Inventory) -> tuple[str, ...]:
    roots = {
        PurePosixPath(entry.path).parent.as_posix()
        for entry in inventory.entries
        if entry.kind == "file" and PurePosixPath(entry.path).name in {"SKILL.md", "skill.md"}
    }
    return tuple(sorted(roots))


def _relative_to(path: str, root: str) -> str:
    return path if root == "." else path.removeprefix(f"{root}/")


def _is_documentation_or_marketplace(path: str, root: str) -> bool:
    relative = PurePosixPath(_relative_to(path, root))
    parts = relative.parts
    if not parts:
        return False
    upper_name = parts[-1].upper()
    if len(parts) == 1 and upper_name.startswith(("README", "CHANGELOG", "LICENSE")):
        return True
    if parts[0].casefold() in _DOC_DIRECTORIES:
        return True
    return parts[-1].casefold() in _MARKETPLACE_NAMES and (
        len(parts) == 1 or parts[0].casefold() in _METADATA_DIRECTORIES
    )


def _is_known_runtime_directory(path: str, root: str) -> bool:
    relative = PurePosixPath(_relative_to(path, root))
    return any(
        _normalized_component_name(part) in _RUNTIME_DIRECTORY_NAMES for part in relative.parts
    )


def _classify_package(
    root: str,
    inventory: Inventory,
    skill_roots: tuple[str, ...],
    manifest_paths: frozenset[str],
) -> str:
    enclosed_skill_roots = tuple(item for item in skill_roots if _is_within(item, root))
    for entry in inventory.entries:
        if not _is_within(entry.path, root):
            continue
        if any(_is_within(entry.path, skill_root) for skill_root in enclosed_skill_roots):
            continue
        if _is_documentation_or_marketplace(entry.path, root):
            continue
        if entry.path in manifest_paths:
            if _manifest_is_invalid_or_runtime(entry):
                return "mixed"
            continue
        if entry.kind == "directory":
            if _is_known_runtime_directory(entry.path, root):
                return "mixed"
            continue
        return "mixed"
    return "skills_only"


def detect_boundaries(inventory: Inventory) -> tuple[PackageBoundary, ...]:
    """Return deterministic plugin boundaries inferred only from static inventory data."""
    descriptors: list[tuple[InventoryEntry, str, str]] = []
    for entry in inventory.entries:
        descriptor = _manifest_descriptor(entry)
        if descriptor is not None:
            root, kind = descriptor
            descriptors.append((entry, root, kind))

    manifest_paths = frozenset(entry.path for entry, _, _ in descriptors)
    skill_roots = _skill_roots(inventory)
    package_kinds = {
        root: _classify_package(root, inventory, skill_roots, manifest_paths)
        for _, root, _ in descriptors
    }
    return tuple(
        PackageBoundary(
            root=root,
            manifest_path=entry.path,
            manifest_kind=kind,
            package_kind=package_kinds[root],
        )
        for entry, root, kind in sorted(descriptors, key=lambda item: item[0].path)
    )
