"""Conservative, evidence-first static portability analysis."""

from __future__ import annotations

import json
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import PurePosixPath
from urllib.parse import unquote

from .models import (
    Classification,
    DecisionReason,
    Evidence,
    ExternalRequirements,
    Inventory,
    InventoryEntry,
    PackageBoundary,
    ReasonCode,
    SkillCandidate,
    ValidationResult,
)

_EVIDENCE_VALUE_LIMIT = 256
_MAX_EVIDENCE_PER_REASON = 64
_MAX_MANIFEST_NODES = 4096
_MAX_MANIFEST_DEPTH = 64
_MAX_SYMLINK_CHAIN = 64
_PLUGIN_VARIABLE_RE = re.compile(
    r"\$\{(?:(?:CLAUDE_|CODEX_|CURSOR_|GEMINI_|OPENCLAW_)?PLUGIN_(?:ROOT|DIR|PATH)"
    r"|EXTENSION_(?:ROOT|DIR|PATH))\}"
    r"|\$(?:CLAUDE_|CODEX_|CURSOR_|GEMINI_|OPENCLAW_)?PLUGIN_ROOT\b"
    r"|\bextensionPath\b",
    re.IGNORECASE,
)
_DYNAMIC_RE = re.compile(r"\$(?:\{[^}]+\}|[A-Za-z_][A-Za-z0-9_]*)|[*?]|\{[^}]+\}")
_MARKDOWN_DESTINATION_RE = re.compile(
    r"!?\[[^\]]*\]\(\s*(?:<(?P<angle>[^>]+)>|(?P<plain>[^)\s]+))",
)
_PATH_TOKEN_RE = re.compile(
    r"(?<![\w:/.-])"
    r"(?P<path>(?:(?:\.\.?/)+|\$\{[A-Za-z_][A-Za-z0-9_]*\}/|"
    r"[A-Za-z0-9_.-]+/)[A-Za-z0-9_.$/{}/?*+-]+)"
)
_HOST_PATH_TOKEN_RE = re.compile(
    r"(?P<file>file://[^\s`'\"<>]+)"
    r"|(?P<windows>(?<![A-Za-z0-9])[A-Za-z]:(?:\\|/(?!/))[^\s`'\"<>]+)"
    r"|(?P<posix>(?<![\w:/.$}])/(?!/)[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)+)"
    r"|(?P<encoded>(?<![A-Za-z0-9:/])(?:%2e|%2f|%5c)[^\s`'\"<>]+)",
    re.IGNORECASE,
)
_BACKSLASH_PATH_TOKEN_RE = re.compile(r"(?<![A-Za-z0-9_])(?P<path>(?:\.\.\\|\.\\|~\\)[^\s`'\"<>]+)")
_HOME_PATH_TOKEN_RE = re.compile(r"(?<![A-Za-z0-9_./:])(?P<path>~/[^\s`'\"<>]{1,1024})")
_FILE_API_ONE_SEGMENT_PATH_RE = re.compile(
    r"\b(?:open|path|readFile|readFileSync|load)\s*\(\s*[\"']"
    r"(?P<path>/(?!/)[A-Za-z0-9_.-]{1,256}|~/[A-Za-z0-9_.-]{1,256})[\"']",
    re.IGNORECASE,
)
_SHELL_ONE_SEGMENT_PATH_RE = re.compile(
    r"^\s*(?:[-*+]\s+|\$\s+|>\s+)?"
    r"(?:source|cat|less|head|tail|stat|ls|cd|rm|cp|mv|chmod|chown)\s+"
    r"(?:-[A-Za-z0-9_.-]+\s+)*"
    r"(?P<path>/(?!/)[A-Za-z0-9_.-]{1,256}|~/[A-Za-z0-9_.-]{1,256})(?:\s|$)",
    re.IGNORECASE | re.MULTILINE,
)
_MCP_TOOL_RE = re.compile(r"\bmcp__(?P<server>[A-Za-z0-9_.-]+)__(?P<tool>[A-Za-z0-9_.-]+)\b")
_COMMAND_REFERENCE_RE = re.compile(
    r"(?<![\w-])/(?P<slash>[A-Za-z0-9_.-]+)\b"
    r"|\bcommand\s*[:=]\s*[`\"']?(?P<structured>[A-Za-z0-9_.-]+)\b"
    r"|\bcommands?/(?P<path>[A-Za-z0-9_.-]+)\b",
    re.IGNORECASE,
)
_COMPONENT_REFERENCE_RE = re.compile(
    r"\b(?P<kind>agent|hook|provider)\s*[:=]\s*[`\"']?(?P<structured>[A-Za-z0-9_.-]+)\b"
    r"|\b(?P<directory>agents|hooks|providers)/(?P<path>[A-Za-z0-9_.-]+)\b",
    re.IGNORECASE,
)
_IMPORT_RE = re.compile(r"^\s*(?:from|import)\s+(?P<module>[A-Za-z_][A-Za-z0-9_.]*)")
_JS_MODULE_RE = re.compile(
    r"\bfrom\s*[\"'](?P<from>[^\"']+)[\"']"
    r"|\bimport\s*[\"'](?P<side_effect>[^\"']+)[\"']"
    r"|\b(?:import|require|load)\s*\(\s*[\"'](?P<call>[^\"']+)[\"']\s*\)"
)
_RUNTIME_FILENAME_RE = re.compile(
    r"(?<![A-Za-z0-9_./-])(?P<name>[A-Za-z0-9_.-]+\.(?:py|js|ts|mjs|cjs|mts|cts|sh))\b",
    re.IGNORECASE,
)
_PLUGIN_INSTALL_RE = re.compile(
    r"(?:requires?|needs?)\b[^\n]{0,80}\bplugin\b[^\n]{0,80}\b(?:installed|enabled)\b"
    r"|\b(?:install|enable)\b[^\n]{0,80}\bplugin\b"
    r"|\bplugin\b[^\n]{0,80}\bmust\s+be\s+(?:installed|enabled)\b",
    re.IGNORECASE,
)
_URL_SCHEME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*:")
_WINDOWS_ABSOLUTE_RE = re.compile(r"^[A-Za-z]:[\\/]")
_STRUCTURED_SKILL_KEY_RE = re.compile(
    r"\b(?:skill|skill[_-]?(?:name|id|path|root))\s*[:=]\s*[\"']?(?P<value>[^\s,}\]\"']+)",
    re.IGNORECASE,
)
_STRUCTURED_SKILLS_LIST_RE = re.compile(
    r"\bskills\s*[:=]\s*\[(?P<values>[^\]\r\n]{0,2048})\]",
    re.IGNORECASE,
)
_CONFIG_LIST_VALUE_RE = re.compile(
    r"[\"'](?P<quoted>[^\"']{1,256})[\"']|(?P<bare>[A-Za-z0-9_.-]{1,256})"
)
_ORCHESTRATION_CALL_RE = re.compile(
    r"\b(?:runSkill|loadSkill|load_skill|invokeSkill|invoke_skill|skills?\.get)"
    r"\s*\(\s*[\"'](?P<value>[^\"']+)[\"']",
)

_EXTERNAL_COMMANDS = frozenset(
    {
        "bash",
        "bun",
        "curl",
        "docker",
        "git",
        "gh",
        "jq",
        "node",
        "npm",
        "npx",
        "pnpm",
        "python",
        "python3",
        "sh",
        "uv",
        "wget",
        "yarn",
    }
)
_DOCUMENTATION_DIRECTORIES = frozenset({"docs", "doc", "examples", "example"})
_EXPLICIT_LOCAL_DIRECTORIES = frozenset(
    {
        "asset",
        "assets",
        "file",
        "files",
        "prompt",
        "prompts",
        "reference",
        "references",
        "resource",
        "resources",
        "script",
        "scripts",
    }
)
_RUNTIME_DIRECTORIES = frozenset(
    {
        "agent",
        "agents",
        "bin",
        "command",
        "commands",
        "hook",
        "hooks",
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
        "config",
        "configs",
        "orchestration",
        "workflow",
        "workflows",
    }
)
_RUNTIME_FILE_STEMS = frozenset(
    {
        "agent",
        "agents",
        "command",
        "commands",
        "config",
        "hook",
        "hooks",
        "orchestration",
        "provider",
        "providers",
        "runtime",
        "server",
        "workflow",
    }
)
_MANIFEST_COMPONENT_KEYS = {
    "mcp": "mcp",
    "mcpserver": "mcp",
    "mcpservers": "mcp",
    "command": "commands",
    "commands": "commands",
    "agent": "agents",
    "agents": "agents",
    "hook": "hooks",
    "hooks": "hooks",
    "provider": "providers",
    "providers": "providers",
    "bin": "binaries",
    "executables": "binaries",
}
_PACKAGE_PLUGIN_WRAPPERS = frozenset(
    {
        "plugin",
        "openclaw",
        "claudeplugin",
        "codexplugin",
        "cursorplugin",
        "geminiextension",
    }
)
_RUNTIME_MANIFEST_KEYS = frozenset(
    {
        "agent",
        "agents",
        "bin",
        "command",
        "commands",
        "entrypoint",
        "executable",
        "executables",
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
_BLOCKED_CODES = frozenset(
    {
        ReasonCode.SYMLINK_ESCAPE,
        ReasonCode.PATH_TRAVERSAL,
        ReasonCode.PATH_COLLISION,
        ReasonCode.FILE_TOO_LARGE,
        ReasonCode.SCAN_LIMIT_EXCEEDED,
    }
)
_BOUND_CODES = frozenset(
    {
        ReasonCode.PLUGIN_ROOT_VARIABLE,
        ReasonCode.REFERENCE_OUTSIDE_SKILL_ROOT,
        ReasonCode.PLUGIN_OWNED_MCP_TOOL,
        ReasonCode.PLUGIN_COMMAND_REFERENCE,
        ReasonCode.PLUGIN_RUNTIME_FILE_REFERENCE,
        ReasonCode.PLUGIN_RUNTIME_INSIDE_SKILL_ROOT,
        ReasonCode.REFERENCED_BY_PLUGIN_RUNTIME,
        ReasonCode.MISSING_LOCAL_RESOURCE,
        ReasonCode.DYNAMIC_REFERENCE_UNRESOLVED,
    }
)
_MESSAGES = {
    ReasonCode.STANDALONE_NO_PLUGIN_BOUNDARY: "skill has no enclosing plugin boundary",
    ReasonCode.SKILLS_ONLY_PACKAGE: "enclosing plugin package contains only skills and metadata",
    ReasonCode.PLUGIN_ROOT_VARIABLE: "skill uses a plugin-root runtime variable",
    ReasonCode.REFERENCE_OUTSIDE_SKILL_ROOT: "skill references a resource outside its root",
    ReasonCode.PLUGIN_OWNED_MCP_TOOL: "skill calls an MCP tool owned by the plugin",
    ReasonCode.PLUGIN_COMMAND_REFERENCE: "skill invokes a command owned by the plugin",
    ReasonCode.PLUGIN_RUNTIME_FILE_REFERENCE: "skill depends on plugin runtime or components",
    ReasonCode.PLUGIN_RUNTIME_INSIDE_SKILL_ROOT: (
        "skill payload contains a mixed plugin package and its runtime"
    ),
    ReasonCode.REFERENCED_BY_PLUGIN_RUNTIME: "plugin runtime references this skill",
    ReasonCode.MISSING_LOCAL_RESOURCE: "skill references a missing local resource",
    ReasonCode.DYNAMIC_REFERENCE_UNRESOLVED: "skill contains a dynamic resource reference",
    ReasonCode.MIXED_PLUGIN_AUTONOMY_UNPROVEN: (
        "skill is inside a mixed plugin and static autonomy is unproven"
    ),
    ReasonCode.SYMLINK_ESCAPE: "symlink resolves outside the skill root",
    ReasonCode.PATH_TRAVERSAL: "resource reference traverses beyond the source snapshot",
    ReasonCode.INVALID_FRONTMATTER: "skill frontmatter is invalid",
}


@dataclass(frozen=True, slots=True)
class StaticAnalysisResult:
    """Deterministic static decision before any optional FM review."""

    classification: Classification
    reasons: tuple[DecisionReason, ...]
    external_requirements: ExternalRequirements

    def __post_init__(self) -> None:
        object.__setattr__(self, "reasons", tuple(self.reasons))
        if not self.reasons:
            raise ValueError("static analysis must include at least one evidence-backed reason")
        if any(not reason.evidence for reason in self.reasons):
            raise ValueError("every static analysis reason must include evidence")

    @property
    def reason_codes(self) -> frozenset[ReasonCode]:
        """Return unique machine-readable reason codes."""
        return frozenset(reason.code for reason in self.reasons)


@dataclass(slots=True)
class _OwnedComponents:
    mcp: set[str]
    commands: set[str]
    agents: set[str]
    hooks: set[str]
    providers: set[str]
    binaries: set[str]
    runtime_paths: set[str]
    runtime_modules: set[str]

    @classmethod
    def empty(cls) -> _OwnedComponents:
        return cls(set(), set(), set(), set(), set(), set(), set(), set())


class _ReasonCollector:
    def __init__(self) -> None:
        self._items: dict[ReasonCode, tuple[str, list[Evidence]]] = {}
        self._attempts: dict[ReasonCode, int] = {}

    def add(
        self,
        code: ReasonCode,
        evidence: Evidence,
        *,
        message: str | None = None,
    ) -> None:
        attempts = self._attempts.get(code, 0)
        if attempts >= _MAX_EVIDENCE_PER_REASON:
            return
        self._attempts[code] = attempts + 1
        bounded = Evidence(
            path=evidence.path,
            line=evidence.line,
            field=evidence.field,
            value=_bounded(evidence.value),
            detector=evidence.detector,
        )
        if code not in self._items:
            self._items[code] = (message or _MESSAGES.get(code, code.value), [])
        values = self._items[code][1]
        if bounded not in values and len(values) < _MAX_EVIDENCE_PER_REASON:
            values.append(bounded)

    def has_capacity(self, code: ReasonCode) -> bool:
        return self._attempts.get(code, 0) < _MAX_EVIDENCE_PER_REASON

    def add_reason(self, reason: DecisionReason) -> None:
        for evidence in reason.evidence:
            self.add(reason.code, evidence, message=reason.message)

    def build(self) -> tuple[DecisionReason, ...]:
        result: list[DecisionReason] = []
        for code, (message, evidence) in sorted(
            self._items.items(), key=lambda item: item[0].value
        ):
            ordered = tuple(
                sorted(
                    evidence,
                    key=lambda item: (
                        item.path,
                        item.line or 0,
                        item.field or "",
                        item.value,
                        item.detector,
                    ),
                )
            )
            result.append(DecisionReason(code=code, message=message, evidence=ordered))
        return tuple(result)


def _bounded(value: str) -> str:
    if len(value) <= _EVIDENCE_VALUE_LIMIT:
        return value
    return f"{value[: _EVIDENCE_VALUE_LIMIT - 3]}..."


def _normalized_component(value: str) -> str:
    return "".join(character for character in value.casefold() if character.isalnum())


def _is_within(path: str, root: str) -> bool:
    return root == "." or path == root or path.startswith(f"{root}/")


def _is_within_any(path: str, roots: frozenset[str]) -> bool:
    if not roots:
        return False
    if "." in roots:
        return True
    parts = PurePosixPath(path).parts
    return any(
        PurePosixPath(*parts[:index]).as_posix() in roots for index in range(1, len(parts) + 1)
    )


def _relative_to(path: str, root: str) -> str:
    return path if root == "." else path.removeprefix(f"{root}/")


def _line_number(content: str, offset: int) -> int:
    return content.count("\n", 0, offset) + 1


def _text_evidence(
    path: str,
    content: str,
    offset: int,
    value: str,
    detector: str,
    *,
    field: str = "text",
) -> Evidence:
    return Evidence(
        path=path,
        line=_line_number(content, offset),
        field=field,
        value=value,
        detector=detector,
    )


def _collapse_path(base: PurePosixPath, value: str) -> tuple[str | None, bool]:
    """Lexically resolve a relative path and report snapshot escape."""
    parts = list(base.parts) if base.as_posix() != "." else []
    for part in PurePosixPath(value).parts:
        if part in {"", "."}:
            continue
        if part == "..":
            if not parts:
                return None, True
            parts.pop()
        else:
            parts.append(part)
    return (PurePosixPath(*parts).as_posix() if parts else "."), False


def _clean_reference(value: str) -> str:
    cleaned = value.strip().strip("`'\"<>")
    cleaned = cleaned.split("#", 1)[0].split("?", 1)[0]
    return cleaned.rstrip(".,;:")


def _looks_explicit_path(value: str) -> bool:
    if value.startswith(("./", "../", "${", "$")):
        return True
    path = PurePosixPath(value)
    if path.suffix:
        return True
    return bool(path.parts) and _normalized_component(path.parts[0]) in _EXPLICIT_LOCAL_DIRECTORIES


def _is_first_line_shebang_interpreter(content: str, match: re.Match[str]) -> bool:
    start = match.start()
    return (
        match.group("posix") is not None
        and content.startswith("#!")
        and all(character in " \t" for character in content[2:start])
    )


def _path_references(content: str) -> Iterable[tuple[str, int]]:
    for match in _MARKDOWN_DESTINATION_RE.finditer(content):
        value = match.group("angle") or match.group("plain")
        yield _clean_reference(value), match.start()
    for match in _PATH_TOKEN_RE.finditer(content):
        value = _clean_reference(match.group("path"))
        if _looks_explicit_path(value):
            yield value, match.start("path")
    for match in _HOST_PATH_TOKEN_RE.finditer(content):
        if _is_first_line_shebang_interpreter(content, match):
            continue
        value = next(item for item in match.groups() if item is not None)
        yield _clean_reference(value), match.start()
    for match in _BACKSLASH_PATH_TOKEN_RE.finditer(content):
        yield _clean_reference(match.group("path")), match.start("path")
    for pattern in (
        _HOME_PATH_TOKEN_RE,
        _FILE_API_ONE_SEGMENT_PATH_RE,
        _SHELL_ONE_SEGMENT_PATH_RE,
    ):
        for match in pattern.finditer(content):
            yield _clean_reference(match.group("path")), match.start("path")


def _decode_reference(value: str) -> str:
    decoded = value
    for _ in range(4):
        current = unquote(decoded)
        if current == decoded:
            break
        decoded = current
    return decoded


def _is_unsafe_host_reference(value: str) -> bool:
    casefolded = value.casefold()
    return (
        casefolded.startswith("file:")
        or value.startswith(("/", "~/"))
        or _WINDOWS_ABSOLUTE_RE.match(value) is not None
        or "\\" in value
        or "\x00" in value
    )


def _is_candidate_local_reference(value: str) -> bool:
    if not value or value.startswith("#") or value.startswith("//"):
        return False
    return _URL_SCHEME_RE.match(value) is None


def _manifest_json(entry: InventoryEntry) -> Mapping[str, object] | None:
    if entry.kind != "file" or entry.content is None:
        return None
    try:
        parsed: object = json.loads(entry.content)
    except (ValueError, OverflowError, RecursionError):
        return None
    return parsed if isinstance(parsed, Mapping) else None


def _iter_strings(value: object) -> Iterable[str]:
    pending = [value]
    visited = 0
    while pending:
        current = pending.pop()
        visited += 1
        if visited > _MAX_MANIFEST_NODES:
            return
        if isinstance(current, str):
            yield current
        elif isinstance(current, Mapping):
            remaining = _MAX_MANIFEST_NODES - visited - len(pending)
            for item in current.values():
                if remaining <= 0:
                    break
                pending.append(item)
                remaining -= 1
        elif isinstance(current, (list, tuple)):
            remaining = _MAX_MANIFEST_NODES - visited - len(pending)
            pending.extend(current[:remaining])


def _component_symbols(value: object) -> set[str]:
    symbols: set[str] = set()
    if isinstance(value, Mapping):
        for key in value:
            if len(symbols) >= _MAX_MANIFEST_NODES:
                break
            if isinstance(key, str):
                symbols.add(key)
    elif isinstance(value, (list, tuple)):
        for item in value[:_MAX_MANIFEST_NODES]:
            if isinstance(item, str):
                symbols.add(PurePosixPath(item).stem)
            elif isinstance(item, Mapping):
                name = item.get("name") or item.get("id")
                if isinstance(name, str):
                    symbols.add(name)
    elif isinstance(value, str):
        symbols.add(PurePosixPath(value).stem)
    return {item.casefold() for item in symbols if item}


def _path_if_owned(value: str, boundary: PackageBoundary, inventory: Inventory) -> str | None:
    cleaned = _clean_reference(value)
    if not cleaned or _URL_SCHEME_RE.match(cleaned) is not None:
        return None
    relative = cleaned.removeprefix("./")
    candidate = relative if boundary.root == "." else f"{boundary.root}/{relative}"
    return candidate if candidate in inventory.by_path else None


def _is_known_runtime_component_path(path: str, boundary: PackageBoundary) -> bool:
    relative = PurePosixPath(_relative_to(path, boundary.root))
    if not relative.parts:
        return False
    if _normalized_component(relative.parts[0]) in _RUNTIME_DIRECTORIES:
        return True
    return len(relative.parts) == 1 and _normalized_component(relative.stem) in _RUNTIME_FILE_STEMS


def _collect_manifest_components(
    parsed: Mapping[str, object],
    boundary: PackageBoundary,
    inventory: Inventory,
    owned: _OwnedComponents,
) -> None:
    pending: list[object] = [parsed]
    visited = 0
    while pending:
        current = pending.pop()
        visited += 1
        if visited > _MAX_MANIFEST_NODES:
            return
        if isinstance(current, Mapping):
            for raw_key, value in current.items():
                if visited + len(pending) >= _MAX_MANIFEST_NODES:
                    return
                if not isinstance(raw_key, str):
                    continue
                key = _normalized_component(raw_key)
                category = _MANIFEST_COMPONENT_KEYS.get(key)
                if category is not None and not (key == "command" and isinstance(value, str)):
                    getattr(owned, category).update(_component_symbols(value))
                if key in _RUNTIME_MANIFEST_KEYS:
                    for string in _iter_strings(value):
                        path = _path_if_owned(string, boundary, inventory)
                        if path is not None:
                            owned.runtime_paths.add(path)
                pending.append(value)
        elif isinstance(current, (list, tuple)):
            remaining = _MAX_MANIFEST_NODES - visited - len(pending)
            pending.extend(current[:remaining])


def _derive_owned_components(
    candidate: SkillCandidate,
    inventory: Inventory,
    boundaries: tuple[PackageBoundary, ...],
) -> _OwnedComponents:
    boundary = candidate.enclosing_boundary
    owned = _OwnedComponents.empty()
    if boundary is None:
        return owned

    manifest_paths = {item.manifest_path for item in boundaries if item.root == boundary.root} | {
        boundary.manifest_path
    }
    nested_roots = frozenset(
        item.root
        for item in boundaries
        if item.root != boundary.root and _is_within(item.root, boundary.root)
    )
    skill_roots = _excluded_skill_roots(candidate, inventory)
    for path in sorted(manifest_paths):
        entry = inventory.by_path.get(path)
        if entry is None:
            continue
        parsed = _manifest_json(entry)
        if parsed is not None:
            _collect_manifest_components(parsed, boundary, inventory, owned)

    declared_runtime_roots = frozenset(owned.runtime_paths)
    for entry in inventory.entries:
        if (
            not _is_within(entry.path, boundary.root)
            or _is_within(entry.path, candidate.root)
            or _is_within_any(entry.path, nested_roots)
            or _is_within_any(entry.path, skill_roots)
            or _is_documentation(entry.path, boundary)
        ):
            continue
        relative = PurePosixPath(_relative_to(entry.path, boundary.root))
        parts = relative.parts
        if not parts:
            continue
        component = _normalized_component(parts[0])
        symbol = PurePosixPath(parts[-1]).stem.casefold()
        if component in {"command", "commands"}:
            owned.commands.add(symbol)
        elif component in {"agent", "agents"}:
            owned.agents.add(symbol)
        elif component in {"hook", "hooks"}:
            owned.hooks.add(symbol)
        elif component in {"provider", "providers"}:
            owned.providers.add(symbol)
        elif component in {"mcp", "mcpserver", "mcpservers"} and len(parts) > 1:
            owned.mcp.add(parts[1].casefold())
        proven_runtime = (
            entry.executable
            or _is_known_runtime_component_path(entry.path, boundary)
            or _is_within_any(entry.path, declared_runtime_roots)
        )
        if proven_runtime:
            owned.runtime_paths.add(entry.path)
        if entry.executable:
            owned.binaries.update({PurePosixPath(entry.path).name.casefold(), symbol})
        if (
            proven_runtime
            and entry.kind == "file"
            and PurePosixPath(entry.path).suffix.casefold()
            in {
                ".py",
                ".js",
                ".ts",
                ".mjs",
                ".cjs",
                ".mts",
                ".cts",
            }
        ):
            owned.runtime_modules.add(symbol)
            if "src" in parts:
                index = parts.index("src")
                module_parts = list(parts[index + 1 :])
                if module_parts:
                    module_parts[-1] = PurePosixPath(module_parts[-1]).stem
                    owned.runtime_modules.add(".".join(module_parts).casefold())
    return owned


def _add_plugin_symbol_references(
    candidate: SkillCandidate,
    validation: ValidationResult,
    inventory: Inventory,
    owned: _OwnedComponents,
    collector: _ReasonCollector,
) -> None:
    runtime_names = {
        PurePosixPath(path).name.casefold()
        for path in owned.runtime_paths
        if PurePosixPath(path).suffix
    }
    requires = validation.frontmatter.get("requires")
    if isinstance(requires, Mapping):
        entrypoint = inventory.by_path.get(candidate.entrypoint)
        content = entrypoint.content if entrypoint is not None and entrypoint.content else ""
        for key in ("bins", "binaries"):
            for binary in _sequence_of_strings(requires.get(key)):
                if binary.casefold() not in owned.binaries:
                    continue
                if not collector.has_capacity(ReasonCode.PLUGIN_RUNTIME_FILE_REFERENCE):
                    break
                offset = content.find(binary)
                collector.add(
                    ReasonCode.PLUGIN_RUNTIME_FILE_REFERENCE,
                    _text_evidence(
                        candidate.entrypoint,
                        content,
                        max(offset, 0),
                        binary,
                        "static.forward.plugin_binary_requirement",
                        field=f"requires.{key}",
                    ),
                )
    for entry in inventory.entries:
        if (
            entry.kind != "file"
            or entry.content is None
            or not _is_within(entry.path, candidate.root)
        ):
            continue
        content = entry.content
        for match in _MCP_TOOL_RE.finditer(content):
            if not collector.has_capacity(ReasonCode.PLUGIN_OWNED_MCP_TOOL):
                break
            if match.group("server").casefold() in owned.mcp:
                collector.add(
                    ReasonCode.PLUGIN_OWNED_MCP_TOOL,
                    _text_evidence(
                        entry.path,
                        content,
                        match.start(),
                        match.group(0),
                        "static.forward.plugin_owned_mcp",
                        field="mcpTool",
                    ),
                )

        for match in _COMMAND_REFERENCE_RE.finditer(content):
            if not collector.has_capacity(ReasonCode.PLUGIN_COMMAND_REFERENCE):
                break
            symbol = next(value for value in match.groups() if value is not None).casefold()
            if symbol in owned.commands:
                collector.add(
                    ReasonCode.PLUGIN_COMMAND_REFERENCE,
                    _text_evidence(
                        entry.path,
                        content,
                        match.start(),
                        match.group(0).strip("`\"'"),
                        "static.forward.plugin_command",
                        field="command",
                    ),
                )

        for match in _COMPONENT_REFERENCE_RE.finditer(content):
            if not collector.has_capacity(ReasonCode.PLUGIN_RUNTIME_FILE_REFERENCE):
                break
            kind = (match.group("kind") or match.group("directory") or "").casefold()
            category = f"{kind}s" if not kind.endswith("s") else kind
            symbol = (match.group("structured") or match.group("path") or "").casefold()
            if category in {"agents", "hooks", "providers"} and symbol in getattr(owned, category):
                collector.add(
                    ReasonCode.PLUGIN_RUNTIME_FILE_REFERENCE,
                    _text_evidence(
                        entry.path,
                        content,
                        match.start(),
                        match.group(0).strip("`\"'"),
                        "static.forward.plugin_component",
                        field=category[:-1],
                    ),
                )

        for match in _JS_MODULE_RE.finditer(content):
            if not collector.has_capacity(ReasonCode.PLUGIN_RUNTIME_FILE_REFERENCE):
                break
            module = next(value for value in match.groups() if value is not None)
            if _module_is_owned(module, owned.runtime_modules):
                collector.add(
                    ReasonCode.PLUGIN_RUNTIME_FILE_REFERENCE,
                    _text_evidence(
                        entry.path,
                        content,
                        match.start(),
                        module,
                        "static.forward.plugin_import",
                        field="import",
                    ),
                )

        for match in _RUNTIME_FILENAME_RE.finditer(content):
            if not collector.has_capacity(ReasonCode.PLUGIN_RUNTIME_FILE_REFERENCE):
                break
            runtime_name = match.group("name")
            candidate_local = (
                runtime_name if candidate.root == "." else f"{candidate.root}/{runtime_name}"
            )
            if (
                runtime_name.casefold() in runtime_names
                and candidate_local not in inventory.by_path
            ):
                collector.add(
                    ReasonCode.PLUGIN_RUNTIME_FILE_REFERENCE,
                    _text_evidence(
                        entry.path,
                        content,
                        match.start(),
                        runtime_name,
                        "static.forward.plugin_runtime_file",
                        field="runtimeFile",
                    ),
                )

        for line_offset, line in _iter_lines_with_offsets(content):
            import_match = _IMPORT_RE.match(line)
            if import_match is not None:
                module = import_match.group("module")
                if collector.has_capacity(
                    ReasonCode.PLUGIN_RUNTIME_FILE_REFERENCE
                ) and _module_is_owned(module, owned.runtime_modules):
                    collector.add(
                        ReasonCode.PLUGIN_RUNTIME_FILE_REFERENCE,
                        _text_evidence(
                            entry.path,
                            content,
                            line_offset + import_match.start("module"),
                            import_match.group("module"),
                            "static.forward.plugin_import",
                            field="import",
                        ),
                    )

            command = _command_binary(line)
            if (
                collector.has_capacity(ReasonCode.PLUGIN_RUNTIME_FILE_REFERENCE)
                and command is not None
                and command.casefold() in owned.binaries
            ):
                position = line.find(command)
                collector.add(
                    ReasonCode.PLUGIN_RUNTIME_FILE_REFERENCE,
                    _text_evidence(
                        entry.path,
                        content,
                        line_offset + max(position, 0),
                        command,
                        "static.forward.plugin_binary",
                        field="binary",
                    ),
                )


def _module_is_owned(module: str, owned_modules: set[str]) -> bool:
    normalized = module.casefold().replace("/", ".")
    for extension in (".mjs", ".cjs", ".mts", ".cts", ".js", ".ts"):
        if normalized.endswith(extension):
            normalized = normalized.removesuffix(extension)
            break
    parts = normalized.split(".")
    return any(".".join(parts[:index]) in owned_modules for index in range(1, len(parts) + 1))


def _iter_lines_with_offsets(content: str) -> Iterable[tuple[int, str]]:
    offset = 0
    for line in content.splitlines(keepends=True):
        yield offset, line.rstrip("\r\n")
        offset += len(line)
    if content and not content.endswith(("\n", "\r")):
        return


def _command_binary(line: str) -> str | None:
    stripped = line.strip()
    if not stripped or stripped.startswith(("```", "---", "#")):
        return None
    stripped = re.sub(r"^(?:[-*+]\s+|\$\s+|>\s+)", "", stripped)
    match = re.match(r"(?:(?:sudo|env)\s+)?(?P<binary>[A-Za-z0-9_.+-]+)(?:\s|$)", stripped)
    return match.group("binary") if match is not None else None


def _is_runtime_path(path: str, boundary: PackageBoundary, owned: _OwnedComponents) -> bool:
    if path in owned.runtime_paths:
        return True
    return _is_known_runtime_component_path(path, boundary)


def _analyze_forward_paths(
    candidate: SkillCandidate,
    inventory: Inventory,
    owned: _OwnedComponents,
    collector: _ReasonCollector,
) -> None:
    by_path = inventory.by_path
    boundary = candidate.enclosing_boundary
    for entry in inventory.entries:
        if (
            entry.kind != "file"
            or entry.content is None
            or not _is_within(entry.path, candidate.root)
        ):
            continue
        content = entry.content
        for match in _PLUGIN_VARIABLE_RE.finditer(content):
            if not collector.has_capacity(ReasonCode.PLUGIN_ROOT_VARIABLE):
                break
            collector.add(
                ReasonCode.PLUGIN_ROOT_VARIABLE,
                _text_evidence(
                    entry.path,
                    content,
                    match.start(),
                    match.group(0),
                    "static.forward.plugin_root_variable",
                ),
            )
        for match in _PLUGIN_INSTALL_RE.finditer(content):
            if not collector.has_capacity(ReasonCode.PLUGIN_RUNTIME_FILE_REFERENCE):
                break
            collector.add(
                ReasonCode.PLUGIN_RUNTIME_FILE_REFERENCE,
                _text_evidence(
                    entry.path,
                    content,
                    match.start(),
                    match.group(0),
                    "static.forward.plugin_installation",
                    field="instruction",
                ),
            )

        base = PurePosixPath(entry.path).parent
        for source_value, offset in _path_references(content):
            raw = _decode_reference(source_value)
            if _is_unsafe_host_reference(raw):
                if collector.has_capacity(ReasonCode.PATH_TRAVERSAL):
                    collector.add(
                        ReasonCode.PATH_TRAVERSAL,
                        _text_evidence(
                            entry.path,
                            content,
                            offset,
                            source_value,
                            "static.forward.host_path",
                            field="path",
                        ),
                    )
                continue
            if not _is_candidate_local_reference(raw):
                continue
            if _PLUGIN_VARIABLE_RE.search(raw) is not None:
                continue
            if _DYNAMIC_RE.search(raw) is not None:
                if collector.has_capacity(ReasonCode.DYNAMIC_REFERENCE_UNRESOLVED):
                    collector.add(
                        ReasonCode.DYNAMIC_REFERENCE_UNRESOLVED,
                        _text_evidence(
                            entry.path,
                            content,
                            offset,
                            raw,
                            "static.forward.dynamic_reference",
                            field="path",
                        ),
                    )
                continue

            resolved, escaped = _collapse_path(base, raw)
            if escaped or resolved is None:
                if collector.has_capacity(ReasonCode.PATH_TRAVERSAL):
                    collector.add(
                        ReasonCode.PATH_TRAVERSAL,
                        _text_evidence(
                            entry.path,
                            content,
                            offset,
                            raw,
                            "static.forward.path_traversal",
                            field="path",
                        ),
                    )
                continue

            target = by_path.get(resolved)
            if target is not None:
                if not _is_within(resolved, candidate.root):
                    if collector.has_capacity(ReasonCode.REFERENCE_OUTSIDE_SKILL_ROOT):
                        collector.add(
                            ReasonCode.REFERENCE_OUTSIDE_SKILL_ROOT,
                            _text_evidence(
                                entry.path,
                                content,
                                offset,
                                f"{raw} -> {resolved}",
                                "static.forward.outside_reference",
                                field="path",
                            ),
                        )
                    if (
                        boundary is not None
                        and _is_within(resolved, boundary.root)
                        and _is_runtime_path(resolved, boundary, owned)
                        and collector.has_capacity(ReasonCode.PLUGIN_RUNTIME_FILE_REFERENCE)
                    ):
                        collector.add(
                            ReasonCode.PLUGIN_RUNTIME_FILE_REFERENCE,
                            _text_evidence(
                                entry.path,
                                content,
                                offset,
                                f"{raw} -> {resolved}",
                                "static.forward.plugin_runtime_path",
                                field="path",
                            ),
                        )
                continue

            boundary_target: str | None = None
            if boundary is not None and not raw.startswith((".", "..")):
                candidate_at_boundary = raw if boundary.root == "." else f"{boundary.root}/{raw}"
                if candidate_at_boundary in by_path:
                    boundary_target = candidate_at_boundary
            if boundary_target is not None:
                if collector.has_capacity(ReasonCode.REFERENCE_OUTSIDE_SKILL_ROOT):
                    collector.add(
                        ReasonCode.REFERENCE_OUTSIDE_SKILL_ROOT,
                        _text_evidence(
                            entry.path,
                            content,
                            offset,
                            f"{raw} -> {boundary_target}",
                            "static.forward.outside_reference",
                            field="path",
                        ),
                    )
                if (
                    boundary is not None
                    and _is_runtime_path(boundary_target, boundary, owned)
                    and collector.has_capacity(ReasonCode.PLUGIN_RUNTIME_FILE_REFERENCE)
                ):
                    collector.add(
                        ReasonCode.PLUGIN_RUNTIME_FILE_REFERENCE,
                        _text_evidence(
                            entry.path,
                            content,
                            offset,
                            f"{raw} -> {boundary_target}",
                            "static.forward.plugin_runtime_path",
                            field="path",
                        ),
                    )
            else:
                if collector.has_capacity(ReasonCode.MISSING_LOCAL_RESOURCE):
                    collector.add(
                        ReasonCode.MISSING_LOCAL_RESOURCE,
                        _text_evidence(
                            entry.path,
                            content,
                            offset,
                            f"{raw} -> {resolved}",
                            "static.forward.missing_reference",
                            field="path",
                        ),
                    )


def _analyze_symlinks(
    candidate: SkillCandidate,
    inventory: Inventory,
    collector: _ReasonCollector,
) -> None:
    by_path = inventory.by_path
    for entry in inventory.entries:
        if entry.kind != "symlink" or not _is_within(entry.path, candidate.root):
            continue
        assert entry.symlink_target is not None
        current = entry
        visited: set[str] = set()
        steps = 0
        while current.kind == "symlink":
            steps += 1
            if steps > _MAX_SYMLINK_CHAIN:
                if collector.has_capacity(ReasonCode.DYNAMIC_REFERENCE_UNRESOLVED):
                    collector.add(
                        ReasonCode.DYNAMIC_REFERENCE_UNRESOLVED,
                        Evidence(
                            path=entry.path,
                            line=None,
                            field="symlinkTarget",
                            value=f"chain exceeds {_MAX_SYMLINK_CHAIN} links",
                            detector="static.symlink.chain_limit",
                        ),
                    )
                break
            if current.path in visited:
                if collector.has_capacity(ReasonCode.DYNAMIC_REFERENCE_UNRESOLVED):
                    collector.add(
                        ReasonCode.DYNAMIC_REFERENCE_UNRESOLVED,
                        Evidence(
                            path=entry.path,
                            line=None,
                            field="symlinkTarget",
                            value=f"{entry.symlink_target} (cycle)",
                            detector="static.symlink.cycle",
                        ),
                    )
                break
            visited.add(current.path)
            target = current.symlink_target or ""
            if _is_unsafe_host_reference(target):
                if collector.has_capacity(ReasonCode.SYMLINK_ESCAPE):
                    collector.add(
                        ReasonCode.SYMLINK_ESCAPE,
                        Evidence(
                            path=entry.path,
                            line=None,
                            field="symlinkTarget",
                            value=target,
                            detector="static.symlink.escape",
                        ),
                    )
                break
            resolved, escaped = _collapse_path(PurePosixPath(current.path).parent, target)
            if escaped or resolved is None or not _is_within(resolved, candidate.root):
                if collector.has_capacity(ReasonCode.SYMLINK_ESCAPE):
                    collector.add(
                        ReasonCode.SYMLINK_ESCAPE,
                        Evidence(
                            path=entry.path,
                            line=None,
                            field="symlinkTarget",
                            value=f"{target} -> {resolved or '<outside snapshot>'}",
                            detector="static.symlink.escape",
                        ),
                    )
                break
            next_entry = by_path.get(resolved)
            if next_entry is None:
                if collector.has_capacity(ReasonCode.MISSING_LOCAL_RESOURCE):
                    collector.add(
                        ReasonCode.MISSING_LOCAL_RESOURCE,
                        Evidence(
                            path=entry.path,
                            line=None,
                            field="symlinkTarget",
                            value=f"{target} -> {resolved}",
                            detector="static.symlink.dangling",
                        ),
                    )
                break
            current = next_entry


def _is_documentation(path: str, boundary: PackageBoundary) -> bool:
    relative = PurePosixPath(_relative_to(path, boundary.root))
    parts = tuple(part.casefold() for part in relative.parts)
    documentation_indexes = [
        index for index, part in enumerate(parts[:-1]) if part in _DOCUMENTATION_DIRECTORIES
    ]
    if documentation_indexes:
        named_component = parts[0] in {
            "agent",
            "agents",
            "command",
            "commands",
            "hook",
            "hooks",
            "mcp",
            "mcpserver",
            "mcpservers",
            "provider",
            "providers",
        }
        if documentation_indexes != [1] or not named_component:
            return True
    name = relative.name.casefold()
    return name.startswith(("readme", "changelog", "license"))


def _skill_roots(inventory: Inventory) -> tuple[str, ...]:
    return tuple(
        sorted(
            {
                PurePosixPath(entry.path).parent.as_posix()
                for entry in inventory.entries
                if entry.kind == "file"
                and PurePosixPath(entry.path).name in {"SKILL.md", "skill.md"}
            }
        )
    )


def _excluded_skill_roots(candidate: SkillCandidate, inventory: Inventory) -> frozenset[str]:
    """Return sibling skill payloads, never an ancestor that shadows plugin runtime."""
    return frozenset(
        root
        for root in _skill_roots(inventory)
        if root != candidate.root and not _is_within(candidate.root, root)
    )


def _structured_reverse_reference(
    value: object,
    candidate: SkillCandidate,
    skill_name: str,
    *,
    manifest: bool,
    parent_key: str = "",
    depth: int = 0,
    budget: list[int] | None = None,
) -> str | None:
    budget = [0] if budget is None else budget
    budget[0] += 1
    if budget[0] > _MAX_MANIFEST_NODES or depth > _MAX_MANIFEST_DEPTH:
        return None
    if isinstance(value, Mapping):
        type_value = value.get("type")
        name_value = value.get("name")
        if (
            isinstance(type_value, str)
            and type_value.casefold() == "skill"
            and isinstance(name_value, str)
            and name_value.casefold() == skill_name.casefold()
        ):
            return f"type=skill,name={name_value}"
        for raw_key, item in value.items():
            if budget[0] >= _MAX_MANIFEST_NODES:
                return None
            if not isinstance(raw_key, str):
                continue
            key = _normalized_component(raw_key)
            if (
                manifest
                and key == "skills"
                and (depth == 0 or (depth == 1 and parent_key in _PACKAGE_PLUGIN_WRAPPERS))
            ):
                continue
            if key in {"skill", "skills", "skillname", "skillid", "skillpath", "skillroot"}:
                for string in _iter_strings(item):
                    if _matches_skill_identity(string, candidate, skill_name):
                        return f"{raw_key}={string}"
            nested = _structured_reverse_reference(
                item,
                candidate,
                skill_name,
                manifest=manifest,
                parent_key=key,
                depth=depth + 1,
                budget=budget,
            )
            if nested is not None:
                return nested
    elif isinstance(value, (list, tuple)):
        if not manifest and parent_key == "skills":
            for item in value:
                if isinstance(item, str) and _matches_skill_identity(item, candidate, skill_name):
                    return f"skills={item}"
        for item in value:
            if budget[0] >= _MAX_MANIFEST_NODES:
                return None
            nested = _structured_reverse_reference(
                item,
                candidate,
                skill_name,
                manifest=manifest,
                parent_key=parent_key,
                depth=depth + 1,
                budget=budget,
            )
            if nested is not None:
                return nested
    return None


def _without_packaging_skills(
    value: object,
    *,
    depth: int = 0,
    budget: list[int] | None = None,
    parent_key: str = "",
) -> object:
    """Drop manifest-only skill registration fields before reverse path matching."""
    budget = [0] if budget is None else budget
    budget[0] += 1
    if budget[0] > _MAX_MANIFEST_NODES or depth > _MAX_MANIFEST_DEPTH:
        return None
    if isinstance(value, Mapping):
        normalized: dict[str, object] = {}
        for key, item in value.items():
            if budget[0] >= _MAX_MANIFEST_NODES:
                break
            if not isinstance(key, str):
                continue
            normalized_key = _normalized_component(key)
            if normalized_key == "skills" and (
                depth == 0 or (depth == 1 and parent_key in _PACKAGE_PLUGIN_WRAPPERS)
            ):
                continue
            normalized[key] = _without_packaging_skills(
                item,
                depth=depth + 1,
                budget=budget,
                parent_key=normalized_key,
            )
        return normalized
    if isinstance(value, (list, tuple)):
        normalized_list: list[object] = []
        for item in value:
            if budget[0] >= _MAX_MANIFEST_NODES:
                break
            normalized_list.append(
                _without_packaging_skills(
                    item,
                    depth=depth + 1,
                    budget=budget,
                    parent_key=parent_key,
                )
            )
        return normalized_list
    return value


def _matches_skill_identity(value: str, candidate: SkillCandidate, skill_name: str) -> bool:
    cleaned = _clean_reference(value).removeprefix("./")
    return (
        cleaned.casefold() == skill_name.casefold()
        or cleaned == candidate.root
        or cleaned == candidate.entrypoint
        or cleaned.startswith(f"{candidate.root}/")
    )


def _analyze_reverse_dependencies(
    candidate: SkillCandidate,
    validation: ValidationResult,
    inventory: Inventory,
    boundaries: tuple[PackageBoundary, ...],
    owned: _OwnedComponents,
    collector: _ReasonCollector,
) -> None:
    boundary = candidate.enclosing_boundary
    if boundary is None or validation.name is None:
        return
    manifest_paths = {item.manifest_path for item in boundaries if item.root == boundary.root} | {
        boundary.manifest_path
    }
    nested_roots = frozenset(
        item.root
        for item in boundaries
        if item.root != boundary.root and _is_within(item.root, boundary.root)
    )
    skill_roots = _excluded_skill_roots(candidate, inventory)
    for entry in inventory.entries:
        if (
            entry.kind != "file"
            or entry.content is None
            or not _is_within(entry.path, boundary.root)
            or _is_within(entry.path, candidate.root)
            or _is_within_any(entry.path, nested_roots)
            or _is_within_any(entry.path, skill_roots)
            or _is_documentation(entry.path, boundary)
            or not (
                entry.path in manifest_paths
                or entry.executable
                or entry.path in owned.runtime_paths
                or _is_known_runtime_component_path(entry.path, boundary)
            )
        ):
            continue
        content = entry.content
        parsed = _manifest_json(entry)
        path_search_content = content
        if entry.path in manifest_paths and parsed is not None:
            path_search_content = json.dumps(
                _without_packaging_skills(parsed), ensure_ascii=False, separators=(",", ":")
            )
        exact_match = re.search(
            rf"(?<![A-Za-z0-9_.-]){re.escape(candidate.root)}(?:/[A-Za-z0-9_./-]+)?",
            path_search_content,
        )
        if exact_match is not None and collector.has_capacity(
            ReasonCode.REFERENCED_BY_PLUGIN_RUNTIME
        ):
            matched_value = exact_match.group(0)
            original_offset = content.find(matched_value)
            collector.add(
                ReasonCode.REFERENCED_BY_PLUGIN_RUNTIME,
                _text_evidence(
                    entry.path,
                    content,
                    max(original_offset, 0),
                    matched_value,
                    "static.reverse.skill_path",
                    field="skillPath",
                ),
            )

        if parsed is not None:
            structured = _structured_reverse_reference(
                parsed,
                candidate,
                validation.name,
                manifest=entry.path in manifest_paths,
            )
            if structured is not None and collector.has_capacity(
                ReasonCode.REFERENCED_BY_PLUGIN_RUNTIME
            ):
                source_value = structured.rsplit("=", 1)[-1]
                offset = content.find(source_value)
                collector.add(
                    ReasonCode.REFERENCED_BY_PLUGIN_RUNTIME,
                    _text_evidence(
                        entry.path,
                        content,
                        max(offset, 0),
                        source_value,
                        "static.reverse.structured_skill",
                        field="config",
                    ),
                )
        elif entry.path not in manifest_paths:
            for match in _STRUCTURED_SKILL_KEY_RE.finditer(content):
                if not collector.has_capacity(ReasonCode.REFERENCED_BY_PLUGIN_RUNTIME):
                    break
                if _matches_skill_identity(match.group("value"), candidate, validation.name):
                    collector.add(
                        ReasonCode.REFERENCED_BY_PLUGIN_RUNTIME,
                        _text_evidence(
                            entry.path,
                            content,
                            match.start(),
                            match.group(0),
                            "static.reverse.structured_skill",
                            field="config",
                        ),
                    )
            for match in _STRUCTURED_SKILLS_LIST_RE.finditer(content):
                if not collector.has_capacity(ReasonCode.REFERENCED_BY_PLUGIN_RUNTIME):
                    break
                list_matched_value: str | None = None
                for index, value_match in enumerate(
                    _CONFIG_LIST_VALUE_RE.finditer(match.group("values"))
                ):
                    if index >= 64:
                        break
                    value = value_match.group("quoted") or value_match.group("bare") or ""
                    if _matches_skill_identity(value, candidate, validation.name):
                        list_matched_value = value
                        break
                if list_matched_value is not None:
                    value_offset = content.find(list_matched_value, match.start(), match.end())
                    collector.add(
                        ReasonCode.REFERENCED_BY_PLUGIN_RUNTIME,
                        _text_evidence(
                            entry.path,
                            content,
                            max(value_offset, match.start()),
                            list_matched_value,
                            "static.reverse.structured_skill_list",
                            field="config.skills",
                        ),
                    )
            for match in _ORCHESTRATION_CALL_RE.finditer(content):
                if not collector.has_capacity(ReasonCode.REFERENCED_BY_PLUGIN_RUNTIME):
                    break
                if _matches_skill_identity(match.group("value"), candidate, validation.name):
                    collector.add(
                        ReasonCode.REFERENCED_BY_PLUGIN_RUNTIME,
                        _text_evidence(
                            entry.path,
                            content,
                            match.start(),
                            match.group(0),
                            "static.reverse.orchestration",
                            field="orchestration",
                        ),
                    )


def _sequence_of_strings(value: object) -> Iterable[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, (list, tuple)):
        for item in value:
            if isinstance(item, str):
                yield item


def _external_requirements(
    validation: ValidationResult,
    candidate: SkillCandidate,
    inventory: Inventory,
    owned: _OwnedComponents,
) -> ExternalRequirements:
    binaries: set[str] = set()
    environment: set[str] = set()
    requires = validation.frontmatter.get("requires")
    if isinstance(requires, Mapping):
        for key in ("bins", "binaries"):
            for item in _sequence_of_strings(requires.get(key)):
                if (
                    re.fullmatch(r"[A-Za-z0-9_.+-]+", item)
                    and item.casefold() not in owned.binaries
                ):
                    binaries.add(item)
        for key in ("env", "environment"):
            for item in _sequence_of_strings(requires.get(key)):
                if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", item):
                    environment.add(item)

    for entry in inventory.entries:
        if (
            entry.kind != "file"
            or entry.content is None
            or not _is_within(entry.path, candidate.root)
        ):
            continue
        for _, line in _iter_lines_with_offsets(entry.content):
            binary = _command_binary(line)
            if binary in _EXTERNAL_COMMANDS and binary.casefold() not in owned.binaries:
                binaries.add(binary)
    return ExternalRequirements(
        binaries=tuple(sorted(binaries)),
        environment=tuple(sorted(environment)),
    )


def _classification_for(
    validation: ValidationResult,
    reason_codes: frozenset[ReasonCode],
    candidate: SkillCandidate,
) -> Classification:
    if reason_codes & _BLOCKED_CODES:
        return Classification.BLOCKED
    if not validation.valid or ReasonCode.INVALID_FRONTMATTER in reason_codes:
        return Classification.INVALID
    if reason_codes & _BOUND_CODES:
        return Classification.PLUGIN_BOUND
    boundary = candidate.enclosing_boundary
    if boundary is None:
        return Classification.PORTABLE
    if boundary.package_kind == "skills_only":
        return Classification.PORTABLE
    return Classification.AMBIGUOUS


def _base_reason(
    candidate: SkillCandidate,
    classification: Classification,
) -> tuple[ReasonCode, Evidence] | None:
    if classification is Classification.PORTABLE and candidate.enclosing_boundary is None:
        return (
            ReasonCode.STANDALONE_NO_PLUGIN_BOUNDARY,
            Evidence(
                path=candidate.entrypoint,
                line=1,
                field="enclosingPackage",
                value="none",
                detector="static.classification.standalone",
            ),
        )
    if classification is Classification.PORTABLE and candidate.enclosing_boundary is not None:
        boundary = candidate.enclosing_boundary
        return (
            ReasonCode.SKILLS_ONLY_PACKAGE,
            Evidence(
                path=boundary.manifest_path,
                line=1,
                field="packageKind",
                value=boundary.package_kind,
                detector="static.classification.skills_only",
            ),
        )
    if classification is Classification.AMBIGUOUS and candidate.enclosing_boundary is not None:
        boundary = candidate.enclosing_boundary
        return (
            ReasonCode.MIXED_PLUGIN_AUTONOMY_UNPROVEN,
            Evidence(
                path=boundary.manifest_path,
                line=1,
                field="packageKind",
                value=boundary.package_kind,
                detector="static.classification.mixed_unproven",
            ),
        )
    return None


def analyze_static(
    candidate: SkillCandidate,
    validation: ValidationResult,
    inventory: Inventory,
    boundaries: tuple[PackageBoundary, ...],
) -> StaticAnalysisResult:
    """Classify a candidate without executing or reading beyond its immutable inventory."""
    collector = _ReasonCollector()
    for reason in validation.reasons:
        collector.add_reason(reason)
    if not validation.valid and not validation.reasons:
        collector.add(
            ReasonCode.INVALID_FRONTMATTER,
            Evidence(
                path=candidate.entrypoint,
                line=1,
                field="frontmatter",
                value="invalid",
                detector="static.validation.fail_closed",
            ),
        )

    for boundary in boundaries:
        if boundary.package_kind == "mixed" and _is_within(boundary.root, candidate.root):
            collector.add(
                ReasonCode.PLUGIN_RUNTIME_INSIDE_SKILL_ROOT,
                Evidence(
                    path=boundary.manifest_path,
                    line=1,
                    field="packageKind",
                    value=boundary.package_kind,
                    detector="static.payload.mixed_plugin",
                ),
            )

    owned = _derive_owned_components(candidate, inventory, boundaries)
    _analyze_symlinks(candidate, inventory, collector)
    _analyze_forward_paths(candidate, inventory, owned, collector)
    _add_plugin_symbol_references(candidate, validation, inventory, owned, collector)
    _analyze_reverse_dependencies(candidate, validation, inventory, boundaries, owned, collector)

    reasons = collector.build()
    reason_codes = frozenset(reason.code for reason in reasons)
    classification = _classification_for(validation, reason_codes, candidate)
    base = _base_reason(candidate, classification)
    if base is not None:
        collector.add(*base)
        reasons = collector.build()
    return StaticAnalysisResult(
        classification=classification,
        reasons=reasons,
        external_requirements=_external_requirements(validation, candidate, inventory, owned),
    )
