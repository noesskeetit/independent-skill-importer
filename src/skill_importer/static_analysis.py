"""Conservative, evidence-first static portability analysis."""

from __future__ import annotations

import json
import re
from bisect import bisect_left
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
_PLUGIN_NEGATION_CONTEXT_CHARS = 256
_PLUGIN_ENV_NAME_PATTERN = (
    r"(?:(?:CLAUDE_|CODEX_|CURSOR_|GEMINI_|OPENCLAW_)?PLUGIN_(?:ROOT|DIR|PATH)"
    r"|EXTENSION_(?:ROOT|DIR|PATH))"
)
_PLUGIN_VARIABLE_RE = re.compile(
    rf"\$\{{{_PLUGIN_ENV_NAME_PATTERN}(?![A-Za-z0-9_])[^}}\r\n]{{0,256}}\}}"
    rf"|\$\{{[#!]{_PLUGIN_ENV_NAME_PATTERN}(?![A-Za-z0-9_])[^}}\r\n]{{0,256}}\}}"
    rf"|\$\{{env:{_PLUGIN_ENV_NAME_PATTERN}\}}"
    r"|\$(?:CLAUDE_|CODEX_|CURSOR_|GEMINI_|OPENCLAW_)?PLUGIN_(?:ROOT|DIR|PATH)\b"
    r"|\$EXTENSION_(?:ROOT|DIR|PATH)\b"
    rf"|\$env:{_PLUGIN_ENV_NAME_PATTERN}\b"
    rf"|%{_PLUGIN_ENV_NAME_PATTERN}(?::[^%\r\n]{{0,256}})?%"
    rf"|\b(?:process|Deno|Bun)\.env\.{_PLUGIN_ENV_NAME_PATTERN}\b"
    rf"|\b(?:process|Deno|Bun)\.env\[\s*[\"']{_PLUGIN_ENV_NAME_PATTERN}[\"']\s*\]"
    rf"|\bos\.environ\[\s*[\"']{_PLUGIN_ENV_NAME_PATTERN}[\"']\s*\]"
    rf"|\bstd::env::var\(\s*[\"']{_PLUGIN_ENV_NAME_PATTERN}[\"']\s*\)"
    rf"|\bSystem\.getenv\(\s*[\"']{_PLUGIN_ENV_NAME_PATTERN}[\"']\s*\)"
    rf"|\b(?:os\.(?:getenv|environ\.get)|(?:env|environment)\.get|"
    rf"(?:process|Deno|Bun)\.env\.get)\(\s*[\"']{_PLUGIN_ENV_NAME_PATTERN}[\"']"
    r"\s*(?:,[^)\r\n]{0,256})?\)"
    rf"|\bgetenv\(\s*[\"']{_PLUGIN_ENV_NAME_PATTERN}[\"']\s*\)"
    rf"|\b(?-i:ENV)\[\s*[\"']{_PLUGIN_ENV_NAME_PATTERN}[\"']\s*\]"
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
    r"|(?P<posix>(?<![\w:/.$}%])/(?!/)[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)+)"
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
    r"|\bplugin\b[^\n]{0,80}\bmust(?:\s+already)?\s+be\s+(?:installed|enabled)\b"
    r"|\bwithout\b[^\n]{0,80}\b(?:installing|enabling)\b[^\n]{0,80}\bplugin\b"
    r"|\bwithout\b[^\n]{0,80}\bplugin\b[^\n]{0,80}\b(?:installed|enabled)\b",
    re.IGNORECASE,
)
_PROVEN_PLUGIN_INDEPENDENCE_RE = re.compile(
    r"^\s*(?:this\s+skill\s+)?(?:do|does|did)\s+not\s+require\s+"
    r"(?:the\s+|a\s+|any\s+)?plugin\s+to\s+be\s+(?:installed|enabled)\s*[.!]?\s*$"
    r"|^\s*(?:you\s+)?(?:do|does|did)\s+not\s+need\s+to\s+(?:install|enable)\s+"
    r"(?:the\s+|a\s+|any\s+)?plugin\s*[.!]?\s*$",
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
_DECLARED_RUNTIME_ROOT_KEYS = _RUNTIME_MANIFEST_KEYS - {"source", "src"}
_CONTEXTUAL_RUNTIME_ROOT_KEYS = frozenset({"source", "src"})
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
    review_paths: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "reasons", tuple(self.reasons))
        object.__setattr__(self, "review_paths", tuple(sorted(set(self.review_paths))))
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
    explicit_runtime_paths: set[str]
    manifest_runtime_paths: set[str]
    runtime_symlink_paths: set[str]
    recursive_runtime_symlink_paths: set[str]
    declared_runtime_roots: set[str]
    runtime_modules: set[str]

    @classmethod
    def empty(cls) -> _OwnedComponents:
        return cls(
            mcp=set(),
            commands=set(),
            agents=set(),
            hooks=set(),
            providers=set(),
            binaries=set(),
            runtime_paths=set(),
            explicit_runtime_paths=set(),
            manifest_runtime_paths=set(),
            runtime_symlink_paths=set(),
            recursive_runtime_symlink_paths=set(),
            declared_runtime_roots=set(),
            runtime_modules=set(),
        )


@dataclass(frozen=True, slots=True)
class _SymlinkResolution:
    terminal: InventoryEntry | None
    symlink_paths: tuple[str, ...] = ()
    issue_path: str | None = None
    code: ReasonCode | None = None
    value: str = ""
    detector: str = ""


@dataclass(frozen=True, slots=True)
class _BoundaryOwnership:
    boundary: PackageBoundary
    components: _OwnedComponents


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


def _manifest_runtime_path(value: str, boundary: PackageBoundary) -> str | None:
    literal = value.strip().strip("`'\"<>")
    cleaned = literal if literal in {".", "./"} else _clean_reference(value)
    if not cleaned or _URL_SCHEME_RE.match(cleaned) is not None:
        return None
    candidate, escaped = _collapse_path(PurePosixPath(boundary.root), cleaned)
    if escaped or candidate is None:
        return None
    return candidate


def _resolve_inventory_path(
    path: str,
    by_path: Mapping[str, InventoryEntry],
    *,
    allowed_root: str | None = None,
) -> _SymlinkResolution:
    current_path = path
    visited: set[tuple[str, str]] = set()
    symlink_paths: list[str] = []
    last_target = path
    while True:
        parts = PurePosixPath(current_path).parts
        matched: InventoryEntry | None = None
        suffix: tuple[str, ...] = ()
        for index in range(1, len(parts) + 1):
            prefix = PurePosixPath(*parts[:index]).as_posix()
            entry = by_path.get(prefix)
            if entry is not None and entry.kind == "symlink":
                matched = entry
                suffix = parts[index:]
                break
        if matched is None:
            terminal = by_path.get(current_path)
            if terminal is not None:
                return _SymlinkResolution(
                    terminal=terminal,
                    symlink_paths=tuple(symlink_paths),
                )
            return _SymlinkResolution(
                terminal=None,
                symlink_paths=tuple(symlink_paths),
                issue_path=symlink_paths[0] if symlink_paths else None,
                code=ReasonCode.MISSING_LOCAL_RESOURCE,
                value=f"{last_target} -> {current_path}",
                detector="static.symlink.dangling",
            )

        state = (current_path, matched.path)
        if len(symlink_paths) >= _MAX_SYMLINK_CHAIN:
            return _SymlinkResolution(
                terminal=None,
                symlink_paths=tuple(symlink_paths),
                issue_path=symlink_paths[0] if symlink_paths else matched.path,
                code=ReasonCode.DYNAMIC_REFERENCE_UNRESOLVED,
                value=f"chain exceeds {_MAX_SYMLINK_CHAIN} links",
                detector="static.symlink.chain_limit",
            )
        if state in visited:
            return _SymlinkResolution(
                terminal=None,
                symlink_paths=tuple(symlink_paths),
                issue_path=symlink_paths[0] if symlink_paths else matched.path,
                code=ReasonCode.DYNAMIC_REFERENCE_UNRESOLVED,
                value=f"{matched.symlink_target} (cycle)",
                detector="static.symlink.cycle",
            )
        visited.add(state)
        symlink_paths.append(matched.path)
        target = matched.symlink_target or ""
        last_target = target
        if _is_unsafe_host_reference(target):
            return _SymlinkResolution(
                terminal=None,
                symlink_paths=tuple(symlink_paths),
                issue_path=symlink_paths[0],
                code=ReasonCode.SYMLINK_ESCAPE,
                value=target,
                detector="static.symlink.escape",
            )
        resolved, escaped = _collapse_path(PurePosixPath(matched.path).parent, target)
        if (
            escaped
            or resolved is None
            or (allowed_root is not None and not _is_within(resolved, allowed_root))
        ):
            return _SymlinkResolution(
                terminal=None,
                symlink_paths=tuple(symlink_paths),
                issue_path=symlink_paths[0],
                code=ReasonCode.SYMLINK_ESCAPE,
                value=f"{target} -> {resolved or '<outside snapshot>'}",
                detector="static.symlink.escape",
            )
        next_path, escaped = _collapse_path(
            PurePosixPath(resolved),
            PurePosixPath(*suffix).as_posix() if suffix else ".",
        )
        if (
            escaped
            or next_path is None
            or (allowed_root is not None and not _is_within(next_path, allowed_root))
        ):
            return _SymlinkResolution(
                terminal=None,
                symlink_paths=tuple(symlink_paths),
                issue_path=symlink_paths[0],
                code=ReasonCode.SYMLINK_ESCAPE,
                value=f"{target} -> {next_path or '<outside snapshot>'}",
                detector="static.symlink.escape",
            )
        current_path = next_path


def _resolve_inventory_symlink(
    entry: InventoryEntry,
    by_path: Mapping[str, InventoryEntry],
    *,
    allowed_root: str | None = None,
) -> _SymlinkResolution:
    return _resolve_inventory_path(
        entry.path,
        by_path,
        allowed_root=allowed_root,
    )


def _path_if_owned(
    value: str,
    boundary: PackageBoundary,
    by_path: Mapping[str, InventoryEntry],
) -> str | None:
    candidate = _manifest_runtime_path(value, boundary)
    if candidate is None:
        return None
    if candidate == boundary.root:
        return candidate
    resolution = _resolve_inventory_path(candidate, by_path)
    return resolution.terminal.path if resolution.terminal is not None else None


def _is_declared_runtime_root_key(
    key: str,
    *,
    depth: int,
    parent_key: str,
    manifest_path: str,
) -> bool:
    if key in _DECLARED_RUNTIME_ROOT_KEYS:
        return True
    if key not in _CONTEXTUAL_RUNTIME_ROOT_KEYS:
        return False
    return (depth == 0 and PurePosixPath(manifest_path).name.casefold() != "package.json") or (
        depth == 1 and parent_key in _PACKAGE_PLUGIN_WRAPPERS
    )


def _iter_declared_runtime_values(
    parsed: Mapping[str, object],
    manifest_path: str,
) -> Iterable[tuple[str, str]]:
    pending: list[tuple[object, int, str]] = [(parsed, 0, "")]
    visited = 0
    while pending:
        current, depth, parent_key = pending.pop()
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
                if _is_declared_runtime_root_key(
                    key,
                    depth=depth,
                    parent_key=parent_key,
                    manifest_path=manifest_path,
                ):
                    for string in _iter_strings(value):
                        yield raw_key, string
                    continue
                pending.append((value, depth + 1, key))
        elif isinstance(current, (list, tuple)):
            remaining = _MAX_MANIFEST_NODES - visited - len(pending)
            pending.extend((item, depth + 1, parent_key) for item in current[:remaining])


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
    by_path: Mapping[str, InventoryEntry],
    owned: _OwnedComponents,
    manifest_path: str,
) -> None:
    pending: list[tuple[object, int, str]] = [(parsed, 0, "")]
    visited = 0
    while pending:
        current, depth, parent_key = pending.pop()
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
                    recursive = _is_declared_runtime_root_key(
                        key,
                        depth=depth,
                        parent_key=parent_key,
                        manifest_path=manifest_path,
                    )
                    for string in _iter_strings(value):
                        lexical_path = _manifest_runtime_path(string, boundary)
                        if lexical_path is None:
                            continue
                        if lexical_path == boundary.root:
                            owned.manifest_runtime_paths.add(lexical_path)
                            owned.runtime_paths.add(lexical_path)
                            owned.explicit_runtime_paths.add(lexical_path)
                            if recursive:
                                owned.declared_runtime_roots.add(lexical_path)
                            continue
                        resolution = _resolve_inventory_path(lexical_path, by_path)
                        if resolution.terminal is not None or resolution.symlink_paths:
                            owned.manifest_runtime_paths.add(lexical_path)
                        owned.runtime_symlink_paths.update(resolution.symlink_paths)
                        if recursive:
                            owned.recursive_runtime_symlink_paths.update(resolution.symlink_paths)
                        lexical_entry = by_path.get(lexical_path)
                        if lexical_entry is not None:
                            owned.runtime_paths.add(lexical_path)
                            owned.explicit_runtime_paths.add(lexical_path)
                        if resolution.terminal is None:
                            continue
                        path = resolution.terminal.path
                        owned.runtime_paths.add(path)
                        owned.explicit_runtime_paths.add(path)
                        if recursive and resolution.terminal.kind == "directory":
                            owned.declared_runtime_roots.add(path)
                pending.append((value, depth + 1, key))
        elif isinstance(current, (list, tuple)):
            remaining = _MAX_MANIFEST_NODES - visited - len(pending)
            pending.extend((item, depth + 1, parent_key) for item in current[:remaining])


def _boundary_depth(boundary: PackageBoundary) -> int:
    return 0 if boundary.root == "." else len(PurePosixPath(boundary.root).parts)


def _inventory_symlink_paths(inventory: Inventory) -> tuple[str, ...]:
    return tuple(sorted(entry.path for entry in inventory.entries if entry.kind == "symlink"))


def _symlinks_at_or_below(symlink_paths: tuple[str, ...], root: str) -> tuple[str, ...]:
    if root == ".":
        return symlink_paths

    matches: tuple[str, ...] = ()
    exact_index = bisect_left(symlink_paths, root)
    if exact_index < len(symlink_paths) and symlink_paths[exact_index] == root:
        matches = (root,)

    prefix = f"{root}/"
    start = bisect_left(symlink_paths, prefix)
    end = bisect_left(symlink_paths, f"{root}0")
    return matches + symlink_paths[start:end]


def _expand_owned_runtime_symlinks(
    candidate: SkillCandidate,
    inventory: Inventory,
    by_path: Mapping[str, InventoryEntry],
    boundary: PackageBoundary,
    nested_roots: frozenset[str],
    skill_roots: frozenset[str],
    owned: _OwnedComponents,
) -> None:
    for entry in inventory.entries:
        if (
            entry.kind != "symlink"
            or not _is_within(entry.path, boundary.root)
            or _is_within(entry.path, candidate.root)
            or _is_within_any(entry.path, nested_roots)
            or _is_within_any(entry.path, skill_roots)
            or _is_documentation(entry.path, boundary)
            or not _is_known_runtime_component_path(entry.path, boundary)
        ):
            continue
        owned.runtime_paths.add(entry.path)
        owned.runtime_symlink_paths.add(entry.path)
        owned.recursive_runtime_symlink_paths.add(entry.path)

    symlink_paths: tuple[str, ...] | None = None
    pending_roots = sorted(owned.declared_runtime_roots)
    queued_roots = set(pending_roots)
    root_index = 0
    pending_links: list[tuple[str, bool]] = []
    queued_links: set[tuple[str, bool]] = set()
    link_index = 0

    def queue_link(path: str, recursive: bool) -> None:
        state = (path, recursive)
        if state not in queued_links:
            queued_links.add(state)
            pending_links.append(state)

    for path in sorted(owned.runtime_symlink_paths):
        queue_link(path, path in owned.recursive_runtime_symlink_paths)

    while root_index < len(pending_roots) or link_index < len(pending_links):
        while root_index < len(pending_roots):
            root = pending_roots[root_index]
            root_index += 1
            if symlink_paths is None:
                symlink_paths = _inventory_symlink_paths(inventory)
            for path in _symlinks_at_or_below(symlink_paths, root):
                owned.runtime_paths.add(path)
                owned.runtime_symlink_paths.add(path)
                owned.recursive_runtime_symlink_paths.add(path)
                queue_link(path, True)

        if link_index >= len(pending_links):
            continue
        path, recursive = pending_links[link_index]
        link_index += 1
        link_entry = by_path.get(path)
        if link_entry is None or link_entry.kind != "symlink":
            continue
        resolution = _resolve_inventory_symlink(link_entry, by_path)
        owned.runtime_symlink_paths.update(resolution.symlink_paths)
        owned.runtime_paths.update(resolution.symlink_paths)
        if recursive:
            owned.recursive_runtime_symlink_paths.update(resolution.symlink_paths)
        if resolution.terminal is None:
            continue
        target = resolution.terminal
        owned.runtime_paths.add(target.path)
        owned.explicit_runtime_paths.add(target.path)
        if target.kind == "directory" and recursive:
            owned.declared_runtime_roots.add(target.path)
            if target.path not in queued_roots:
                queued_roots.add(target.path)
                pending_roots.append(target.path)


def _enclosing_boundaries(
    candidate: SkillCandidate,
    boundaries: tuple[PackageBoundary, ...],
) -> tuple[PackageBoundary, ...]:
    by_root: dict[str, PackageBoundary] = {}
    for boundary in sorted(boundaries, key=lambda item: item.manifest_path):
        if _is_within(candidate.root, boundary.root):
            by_root.setdefault(boundary.root, boundary)
    return tuple(
        sorted(
            by_root.values(),
            key=lambda item: (-_boundary_depth(item), item.root, item.manifest_path),
        )
    )


def _derive_boundary_owned_components(
    candidate: SkillCandidate,
    inventory: Inventory,
    boundaries: tuple[PackageBoundary, ...],
    boundary: PackageBoundary,
) -> _OwnedComponents:
    owned = _OwnedComponents.empty()
    by_path = inventory.by_path
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
        entry = by_path.get(path)
        if entry is None:
            continue
        parsed = _manifest_json(entry)
        if parsed is not None:
            _collect_manifest_components(parsed, boundary, by_path, owned, path)

    _expand_owned_runtime_symlinks(
        candidate,
        inventory,
        by_path,
        boundary,
        nested_roots,
        skill_roots,
        owned,
    )

    declared_runtime_roots = frozenset(owned.declared_runtime_roots)
    for entry in inventory.entries:
        if (
            (
                not _is_within(entry.path, boundary.root)
                and entry.path not in owned.explicit_runtime_paths
                and not _is_within_any(entry.path, declared_runtime_roots)
            )
            or _is_within(entry.path, candidate.root)
            or (
                _is_within_any(entry.path, nested_roots)
                and entry.path not in owned.explicit_runtime_paths
                and not _is_within_any(entry.path, declared_runtime_roots)
            )
            or (
                _is_within_any(entry.path, skill_roots)
                and entry.path not in owned.explicit_runtime_paths
                and not _is_within_any(entry.path, declared_runtime_roots)
            )
            or (
                _is_documentation(entry.path, boundary)
                and entry.path not in owned.explicit_runtime_paths
                and not _is_within_any(entry.path, declared_runtime_roots)
            )
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
            or entry.path in owned.explicit_runtime_paths
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


def _derive_boundary_ownerships(
    candidate: SkillCandidate,
    inventory: Inventory,
    boundaries: tuple[PackageBoundary, ...],
) -> tuple[_BoundaryOwnership, ...]:
    return tuple(
        _BoundaryOwnership(
            boundary=boundary,
            components=_derive_boundary_owned_components(
                candidate,
                inventory,
                boundaries,
                boundary,
            ),
        )
        for boundary in _enclosing_boundaries(candidate, boundaries)
    )


def _aggregate_owned_components(
    ownerships: tuple[_BoundaryOwnership, ...],
) -> _OwnedComponents:
    aggregate = _OwnedComponents.empty()
    for ownership in ownerships:
        aggregate.mcp.update(ownership.components.mcp)
        aggregate.commands.update(ownership.components.commands)
        aggregate.agents.update(ownership.components.agents)
        aggregate.hooks.update(ownership.components.hooks)
        aggregate.providers.update(ownership.components.providers)
        aggregate.binaries.update(ownership.components.binaries)
        aggregate.runtime_paths.update(ownership.components.runtime_paths)
        aggregate.explicit_runtime_paths.update(ownership.components.explicit_runtime_paths)
        aggregate.manifest_runtime_paths.update(ownership.components.manifest_runtime_paths)
        aggregate.runtime_symlink_paths.update(ownership.components.runtime_symlink_paths)
        aggregate.recursive_runtime_symlink_paths.update(
            ownership.components.recursive_runtime_symlink_paths
        )
        aggregate.declared_runtime_roots.update(ownership.components.declared_runtime_roots)
        aggregate.runtime_modules.update(ownership.components.runtime_modules)
    return aggregate


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


def _plugin_install_match_proves_independence(content: str, match: re.Match[str]) -> bool:
    window_start = max(0, match.start() - _PLUGIN_NEGATION_CONTEXT_CHARS)
    prefix = content[window_start : match.start()]
    sentence_start = max((prefix.rfind(delimiter) for delimiter in "\n.!?;"), default=-1)
    if window_start > 0 and sentence_start < 0:
        return False

    window_end = min(len(content), match.end() + _PLUGIN_NEGATION_CONTEXT_CHARS)
    suffix = content[match.end() : window_end]
    sentence_end_candidates = [
        position for delimiter in "\n.!?;" if (position := suffix.find(delimiter)) >= 0
    ]
    if window_end < len(content) and not sentence_end_candidates:
        return False
    sentence_end = min(sentence_end_candidates) + 1 if sentence_end_candidates else len(suffix)
    sentence = f"{prefix[sentence_start + 1 :]}{match.group(0)}{suffix[:sentence_end]}"
    return _PROVEN_PLUGIN_INDEPENDENCE_RE.fullmatch(sentence) is not None


def _is_owned_runtime_path(
    path: str,
    ownerships: tuple[_BoundaryOwnership, ...],
) -> bool:
    return any(
        _is_within(path, ownership.boundary.root) and path in ownership.components.runtime_paths
        for ownership in ownerships
    )


def _analyze_forward_paths(
    candidate: SkillCandidate,
    inventory: Inventory,
    ownerships: tuple[_BoundaryOwnership, ...],
    collector: _ReasonCollector,
) -> None:
    by_path = inventory.by_path
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
            if _plugin_install_match_proves_independence(content, match):
                continue
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
                    if _is_owned_runtime_path(resolved, ownerships) and collector.has_capacity(
                        ReasonCode.PLUGIN_RUNTIME_FILE_REFERENCE
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

            boundary_targets: list[tuple[str, _BoundaryOwnership]] = []
            if not raw.startswith((".", "..")):
                for ownership in ownerships:
                    boundary = ownership.boundary
                    candidate_at_boundary = (
                        raw if boundary.root == "." else f"{boundary.root}/{raw}"
                    )
                    if candidate_at_boundary in by_path:
                        boundary_targets.append((candidate_at_boundary, ownership))
            if boundary_targets:
                for boundary_target, ownership in boundary_targets:
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
                        boundary_target in ownership.components.runtime_paths
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
        resolution = _resolve_inventory_symlink(
            entry,
            by_path,
            allowed_root=candidate.root,
        )
        if resolution.code is None or not collector.has_capacity(resolution.code):
            continue
        collector.add(
            resolution.code,
            Evidence(
                path=entry.path,
                line=None,
                field="symlinkTarget",
                value=resolution.value,
                detector=resolution.detector,
            ),
        )


def _analyze_owned_runtime_symlinks(
    candidate: SkillCandidate,
    ownerships: tuple[_BoundaryOwnership, ...],
    inventory: Inventory,
    collector: _ReasonCollector,
) -> None:
    by_path = inventory.by_path
    for ownership in ownerships:
        paths = (
            ownership.components.manifest_runtime_paths | ownership.components.runtime_symlink_paths
        )
        for path in sorted(paths):
            if path == ownership.boundary.root:
                continue
            resolution = _resolve_inventory_path(path, by_path)
            if (
                resolution.code is not None
                and resolution.issue_path is not None
                and collector.has_capacity(resolution.code)
            ):
                collector.add(
                    resolution.code,
                    Evidence(
                        path=resolution.issue_path,
                        line=None,
                        field="symlinkTarget",
                        value=resolution.value,
                        detector=resolution.detector,
                    ),
                )
            terminal = resolution.terminal
            if terminal is None:
                continue
            terminal_overlaps_candidate = _is_within(terminal.path, candidate.root) or (
                terminal.kind == "directory" and _is_within(candidate.root, terminal.path)
            )
            if (
                not resolution.symlink_paths
                or not terminal_overlaps_candidate
                or not collector.has_capacity(ReasonCode.REFERENCED_BY_PLUGIN_RUNTIME)
            ):
                continue
            collector.add(
                ReasonCode.REFERENCED_BY_PLUGIN_RUNTIME,
                Evidence(
                    path=resolution.symlink_paths[0],
                    line=None,
                    field="symlinkTarget",
                    value=f"{path} -> {terminal.path}",
                    detector="static.reverse.runtime_path_contains_skill",
                ),
            )


def _analyze_unresolved_boundary_manifests(
    candidate: SkillCandidate,
    inventory: Inventory,
    boundaries: tuple[PackageBoundary, ...],
    collector: _ReasonCollector,
) -> None:
    by_path = inventory.by_path
    seen: set[str] = set()
    for boundary in sorted(boundaries, key=lambda item: item.manifest_path):
        path = boundary.manifest_path
        if path in seen or not _is_within(candidate.root, boundary.root):
            continue
        seen.add(path)
        entry = by_path.get(path)
        if entry is not None and entry.kind == "file" and _manifest_json(entry) is not None:
            continue

        value = "missing manifest entry"
        line: int | None = None
        if entry is not None:
            value = f"{entry.kind} plugin manifest"
            line = 1 if entry.kind == "file" else None
            if entry.kind == "file":
                value = "unparseable plugin manifest mapping"
            elif entry.kind == "symlink":
                resolution = _resolve_inventory_symlink(entry, by_path)
                terminal = resolution.terminal
                value = (
                    f"symlink plugin manifest -> {terminal.path}"
                    if terminal is not None
                    else "unresolved symlink plugin manifest"
                )
                if resolution.code is not None and collector.has_capacity(resolution.code):
                    collector.add(
                        resolution.code,
                        Evidence(
                            path=resolution.issue_path or path,
                            line=None,
                            field="symlinkTarget",
                            value=resolution.value,
                            detector=resolution.detector,
                        ),
                    )
        if collector.has_capacity(ReasonCode.DYNAMIC_REFERENCE_UNRESOLVED):
            collector.add(
                ReasonCode.DYNAMIC_REFERENCE_UNRESOLVED,
                Evidence(
                    path=path,
                    line=line,
                    field="manifest",
                    value=value,
                    detector="static.boundary.unresolved_manifest",
                ),
            )


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


def _analyze_boundary_reverse_dependencies(
    candidate: SkillCandidate,
    validation: ValidationResult,
    inventory: Inventory,
    boundaries: tuple[PackageBoundary, ...],
    boundary: PackageBoundary,
    owned: _OwnedComponents,
    collector: _ReasonCollector,
) -> None:
    if validation.name is None:
        return
    by_path = inventory.by_path
    manifest_paths = {item.manifest_path for item in boundaries if item.root == boundary.root} | {
        boundary.manifest_path
    }
    nested_roots = frozenset(
        item.root
        for item in boundaries
        if item.root != boundary.root and _is_within(item.root, boundary.root)
    )
    declared_runtime_roots = frozenset(owned.declared_runtime_roots)
    skill_roots = _excluded_skill_roots(candidate, inventory)
    for entry in inventory.entries:
        if (
            entry.kind != "file"
            or entry.content is None
            or (
                not _is_within(entry.path, boundary.root)
                and entry.path not in owned.explicit_runtime_paths
                and not _is_within_any(entry.path, declared_runtime_roots)
            )
            or _is_within(entry.path, candidate.root)
            or (
                _is_within_any(entry.path, nested_roots)
                and entry.path not in owned.explicit_runtime_paths
                and not _is_within_any(entry.path, declared_runtime_roots)
            )
            or (
                _is_within_any(entry.path, skill_roots)
                and entry.path not in owned.explicit_runtime_paths
                and not _is_within_any(entry.path, declared_runtime_roots)
            )
            or (
                _is_documentation(entry.path, boundary)
                and entry.path not in owned.explicit_runtime_paths
                and not _is_within_any(entry.path, declared_runtime_roots)
            )
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
        declared_root_contains_candidate = False
        if entry.path in manifest_paths and parsed is not None:
            for field, raw_value in _iter_declared_runtime_values(parsed, entry.path):
                declared_root = _path_if_owned(raw_value, boundary, by_path)
                if declared_root is None or not _is_within(candidate.root, declared_root):
                    continue
                if collector.has_capacity(ReasonCode.REFERENCED_BY_PLUGIN_RUNTIME):
                    collector.add(
                        ReasonCode.REFERENCED_BY_PLUGIN_RUNTIME,
                        _text_evidence(
                            entry.path,
                            content,
                            max(content.find(raw_value), 0),
                            raw_value,
                            "static.reverse.runtime_root_contains_skill",
                            field=field,
                        ),
                    )
                declared_root_contains_candidate = True
                break
        if declared_root_contains_candidate:
            continue
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


def _analyze_reverse_dependencies(
    candidate: SkillCandidate,
    validation: ValidationResult,
    inventory: Inventory,
    boundaries: tuple[PackageBoundary, ...],
    ownerships: tuple[_BoundaryOwnership, ...],
    collector: _ReasonCollector,
) -> None:
    for ownership in ownerships:
        _analyze_boundary_reverse_dependencies(
            candidate,
            validation,
            inventory,
            boundaries,
            ownership.boundary,
            ownership.components,
            collector,
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

    _analyze_unresolved_boundary_manifests(candidate, inventory, boundaries, collector)
    ownerships = _derive_boundary_ownerships(candidate, inventory, boundaries)
    owned = _aggregate_owned_components(ownerships)
    _analyze_symlinks(candidate, inventory, collector)
    _analyze_forward_paths(candidate, inventory, ownerships, collector)
    _add_plugin_symbol_references(candidate, validation, inventory, owned, collector)
    _analyze_reverse_dependencies(
        candidate,
        validation,
        inventory,
        boundaries,
        ownerships,
        collector,
    )
    _analyze_owned_runtime_symlinks(candidate, ownerships, inventory, collector)

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
        review_paths=tuple(sorted(owned.runtime_paths)),
    )
