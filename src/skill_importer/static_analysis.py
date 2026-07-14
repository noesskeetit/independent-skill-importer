"""Conservative, evidence-first static portability analysis."""

from __future__ import annotations

import ast
import io
import json
import posixpath
import re
import shlex
import tokenize
import warnings
from bisect import bisect_left, bisect_right
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from dataclasses import field as dataclass_field
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
_MAX_STATIC_PROPAGATION_DEPTH = 32
_MAX_STATIC_BINDINGS = 4096
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
_MARKDOWN_INLINE_CODE_RE = re.compile(r"(?<!`)`(?P<body>[^`\r\n]+)`(?!`)")
_MARKDOWN_INLINE_DESTINATION_BEFORE_RE = re.compile(
    r"(?:\b(?:destination|output\s+path|write\s+target|source\.path|"
    r"marketplace\s+config)\s*(?:is|=|:|as)"
    r"|\b(?:write|save|export)\s+(?:the\s+)?(?:result|output|report)\s+to)\s*$",
    re.IGNORECASE,
)
_MARKDOWN_INLINE_DESTINATION_AFTER_RE = re.compile(
    r"^\s+as\s+(?:(?:their|the|a|an)\s+)?"
    r"(?:destination|output\s+path|write\s+target)\b",
    re.IGNORECASE,
)
_MARKDOWN_INLINE_OPTIONAL_WORKSPACE_RE = re.compile(
    r"\bif\s+the\s+current\s+git\s+repo\s+already\s+has\b",
    re.IGNORECASE,
)
_MARKDOWN_HEADING_RE = re.compile(
    r"^ {0,3}(?P<marker>#{1,6})(?:[ \t]+|$)(?P<title>.*?)(?:[ \t]+#+[ \t]*)?$"
)
_MARKDOWN_REFERENCE_DEFINITION_RE = re.compile(
    r"^ {0,3}\[(?P<label>[^\]]+)\]:[ \t]*(?:<(?P<angle>[^>]+)>|(?P<plain>\S+))"
)
_MARKDOWN_REFERENCE_LABEL_RE = re.compile(r"^ {0,3}\[(?P<label>[^\]]+)\]:[ \t]*$")
_MARKDOWN_REFERENCE_DESTINATION_RE = re.compile(r"^[ \t]{1,3}(?:<(?P<angle>[^>]+)>|(?P<plain>\S+))")
_MARKDOWN_REFERENCE_USAGE_RE = re.compile(r"!?\[(?P<text>[^\]]+)\]\[(?P<label>[^\]]*)\]")
_MARKDOWN_SHORTCUT_REFERENCE_RE = re.compile(r"(?<![!\]])!?\[(?P<label>[^\]]+)\](?![\[(])")
_DEVELOPMENT_HEADING_TITLES = frozenset(
    {"dev", "develop", "development", "test", "testing", "tests", "validate", "validation"}
)
_YAML_FIELD_RE = re.compile(
    r"^(?P<indent> *)(?P<key>[A-Za-z_][A-Za-z0-9_-]*)\s*:\s*(?P<value>.*)$",
)
_PYTHON_PATH_CALLS = frozenset(
    {
        "open",
        "load",
        "read_file",
        "readfile",
        "readfilesync",
        "write_file",
        "writefile",
        "writefilesync",
    }
)
_PYTHON_PATH_TYPES = frozenset({"path", "purepath"})
_PYTHON_WRITE_METHODS = frozenset(
    {"chmod", "mkdir", "rename", "replace", "rmdir", "touch", "unlink", "write_bytes", "write_text"}
)
_PYTHON_READ_METHODS = frozenset({"open", "read_bytes", "read_text"})
_PYTHON_SUBPROCESS_CALLS = frozenset({"call", "check_call", "check_output", "popen", "run"})
_JAVASCRIPT_PATH_CALLS = {
    "import": "import",
    "require": "import",
    "load": "read",
    "open": "read",
    "readfile": "read",
    "readfilesync": "read",
    "writefile": "write",
    "writefilesync": "write",
}
_SHELL_PATH_COMMANDS = frozenset(
    {
        ".",
        "cat",
        "cd",
        "chmod",
        "chown",
        "cp",
        "head",
        "less",
        "ls",
        "mv",
        "rm",
        "source",
        "stat",
        "tail",
    }
)
_SCRIPT_INTERPRETERS = frozenset({"bash", "bun", "deno", "node", "python", "python3", "sh"})
_JAVASCRIPT_SUFFIXES = frozenset({".cjs", ".cts", ".js", ".jsx", ".mjs", ".mts", ".ts", ".tsx"})
_SHELL_SUFFIXES = frozenset({".bash", ".sh", ".zsh"})
_STRUCTURED_PATH_FIELDS = frozenset({"extends", "files", "include"})
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
        "extension",
        "extensions",
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
        "extension",
        "extensions",
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


@dataclass(frozen=True, slots=True)
class _PathReference:
    value: str
    offset: int
    access: str
    syntax: str


@dataclass(frozen=True, slots=True)
class _StaticPathValue:
    value: str
    anchored_to_repository: bool = False
    propagated: bool = False


@dataclass(frozen=True, slots=True)
class _PathTaint:
    repository: bool = False
    plugin_value: str | None = None
    plugin_offset: int | None = None


@dataclass(frozen=True, slots=True)
class _MarkdownFence:
    language: str
    body_start: int
    body_end: int
    start: int
    end: int


@dataclass(slots=True)
class _JavaScriptToken:
    kind: str
    value: str
    start: int
    end: int


@dataclass(slots=True)
class _JavaScriptContext:
    kind: str
    brace_depth: int = 0
    previous: _JavaScriptToken | None = None
    parens: list[bool] = dataclass_field(default_factory=list)
    template_token_index: int | None = None
    template_dynamic: bool = False


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


def _node_offset(content: str, node: ast.AST, line_starts: tuple[int, ...]) -> int:
    line_index = max(getattr(node, "lineno", 1) - 1, 0)
    if line_index >= len(line_starts):
        return 0
    line_start = line_starts[line_index]
    line_end = content.find("\n", line_start)
    if line_end < 0:
        line_end = len(content)
    line = content[line_start:line_end]
    byte_column = max(getattr(node, "col_offset", 0), 0)
    character_column = len(line.encode("utf-8")[:byte_column].decode("utf-8", "ignore"))
    return line_start + character_column


def _python_call_name(node: ast.expr) -> str | None:
    if isinstance(node, ast.Name):
        return node.id.casefold()
    if isinstance(node, ast.Attribute):
        return node.attr.casefold()
    return None


def _python_argument_value(content: str, node: ast.expr) -> tuple[str, bool]:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value, False
    if isinstance(node, ast.JoinedStr):
        parts: list[str] = []
        for part in node.values:
            if isinstance(part, ast.Constant) and isinstance(part.value, str):
                parts.append(part.value)
            elif isinstance(part, ast.FormattedValue):
                expression = ast.get_source_segment(content, part.value) or "expression"
                parts.append(f"{{{expression}}}")
        return "".join(parts), True
    return ast.get_source_segment(content, node) or type(node).__name__, True


def _python_call_argument(call: ast.Call) -> ast.expr | None:
    if call.args:
        return call.args[0]
    for keyword in call.keywords:
        if keyword.arg in {"file", "filename", "name", "path"}:
            return keyword.value
    return None


def _python_open_access(call: ast.Call) -> str:
    mode_node: ast.expr | None = call.args[1] if len(call.args) > 1 else None
    for keyword in call.keywords:
        if keyword.arg == "mode":
            mode_node = keyword.value
            break
    if (
        isinstance(mode_node, ast.Constant)
        and isinstance(mode_node.value, str)
        and any(flag in mode_node.value for flag in "wax+")
    ):
        return "write"
    return "read"


def _python_symbols(
    tree: ast.AST,
) -> tuple[set[str], set[str], set[str], set[str]]:
    path_names = set(_PYTHON_PATH_TYPES)
    pathlib_modules = {"pathlib"}
    subprocess_modules = {"subprocess"}
    subprocess_names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == "pathlib":
                    pathlib_modules.add((alias.asname or alias.name).casefold())
                elif alias.name == "subprocess":
                    subprocess_modules.add((alias.asname or alias.name).casefold())
        elif isinstance(node, ast.ImportFrom) and node.module == "pathlib":
            path_names.update(
                (alias.asname or alias.name).casefold()
                for alias in node.names
                if alias.name.casefold() in _PYTHON_PATH_TYPES
            )
        elif isinstance(node, ast.ImportFrom) and node.module == "subprocess":
            subprocess_names.update(
                (alias.asname or alias.name).casefold()
                for alias in node.names
                if alias.name.casefold() in _PYTHON_SUBPROCESS_CALLS
            )
    return path_names, pathlib_modules, subprocess_modules, subprocess_names


def _python_is_path_constructor(
    call: ast.Call,
    path_names: set[str],
    pathlib_modules: set[str],
) -> bool:
    if isinstance(call.func, ast.Name):
        return call.func.id.casefold() in path_names
    return (
        isinstance(call.func, ast.Attribute)
        and call.func.attr.casefold() in _PYTHON_PATH_TYPES
        and isinstance(call.func.value, ast.Name)
        and call.func.value.id.casefold() in pathlib_modules
    )


def _python_path_receiver_access(
    call: ast.Call,
    parents: Mapping[int, ast.AST],
) -> str:
    attribute = parents.get(id(call))
    parent_call = parents.get(id(attribute)) if attribute is not None else None
    if not (
        isinstance(attribute, ast.Attribute)
        and attribute.value is call
        and isinstance(parent_call, ast.Call)
        and parent_call.func is attribute
    ):
        return "read"
    method = attribute.attr.casefold()
    if method in _PYTHON_WRITE_METHODS:
        return "write"
    if method == "open":
        mode = parent_call.args[0] if parent_call.args else None
        for keyword in parent_call.keywords:
            if keyword.arg == "mode":
                mode = keyword.value
                break
        if (
            isinstance(mode, ast.Constant)
            and isinstance(mode.value, str)
            and any(flag in mode.value for flag in "wax+")
        ):
            return "write"
    return "read"


def _python_indirect_path_accesses(
    tree: ast.AST,
    parents: Mapping[int, ast.AST],
    path_names: set[str],
    pathlib_modules: set[str],
) -> dict[int, str]:
    bindings: dict[str, ast.Call] = {}
    ambiguous: set[str] = set()
    assignment_targets: set[int] = set()
    names_by_identifier: dict[str, list[ast.Name]] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Name):
            names_by_identifier.setdefault(node.id, []).append(node)
        target: ast.expr | None = None
        value: ast.expr | None = None
        if isinstance(node, ast.Assign) and len(node.targets) == 1:
            target, value = node.targets[0], node.value
        elif isinstance(node, ast.AnnAssign):
            target, value = node.target, node.value
        if not (
            isinstance(target, ast.Name)
            and isinstance(value, ast.Call)
            and _python_is_path_constructor(value, path_names, pathlib_modules)
        ):
            continue
        name = target.id
        assignment_targets.add(id(target))
        if name in bindings:
            ambiguous.add(name)
        else:
            bindings[name] = value

    accesses: dict[int, str] = {}
    for name, constructor in bindings.items():
        access = "write"
        saw_use = False
        if name in ambiguous:
            accesses[id(constructor)] = "read"
            continue
        for node in names_by_identifier.get(name, ()):
            if id(node) in assignment_targets:
                continue
            if not isinstance(node.ctx, ast.Load):
                access = "read"
                break
            saw_use = True
            attribute = parents.get(id(node))
            parent_call = parents.get(id(attribute)) if attribute is not None else None
            if not (
                isinstance(attribute, ast.Attribute)
                and attribute.value is node
                and isinstance(parent_call, ast.Call)
                and parent_call.func is attribute
            ):
                access = "read"
                break
            method = attribute.attr.casefold()
            if method in _PYTHON_WRITE_METHODS:
                continue
            if method == "open" and _python_open_access(parent_call) == "write":
                continue
            access = "read"
            break
        accesses[id(constructor)] = access if saw_use else "read"
    return accesses


def _python_is_subprocess_call(
    call: ast.Call,
    subprocess_modules: set[str],
    subprocess_names: set[str],
) -> bool:
    if isinstance(call.func, ast.Name):
        return call.func.id.casefold() in subprocess_names
    return (
        isinstance(call.func, ast.Attribute)
        and call.func.attr.casefold() in _PYTHON_SUBPROCESS_CALLS
        and isinstance(call.func.value, ast.Name)
        and call.func.value.id.casefold() in subprocess_modules
    )


def _python_subprocess_arguments(call: ast.Call) -> tuple[ast.expr, ...]:
    argument = _python_call_argument(call)
    if isinstance(argument, (ast.List, ast.Tuple)):
        elements = tuple(argument.elts)
        if not elements:
            return ()
        executable = elements[0]
        if not (
            isinstance(executable, ast.Constant)
            and isinstance(executable.value, str)
            and PurePosixPath(executable.value).name.casefold() in _SCRIPT_INTERPRETERS
        ):
            return (executable,)
        interpreter = PurePosixPath(executable.value).name.casefold()
        index = 1
        subcommand = elements[index] if index < len(elements) else None
        if (
            interpreter in {"bun", "deno"}
            and isinstance(subcommand, ast.Constant)
            and isinstance(subcommand.value, str)
            and subcommand.value.casefold() == "run"
        ):
            index += 1
        while index < len(elements):
            current = elements[index]
            if not (isinstance(current, ast.Constant) and isinstance(current.value, str)):
                return ()
            if current.value == "--":
                index += 1
                break
            if current.value.startswith("-"):
                if current.value in {"-c", "-e", "-m", "-p", "--eval", "--print"}:
                    return ()
                index += 1
                continue
            if _looks_shell_path(current.value):
                return (current,)
            index += 1
        return ()
    return (argument,) if argument is not None else ()


def _static_path_join(values: Sequence[_StaticPathValue]) -> _StaticPathValue | None:
    if not values:
        return None
    first, *remaining = values
    if any(value.anchored_to_repository for value in remaining):
        return None
    joined = first.value
    for value in remaining:
        joined = posixpath.join(joined, value.value)
    return _StaticPathValue(
        joined,
        anchored_to_repository=first.anchored_to_repository,
        propagated=True,
    )


def _static_reference_value(value: _StaticPathValue, entry_path: str) -> str:
    if not value.anchored_to_repository:
        return value.value
    source_parent = str(PurePosixPath(entry_path).parent)
    return posixpath.relpath(posixpath.normpath(value.value), start=source_parent)


def _python_static_bindings(
    tree: ast.AST,
) -> tuple[dict[str, ast.expr], dict[str, tuple[ast.expr, ...]], bool]:
    bindings: dict[str, ast.expr] = {}
    values_by_name: dict[str, list[ast.expr]] = {}
    overflow = False
    stored_assignments = 0
    assignments = sorted(
        ast.walk(tree),
        key=lambda node: (
            getattr(node, "lineno", 0),
            getattr(node, "col_offset", 0),
            getattr(node, "end_lineno", 0),
        ),
    )
    for node in assignments:
        target: ast.expr | None = None
        value: ast.expr | None = None
        if isinstance(node, ast.Assign) and len(node.targets) == 1:
            target, value = node.targets[0], node.value
        elif isinstance(node, ast.AnnAssign):
            target, value = node.target, node.value
        if not isinstance(target, ast.Name) or value is None:
            continue
        name = target.id
        if stored_assignments >= _MAX_STATIC_BINDINGS:
            overflow = True
            continue
        bindings[name] = value
        values_by_name.setdefault(name, []).append(value)
        stored_assignments += 1
    return (
        bindings,
        {name: tuple(values) for name, values in values_by_name.items()},
        overflow,
    )


def _merge_path_taints(taints: Iterable[_PathTaint]) -> _PathTaint:
    repository = False
    plugin_value: str | None = None
    plugin_offset: int | None = None
    for taint in taints:
        repository = repository or taint.repository
        if taint.plugin_offset is not None and (
            plugin_offset is None or taint.plugin_offset < plugin_offset
        ):
            plugin_value = taint.plugin_value
            plugin_offset = taint.plugin_offset
    return _PathTaint(
        repository=repository,
        plugin_value=plugin_value,
        plugin_offset=plugin_offset,
    )


def _python_path_taint(
    node: ast.expr,
    *,
    content: str,
    line_starts: tuple[int, ...],
    bindings: Mapping[str, tuple[ast.expr, ...]],
    memo: dict[str, _PathTaint],
    resolving: set[str],
    depth: int = 0,
) -> _PathTaint:
    if depth >= _MAX_STATIC_PROPAGATION_DEPTH:
        return _PathTaint()

    source = ast.get_source_segment(content, node) or ""
    plugin_match = _PLUGIN_VARIABLE_RE.search(source)
    direct = _PathTaint(
        repository=isinstance(node, ast.Name) and node.id == "__file__",
        plugin_value=plugin_match.group(0) if plugin_match is not None else None,
        plugin_offset=(
            _node_offset(content, node, line_starts) + plugin_match.start()
            if plugin_match is not None
            else None
        ),
    )

    if isinstance(node, ast.Name):
        if node.id in memo:
            return _merge_path_taints((direct, memo[node.id]))
        if node.id in resolving:
            return direct
        values = bindings.get(node.id, ())
        if not values:
            return direct
        resolving.add(node.id)
        propagated = _merge_path_taints(
            _python_path_taint(
                value,
                content=content,
                line_starts=line_starts,
                bindings=bindings,
                memo=memo,
                resolving=resolving,
                depth=depth + 1,
            )
            for value in values
        )
        resolving.remove(node.id)
        memo[node.id] = propagated
        return _merge_path_taints((direct, propagated))

    children = tuple(child for child in ast.iter_child_nodes(node) if isinstance(child, ast.expr))
    if not children:
        return direct
    return _merge_path_taints(
        (
            direct,
            *(
                _python_path_taint(
                    child,
                    content=content,
                    line_starts=line_starts,
                    bindings=bindings,
                    memo=memo,
                    resolving=resolving,
                    depth=depth + 1,
                )
                for child in children
            ),
        )
    )


def _python_static_path_value(
    node: ast.expr,
    *,
    entry_path: str,
    bindings: Mapping[str, ast.expr],
    path_names: set[str],
    pathlib_modules: set[str],
    memo: dict[str, _StaticPathValue | None],
    resolving: set[str],
    depth: int = 0,
) -> _StaticPathValue | None:
    if depth >= _MAX_STATIC_PROPAGATION_DEPTH:
        return None
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return _StaticPathValue(node.value)
    if isinstance(node, ast.Name):
        name = node.id
        if name == "__file__":
            return _StaticPathValue(entry_path, anchored_to_repository=True, propagated=True)
        if name in memo:
            return memo[name]
        binding = bindings.get(name)
        if binding is None or name in resolving:
            return None
        resolving.add(name)
        resolved = _python_static_path_value(
            binding,
            entry_path=entry_path,
            bindings=bindings,
            path_names=path_names,
            pathlib_modules=pathlib_modules,
            memo=memo,
            resolving=resolving,
            depth=depth + 1,
        )
        resolving.remove(name)
        if resolved is not None:
            resolved = _StaticPathValue(
                resolved.value,
                anchored_to_repository=resolved.anchored_to_repository,
                propagated=True,
            )
        memo[name] = resolved
        return resolved
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div):
        left = _python_static_path_value(
            node.left,
            entry_path=entry_path,
            bindings=bindings,
            path_names=path_names,
            pathlib_modules=pathlib_modules,
            memo=memo,
            resolving=resolving,
            depth=depth + 1,
        )
        right = _python_static_path_value(
            node.right,
            entry_path=entry_path,
            bindings=bindings,
            path_names=path_names,
            pathlib_modules=pathlib_modules,
            memo=memo,
            resolving=resolving,
            depth=depth + 1,
        )
        return _static_path_join((left, right)) if left is not None and right is not None else None
    if isinstance(node, ast.Attribute) and node.attr.casefold() == "parent":
        value = _python_static_path_value(
            node.value,
            entry_path=entry_path,
            bindings=bindings,
            path_names=path_names,
            pathlib_modules=pathlib_modules,
            memo=memo,
            resolving=resolving,
            depth=depth + 1,
        )
        if value is None:
            return None
        return _StaticPathValue(
            str(PurePosixPath(value.value).parent),
            anchored_to_repository=value.anchored_to_repository,
            propagated=True,
        )
    if (
        isinstance(node, ast.Subscript)
        and isinstance(node.value, ast.Attribute)
        and node.value.attr.casefold() == "parents"
        and isinstance(node.slice, ast.Constant)
        and isinstance(node.slice.value, int)
        and node.slice.value >= 0
    ):
        value = _python_static_path_value(
            node.value.value,
            entry_path=entry_path,
            bindings=bindings,
            path_names=path_names,
            pathlib_modules=pathlib_modules,
            memo=memo,
            resolving=resolving,
            depth=depth + 1,
        )
        if value is None:
            return None
        try:
            parent = PurePosixPath(value.value).parents[node.slice.value]
        except IndexError:
            return None
        return _StaticPathValue(
            str(parent),
            anchored_to_repository=value.anchored_to_repository,
            propagated=True,
        )
    if not isinstance(node, ast.Call):
        return None
    if _python_is_path_constructor(node, path_names, pathlib_modules):
        argument = _python_call_argument(node)
        if argument is None:
            return None
        return _python_static_path_value(
            argument,
            entry_path=entry_path,
            bindings=bindings,
            path_names=path_names,
            pathlib_modules=pathlib_modules,
            memo=memo,
            resolving=resolving,
            depth=depth + 1,
        )
    call_name = _python_call_name(node.func)
    if isinstance(node.func, ast.Attribute) and call_name in {"absolute", "resolve"}:
        value = _python_static_path_value(
            node.func.value,
            entry_path=entry_path,
            bindings=bindings,
            path_names=path_names,
            pathlib_modules=pathlib_modules,
            memo=memo,
            resolving=resolving,
            depth=depth + 1,
        )
        if value is None:
            return None
        return _StaticPathValue(
            value.value,
            anchored_to_repository=value.anchored_to_repository,
            propagated=True,
        )
    if isinstance(node.func, ast.Attribute) and call_name == "joinpath":
        receiver = _python_static_path_value(
            node.func.value,
            entry_path=entry_path,
            bindings=bindings,
            path_names=path_names,
            pathlib_modules=pathlib_modules,
            memo=memo,
            resolving=resolving,
            depth=depth + 1,
        )
        arguments = [
            _python_static_path_value(
                argument,
                entry_path=entry_path,
                bindings=bindings,
                path_names=path_names,
                pathlib_modules=pathlib_modules,
                memo=memo,
                resolving=resolving,
                depth=depth + 1,
            )
            for argument in node.args
        ]
        if receiver is None or any(argument is None for argument in arguments):
            return None
        return _static_path_join((receiver, *(argument for argument in arguments if argument)))
    if call_name in {"dirname", "expandvars"}:
        argument = _python_call_argument(node)
        if argument is None:
            return None
        value = _python_static_path_value(
            argument,
            entry_path=entry_path,
            bindings=bindings,
            path_names=path_names,
            pathlib_modules=pathlib_modules,
            memo=memo,
            resolving=resolving,
            depth=depth + 1,
        )
        if value is None:
            return None
        transformed = (
            str(PurePosixPath(value.value).parent) if call_name == "dirname" else value.value
        )
        return _StaticPathValue(
            transformed,
            anchored_to_repository=value.anchored_to_repository,
            propagated=True,
        )
    if call_name == "join":
        arguments = [
            _python_static_path_value(
                argument,
                entry_path=entry_path,
                bindings=bindings,
                path_names=path_names,
                pathlib_modules=pathlib_modules,
                memo=memo,
                resolving=resolving,
                depth=depth + 1,
            )
            for argument in node.args
        ]
        if not arguments or any(argument is None for argument in arguments):
            return None
        return _static_path_join(tuple(argument for argument in arguments if argument))
    return None


def _python_static_consumed_path_references(
    tree: ast.AST,
    content: str,
    *,
    entry_path: str,
    line_starts: tuple[int, ...],
    path_names: set[str],
    pathlib_modules: set[str],
    subprocess_modules: set[str],
    subprocess_names: set[str],
    base_offset: int,
) -> Iterable[_PathReference]:
    bindings, taint_bindings, binding_overflow = _python_static_bindings(tree)
    memo: dict[str, _StaticPathValue | None] = {}
    taint_memo: dict[str, _PathTaint] = {}
    emitted: set[tuple[str, int, str]] = set()

    def resolved(node: ast.expr) -> _StaticPathValue | None:
        return _python_static_path_value(
            node,
            entry_path=entry_path,
            bindings=bindings,
            path_names=path_names,
            pathlib_modules=pathlib_modules,
            memo=memo,
            resolving=set(),
        )

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        candidates: tuple[tuple[ast.expr, str], ...] = ()
        if _python_is_subprocess_call(node, subprocess_modules, subprocess_names):
            argument = _python_call_argument(node)
            if isinstance(argument, (ast.List, ast.Tuple)):
                candidates = tuple((element, "execute") for element in argument.elts)
            elif argument is not None:
                candidates = ((argument, "execute"),)
        else:
            name = _python_call_name(node.func)
            if name in _PYTHON_PATH_CALLS:
                argument = _python_call_argument(node)
                if argument is not None:
                    access = "write" if name.startswith("write") else "read"
                    if name == "open":
                        access = _python_open_access(node)
                    candidates = ((argument, access),)
            elif isinstance(node.func, ast.Attribute) and name in _PYTHON_READ_METHODS:
                access = _python_open_access(node) if name == "open" else "read"
                candidates = ((node.func.value, access),)

        for expression, access in candidates:
            if access == "write":
                continue
            taint = _python_path_taint(
                expression,
                content=content,
                line_starts=line_starts,
                bindings=taint_bindings,
                memo=taint_memo,
                resolving=set(),
            )
            if taint.plugin_value is not None and taint.plugin_offset is not None:
                identity = (taint.plugin_value, taint.plugin_offset, access)
                if identity not in emitted:
                    emitted.add(identity)
                    yield _PathReference(
                        taint.plugin_value,
                        base_offset + taint.plugin_offset,
                        access,
                        "python.plugin_tainted",
                    )
                continue
            value = resolved(expression)
            uncertain_repository_value = (
                value is not None
                and not value.anchored_to_repository
                and (taint.repository or (binding_overflow and value.propagated))
            )
            if value is None or uncertain_repository_value:
                if taint.repository or binding_overflow:
                    reference = (
                        ast.get_source_segment(content, expression) or type(expression).__name__
                    )
                    offset = base_offset + _node_offset(content, expression, line_starts)
                    syntax = (
                        "python.repo_tainted.expression"
                        if taint.repository
                        else "python.binding_overflow.expression"
                    )
                    identity = (reference, offset, access)
                    if identity not in emitted:
                        emitted.add(identity)
                        yield _PathReference(reference, offset, access, syntax)
                continue
            reference = _static_reference_value(value, entry_path)
            has_plugin_variable = _PLUGIN_VARIABLE_RE.search(reference) is not None
            if not value.propagated and not has_plugin_variable:
                continue
            offset = base_offset + _node_offset(content, expression, line_starts)
            identity = (reference, offset, access)
            if identity in emitted:
                continue
            emitted.add(identity)
            yield _PathReference(reference, offset, access, "python.static")


def _python_import_reference(
    node: ast.Import | ast.ImportFrom,
    entry_path: str,
    candidate_root: str,
    by_path: Mapping[str, InventoryEntry],
) -> str | None:
    relative = isinstance(node, ast.ImportFrom) and node.level > 0
    prefix = "../" * max(node.level - 1, 0) if isinstance(node, ast.ImportFrom) else ""
    modules: list[str] = []
    if isinstance(node, ast.Import):
        modules.extend(alias.name for alias in node.names)
    else:
        if node.module:
            modules.append(node.module)
        elif relative:
            modules.extend(alias.name for alias in node.names if alias.name != "*")

    candidates: list[str] = []
    for module in modules:
        module_path = module.replace(".", "/")
        candidates.extend((f"{prefix}{module_path}.py", f"{prefix}{module_path}/__init__.py"))
        if isinstance(node, ast.ImportFrom) and node.module:
            candidates.extend(
                f"{prefix}{module_path}/{alias.name}.py"
                for alias in node.names
                if alias.name != "*"
            )
    for candidate in candidates:
        resolved, escaped = _resolve_local_reference(
            entry_path,
            candidate_root,
            candidate,
            by_path,
        )
        if not escaped and resolved in by_path:
            return candidate
    return candidates[0] if relative and candidates else None


def _python_path_references(
    content: str,
    *,
    entry_path: str,
    candidate_root: str,
    by_path: Mapping[str, InventoryEntry],
    base_offset: int = 0,
    fail_closed: bool = True,
) -> Iterable[_PathReference]:
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", SyntaxWarning)
            tree = ast.parse(content)
    except (SyntaxError, ValueError, TypeError, MemoryError, RecursionError):
        if fail_closed:
            yield _PathReference(
                "unparseable Python source",
                base_offset,
                "unknown",
                "python.parse_failure",
            )
        return

    line_starts = tuple([0, *(match.end() for match in re.finditer("\n", content))])
    parents = {id(child): node for node in ast.walk(tree) for child in ast.iter_child_nodes(node)}
    path_names, pathlib_modules, subprocess_modules, subprocess_names = _python_symbols(tree)
    indirect_accesses = _python_indirect_path_accesses(
        tree,
        parents,
        path_names,
        pathlib_modules,
    )
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            access = "read"
            arguments: tuple[ast.expr | None, ...]
            if _python_is_path_constructor(node, path_names, pathlib_modules):
                arguments = (_python_call_argument(node),)
                access = indirect_accesses.get(
                    id(node),
                    _python_path_receiver_access(node, parents),
                )
            elif _python_is_subprocess_call(node, subprocess_modules, subprocess_names):
                arguments = _python_subprocess_arguments(node)
                access = "execute"
            else:
                name = _python_call_name(node.func)
                if name not in _PYTHON_PATH_CALLS:
                    continue
                receiver = node.func.value if isinstance(node.func, ast.Attribute) else None
                if isinstance(receiver, ast.Call) and _python_is_path_constructor(
                    receiver,
                    path_names,
                    pathlib_modules,
                ):
                    continue
                arguments = (_python_call_argument(node),)
                access = "write" if name.startswith("write") else "read"
                if name == "open":
                    access = _python_open_access(node)
            for argument in arguments:
                if argument is None:
                    continue
                value, dynamic = _python_argument_value(content, argument)
                syntax = "python.expression" if dynamic else "python.call"
                yield _PathReference(
                    value,
                    base_offset + _node_offset(content, argument, line_starts),
                    access,
                    syntax,
                )
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            import_value = _python_import_reference(node, entry_path, candidate_root, by_path)
            if import_value is not None:
                yield _PathReference(
                    import_value,
                    base_offset + _node_offset(content, node, line_starts),
                    "import",
                    "python.import",
                )
    yield from _python_static_consumed_path_references(
        tree,
        content,
        entry_path=entry_path,
        line_starts=line_starts,
        path_names=path_names,
        pathlib_modules=pathlib_modules,
        subprocess_modules=subprocess_modules,
        subprocess_names=subprocess_names,
        base_offset=base_offset,
    )


_JAVASCRIPT_REGEX_PREFIX_KEYWORDS = frozenset(
    {
        "case",
        "delete",
        "do",
        "else",
        "in",
        "instanceof",
        "new",
        "return",
        "throw",
        "typeof",
        "void",
        "yield",
    }
)
_JAVASCRIPT_CONTROL_KEYWORDS = frozenset({"catch", "for", "if", "switch", "while", "with"})
_JAVASCRIPT_REGEX_PREFIX_TOKENS = frozenset(
    {
        "!",
        "!=",
        "!==",
        "%",
        "%=",
        "&",
        "&&",
        "(",
        "*",
        "*=",
        "+",
        "+=",
        ",",
        "-",
        "-=",
        "/",
        "/=",
        ":",
        ";",
        "<",
        "<=",
        "=",
        "==",
        "===",
        "=>",
        ">",
        ">=",
        "?",
        "??",
        "[",
        "^",
        "|",
        "||",
        "{",
        "~",
    }
)


def _javascript_add_token(
    tokens: list[_JavaScriptToken],
    context: _JavaScriptContext,
    kind: str,
    value: str,
    start: int,
    end: int,
) -> _JavaScriptToken:
    token = _JavaScriptToken(kind, value, start, end)
    tokens.append(token)
    context.previous = token
    return token


def _javascript_regex_allowed(context: _JavaScriptContext) -> bool:
    previous = context.previous
    if previous is None or previous.kind == "control_close":
        return True
    if previous.kind == "identifier":
        return previous.value in _JAVASCRIPT_REGEX_PREFIX_KEYWORDS
    return previous.value in _JAVASCRIPT_REGEX_PREFIX_TOKENS


def _javascript_tokens(content: str) -> tuple[list[_JavaScriptToken], bool]:
    tokens: list[_JavaScriptToken] = []
    contexts = [_JavaScriptContext("code")]
    offset = 0
    while offset < len(content):
        context = contexts[-1]
        character = content[offset]

        if context.kind == "template":
            if character == "\\":
                offset += 2
                continue
            if character == "`":
                if context.template_token_index is None:
                    return tokens, True
                token = tokens[context.template_token_index]
                token.kind = "template_expression" if context.template_dynamic else "template"
                token.end = offset
                contexts.pop()
                contexts[-1].previous = token
                offset += 1
                continue
            if content.startswith("${", offset):
                if context.template_token_index is None:
                    return tokens, True
                if not context.template_dynamic:
                    token = tokens[context.template_token_index]
                    token.value = f"{content[token.start : min(offset, token.start + 512)]}${{...}}"
                    context.template_dynamic = True
                contexts.append(_JavaScriptContext("template_expression"))
                offset += 2
                continue
            offset += 1
            continue

        if context.kind == "template_expression" and character == "}":
            if context.brace_depth == 0:
                if context.parens:
                    return tokens, True
                contexts.pop()
                offset += 1
                continue
            context.brace_depth -= 1

        if character.isspace():
            offset += 1
            continue
        if content.startswith("//", offset):
            end = content.find("\n", offset + 2)
            offset = len(content) if end < 0 else end
            continue
        if content.startswith("/*", offset):
            end = content.find("*/", offset + 2)
            if end < 0:
                return tokens, True
            offset = end + 2
            continue
        if character in {'"', "'"}:
            quote = character
            start = offset + 1
            offset = start
            while offset < len(content):
                if content[offset] == "\\":
                    offset += 2
                    continue
                if content[offset] == quote:
                    _javascript_add_token(
                        tokens,
                        context,
                        "string",
                        content[start:offset],
                        start,
                        offset,
                    )
                    offset += 1
                    break
                if content[offset] in "\r\n":
                    return tokens, True
                offset += 1
            else:
                return tokens, True
            continue
        if character == "`":
            token = _javascript_add_token(tokens, context, "template", "", offset + 1, offset + 1)
            contexts.append(_JavaScriptContext("template", template_token_index=len(tokens) - 1))
            context.previous = token
            offset += 1
            continue
        if character == "/" and _javascript_regex_allowed(context):
            start = offset
            offset += 1
            in_character_class = False
            while offset < len(content):
                if content[offset] == "\\":
                    offset += 2
                    continue
                if content[offset] == "[":
                    in_character_class = True
                elif content[offset] == "]":
                    in_character_class = False
                elif content[offset] == "/" and not in_character_class:
                    offset += 1
                    while offset < len(content) and content[offset].isalpha():
                        offset += 1
                    _javascript_add_token(
                        tokens,
                        context,
                        "regex",
                        content[start:offset],
                        start,
                        offset,
                    )
                    break
                elif content[offset] in "\r\n":
                    return tokens, True
                offset += 1
            else:
                return tokens, True
            continue
        if character.isalpha() or character in "_$":
            start = offset
            offset += 1
            while offset < len(content) and (content[offset].isalnum() or content[offset] in "_$"):
                offset += 1
            _javascript_add_token(
                tokens,
                context,
                "identifier",
                content[start:offset],
                start,
                offset,
            )
            continue
        if character.isdigit():
            start = offset
            offset += 1
            while offset < len(content) and (content[offset].isalnum() or content[offset] in "._"):
                offset += 1
            _javascript_add_token(
                tokens,
                context,
                "number",
                content[start:offset],
                start,
                offset,
            )
            continue

        operator = next(
            (
                candidate
                for size in (3, 2)
                if (candidate := content[offset : offset + size])
                in {
                    "!=",
                    "!==",
                    "%=",
                    "&&",
                    "*=",
                    "+=",
                    "-=",
                    "/=",
                    "<=",
                    "==",
                    "===",
                    "=>",
                    ">=",
                    "??",
                    "||",
                }
            ),
            character,
        )
        kind = "punctuation"
        if operator == "(":
            control = (
                context.previous is not None
                and context.previous.kind == "identifier"
                and context.previous.value in _JAVASCRIPT_CONTROL_KEYWORDS
            )
            context.parens.append(control)
        elif operator == ")":
            control = context.parens.pop() if context.parens else False
            kind = "control_close" if control else kind
        elif operator == "{" and context.kind == "template_expression":
            context.brace_depth += 1
        _javascript_add_token(tokens, context, kind, operator, offset, offset + len(operator))
        offset += len(operator)

    if len(contexts) != 1 or contexts[0].parens:
        return tokens, True
    return tokens, False


def _javascript_static_imports(
    tokens: list[_JavaScriptToken],
) -> Iterable[_JavaScriptToken]:
    declaration_stops = {"class", "const", "default", "function", "let", "var"}
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if token.kind != "identifier" or token.value not in {"export", "import"}:
            index += 1
            continue
        cursor = index + 1
        if cursor >= len(tokens) or tokens[cursor].value in {"(", "."}:
            index += 1
            continue
        if token.value == "import" and tokens[cursor].kind == "string":
            yield tokens[cursor]
            index = cursor + 1
            continue
        if tokens[cursor].kind == "identifier" and tokens[cursor].value in declaration_stops:
            index += 1
            continue
        depth = 0
        while cursor < len(tokens):
            current = tokens[cursor]
            if current.value in {"(", "[", "{"}:
                depth += 1
            elif current.value in {")", "]", "}"}:
                depth = max(depth - 1, 0)
            elif depth == 0 and current.value == ";":
                cursor += 1
                break
            if (
                depth == 0
                and current.kind == "identifier"
                and current.value == "from"
                and cursor + 1 < len(tokens)
                and tokens[cursor + 1].kind == "string"
            ):
                yield tokens[cursor + 1]
                cursor += 2
                break
            if (
                cursor > index + 1
                and depth == 0
                and current.kind == "identifier"
                and current.value in {"export", "import"}
            ):
                break
            cursor += 1
        index = max(cursor, index + 1)


def _javascript_matching_pairs(tokens: Sequence[_JavaScriptToken]) -> dict[int, int]:
    pairs: dict[int, int] = {}
    stack: list[tuple[str, int]] = []
    closing = {")": "(", "]": "[", "}": "{"}
    for index, token in enumerate(tokens):
        if token.value in {"(", "[", "{"}:
            stack.append((token.value, index))
        elif token.value in closing and stack and stack[-1][0] == closing[token.value]:
            _, opening = stack.pop()
            pairs[opening] = index
    return pairs


def _javascript_expression_end(
    content: str,
    tokens: Sequence[_JavaScriptToken],
    start: int,
    stop: int,
    pairs: Mapping[int, int],
) -> int:
    index = start
    while index < stop:
        if tokens[index].value in {"(", "[", "{"} and index in pairs:
            index = pairs[index] + 1
            continue
        if tokens[index].value in {",", ";"}:
            return index
        if index > start and "\n" in content[tokens[index - 1].end : tokens[index].start]:
            previous = tokens[index - 1]
            current = tokens[index]
            continuation_tokens = {
                ".",
                "?.",
                "(",
                "[",
                "+",
                "-",
                "*",
                "/",
                "%",
                "**",
                "&&",
                "||",
                "??",
                "&",
                "|",
                "^",
                "==",
                "===",
                "!=",
                "!==",
                "<",
                ">",
                "<=",
                ">=",
                "?",
                ":",
                "=>",
            }
            incomplete_previous = continuation_tokens | {",", "=", "!", "~"}
            if (
                current.value not in continuation_tokens
                and previous.value not in incomplete_previous
                and current.kind != "template"
            ):
                return index
        index += 1
    return stop


def _javascript_argument_spans(
    tokens: Sequence[_JavaScriptToken],
    opening: int,
    closing: int,
    pairs: Mapping[int, int],
) -> tuple[tuple[int, int], ...]:
    spans: list[tuple[int, int]] = []
    start = opening + 1
    index = start
    while index < closing:
        if tokens[index].value in {"(", "[", "{"} and index in pairs:
            index = pairs[index] + 1
            continue
        if tokens[index].value == ",":
            if start < index:
                spans.append((start, index))
            start = index + 1
        index += 1
    if start < closing:
        spans.append((start, closing))
    return tuple(spans)


def _javascript_static_bindings(
    content: str,
    tokens: Sequence[_JavaScriptToken],
    pairs: Mapping[int, int],
) -> tuple[
    dict[str, tuple[int, int]],
    dict[str, tuple[tuple[int, int], ...]],
    bool,
]:
    bindings: dict[str, tuple[int, int]] = {}
    spans_by_name: dict[str, list[tuple[int, int]]] = {}
    overflow = False
    stored_bindings = 0
    for index, token in enumerate(tokens):
        if token.value not in {"const", "let", "var"} or index + 3 >= len(tokens):
            continue
        name = tokens[index + 1]
        if name.kind != "identifier" or tokens[index + 2].value != "=":
            continue
        end = _javascript_expression_end(content, tokens, index + 3, len(tokens), pairs)
        identifier = name.value
        if stored_bindings >= _MAX_STATIC_BINDINGS:
            overflow = True
            continue
        span = (index + 3, end)
        bindings[identifier] = span
        spans_by_name.setdefault(identifier, []).append(span)
        stored_bindings += 1
    return (
        bindings,
        {name: tuple(spans) for name, spans in spans_by_name.items()},
        overflow,
    )


def _javascript_path_taint(
    content: str,
    tokens: Sequence[_JavaScriptToken],
    start: int,
    end: int,
    *,
    bindings: Mapping[str, tuple[tuple[int, int], ...]],
    memo: dict[str, _PathTaint],
    resolving: set[str],
    depth: int = 0,
) -> _PathTaint:
    if depth >= _MAX_STATIC_PROPAGATION_DEPTH or start >= end:
        return _PathTaint()

    source_start = tokens[start].start
    source_end = tokens[end - 1].end
    source = content[source_start:source_end]
    plugin_match = _PLUGIN_VARIABLE_RE.search(source)
    direct = _PathTaint(
        repository=any(
            token.kind == "identifier" and token.value == "__dirname" for token in tokens[start:end]
        ),
        plugin_value=plugin_match.group(0) if plugin_match is not None else None,
        plugin_offset=source_start + plugin_match.start() if plugin_match is not None else None,
    )

    propagated: list[_PathTaint] = []
    for token in tokens[start:end]:
        if token.kind != "identifier" or token.value in resolving:
            continue
        if token.value in memo:
            propagated.append(memo[token.value])
            continue
        spans = bindings.get(token.value, ())
        if not spans:
            continue
        resolving.add(token.value)
        binding_taints = tuple(
            _javascript_path_taint(
                content,
                tokens,
                span_start,
                span_end,
                bindings=bindings,
                memo=memo,
                resolving=resolving,
                depth=depth + 1,
            )
            for span_start, span_end in spans
        )
        resolving.remove(token.value)
        combined = _merge_path_taints(binding_taints)
        memo[token.value] = combined
        propagated.append(combined)
    return _merge_path_taints((direct, *propagated))


def _javascript_static_path_value(
    tokens: Sequence[_JavaScriptToken],
    start: int,
    end: int,
    *,
    entry_path: str,
    pairs: Mapping[int, int],
    bindings: Mapping[str, tuple[int, int]],
    memo: dict[str, _StaticPathValue | None],
    resolving: set[str],
    depth: int = 0,
) -> _StaticPathValue | None:
    if depth >= _MAX_STATIC_PROPAGATION_DEPTH or start >= end:
        return None
    if tokens[start].value == "(" and pairs.get(start) == end - 1:
        return _javascript_static_path_value(
            tokens,
            start + 1,
            end - 1,
            entry_path=entry_path,
            pairs=pairs,
            bindings=bindings,
            memo=memo,
            resolving=resolving,
            depth=depth + 1,
        )
    if end - start == 1:
        token = tokens[start]
        if token.kind in {"string", "template"}:
            return _StaticPathValue(token.value)
        if token.kind != "identifier":
            return None
        name = token.value
        if name == "__dirname":
            return _StaticPathValue(
                str(PurePosixPath(entry_path).parent),
                anchored_to_repository=True,
                propagated=True,
            )
        if name in memo:
            return memo[name]
        span = bindings.get(name)
        if span is None or name in resolving:
            return None
        resolving.add(name)
        value = _javascript_static_path_value(
            tokens,
            *span,
            entry_path=entry_path,
            pairs=pairs,
            bindings=bindings,
            memo=memo,
            resolving=resolving,
            depth=depth + 1,
        )
        resolving.remove(name)
        if value is not None:
            value = _StaticPathValue(
                value.value,
                anchored_to_repository=value.anchored_to_repository,
                propagated=True,
            )
        memo[name] = value
        return value

    call_opening: int | None = None
    call_name: str | None = None
    if (
        start + 3 < end
        and tokens[start].kind == "identifier"
        and tokens[start + 1].value == "."
        and tokens[start + 2].kind == "identifier"
        and tokens[start + 3].value == "("
    ):
        call_opening = start + 3
        call_name = tokens[start + 2].value.casefold()
    elif start + 1 < end and tokens[start].kind == "identifier" and tokens[start + 1].value == "(":
        call_opening = start + 1
        call_name = tokens[start].value.casefold()
    if (
        call_opening is not None
        and pairs.get(call_opening) == end - 1
        and call_name in {"join", "resolve"}
    ):
        values = [
            _javascript_static_path_value(
                tokens,
                argument_start,
                argument_end,
                entry_path=entry_path,
                pairs=pairs,
                bindings=bindings,
                memo=memo,
                resolving=resolving,
                depth=depth + 1,
            )
            for argument_start, argument_end in _javascript_argument_spans(
                tokens,
                call_opening,
                end - 1,
                pairs,
            )
        ]
        if not values or any(value is None for value in values):
            return None
        return _static_path_join(tuple(value for value in values if value))

    index = start
    while index < end:
        if tokens[index].value in {"(", "[", "{"} and index in pairs:
            index = pairs[index] + 1
            continue
        if tokens[index].value == "+":
            left = _javascript_static_path_value(
                tokens,
                start,
                index,
                entry_path=entry_path,
                pairs=pairs,
                bindings=bindings,
                memo=memo,
                resolving=resolving,
                depth=depth + 1,
            )
            right = _javascript_static_path_value(
                tokens,
                index + 1,
                end,
                entry_path=entry_path,
                pairs=pairs,
                bindings=bindings,
                memo=memo,
                resolving=resolving,
                depth=depth + 1,
            )
            if left is None or right is None or right.anchored_to_repository:
                return None
            return _StaticPathValue(
                f"{left.value}{right.value}",
                anchored_to_repository=left.anchored_to_repository,
                propagated=True,
            )
        index += 1
    return None


def _javascript_call_argument_span(
    tokens: Sequence[_JavaScriptToken],
    index: int,
    pairs: Mapping[int, int],
) -> tuple[int, int] | None:
    opening = index + 1
    closing = pairs.get(opening)
    if opening >= len(tokens) or tokens[opening].value != "(" or closing is None:
        return None
    spans = _javascript_argument_spans(tokens, opening, closing, pairs)
    return spans[0] if spans else None


def _javascript_call_reference(
    content: str,
    tokens: list[_JavaScriptToken],
    index: int,
) -> tuple[str, int, bool] | None:
    if index + 2 >= len(tokens) or tokens[index + 1].value != "(":
        return None
    argument = tokens[index + 2]
    if argument.value == ")":
        return None
    if argument.kind == "string":
        return argument.value, argument.start, False
    if argument.kind == "template":
        return content[argument.start : argument.end], argument.start, False
    if argument.kind == "template_expression":
        return argument.value, argument.start, True
    end = min(argument.end + 256, len(content))
    for current in tokens[index + 3 : index + 35]:
        if current.value in {",", ")"}:
            end = min(end, current.start)
            break
    value = content[argument.start : end].strip()
    return (value, argument.start, True) if value else None


def _javascript_path_references(
    content: str,
    *,
    entry_path: str | None = None,
    base_offset: int = 0,
) -> Iterable[_PathReference]:
    tokens, failed = _javascript_tokens(content)
    if failed:
        yield _PathReference(
            "unparseable JavaScript/TypeScript source",
            base_offset,
            "unknown",
            "javascript.parse_failure",
        )
        return
    pairs = _javascript_matching_pairs(tokens)
    bindings, taint_bindings, binding_overflow = _javascript_static_bindings(
        content,
        tokens,
        pairs,
    )
    memo: dict[str, _StaticPathValue | None] = {}
    taint_memo: dict[str, _PathTaint] = {}
    for path in _javascript_static_imports(tokens):
        yield _PathReference(
            path.value,
            base_offset + path.start,
            "import",
            "javascript.import",
        )

    for index, token in enumerate(tokens):
        name = token.value.casefold()
        if token.kind != "identifier" or name not in _JAVASCRIPT_PATH_CALLS:
            continue
        argument = _javascript_call_reference(content, tokens, index)
        if argument is None:
            continue
        value, offset, dynamic = argument
        span = _javascript_call_argument_span(tokens, index, pairs)
        if entry_path is not None and span is not None:
            taint = _javascript_path_taint(
                content,
                tokens,
                *span,
                bindings=taint_bindings,
                memo=taint_memo,
                resolving=set(),
            )
            if taint.plugin_value is not None and taint.plugin_offset is not None:
                yield _PathReference(
                    taint.plugin_value,
                    base_offset + taint.plugin_offset,
                    _JAVASCRIPT_PATH_CALLS[name],
                    "javascript.plugin_tainted",
                )
                continue
            static_value = _javascript_static_path_value(
                tokens,
                *span,
                entry_path=entry_path,
                pairs=pairs,
                bindings=bindings,
                memo=memo,
                resolving=set(),
            )
            uncertain_repository_value = (
                static_value is not None
                and not static_value.anchored_to_repository
                and (taint.repository or (binding_overflow and static_value.propagated))
            )
            if static_value is not None and not uncertain_repository_value:
                value = _static_reference_value(static_value, entry_path)
                dynamic = False
            elif taint.repository or binding_overflow:
                source_start = tokens[span[0]].start
                source_end = tokens[span[1] - 1].end
                value = content[source_start:source_end]
                offset = source_start
                dynamic = True
                syntax = (
                    "javascript.repo_tainted.expression"
                    if taint.repository
                    else "javascript.binding_overflow.expression"
                )
                yield _PathReference(
                    value,
                    base_offset + offset,
                    _JAVASCRIPT_PATH_CALLS[name],
                    syntax,
                )
                continue
        syntax = "javascript.expression" if dynamic else "javascript.call"
        yield _PathReference(
            value,
            base_offset + offset,
            _JAVASCRIPT_PATH_CALLS[name],
            syntax,
        )


def _shell_tokens(line: str) -> tuple[list[str], bool]:
    lexer = shlex.shlex(line, posix=True, punctuation_chars=";&|<>")
    lexer.commenters = "#"
    lexer.whitespace_split = True
    try:
        return list(lexer), False
    except ValueError:
        return [], True


def _shell_token_offsets(line: str, tokens: list[str]) -> list[int]:
    offsets: list[int] = []
    cursor = 0
    for token in tokens:
        position = line.find(token, cursor)
        if position < 0:
            position = line.find(token)
        position = max(position, cursor)
        offsets.append(position)
        cursor = position + len(token)
    return offsets


def _shell_logical_lines(content: str) -> Iterable[tuple[str, tuple[int, ...]]]:
    buffer: list[str] = []
    source_offsets: list[int] = []
    physical_offset = 0
    for physical_line in content.splitlines(keepends=True):
        body = physical_line.rstrip("\r\n")
        newline_length = len(physical_line) - len(body)
        trailing_backslashes = len(body) - len(body.rstrip("\\"))
        continued = newline_length > 0 and trailing_backslashes % 2 == 1
        kept = body[:-1] if continued else body
        buffer.append(kept)
        source_offsets.extend(range(physical_offset, physical_offset + len(kept)))
        physical_offset += len(physical_line)
        if continued:
            continue
        yield "".join(buffer), tuple(source_offsets)
        buffer.clear()
        source_offsets.clear()
    if buffer:
        yield "".join(buffer), tuple(source_offsets)


def _shell_heredoc_markers(tokens: list[str]) -> tuple[tuple[str, bool], ...]:
    markers: list[tuple[str, bool]] = []
    for index, token in enumerate(tokens[:-1]):
        if token not in {"<<", "<<-"}:
            continue
        delimiter = tokens[index + 1]
        strip_tabs = token == "<<-" or delimiter.startswith("-")
        if strip_tabs:
            delimiter = delimiter.removeprefix("-")
        if delimiter:
            markers.append((delimiter, strip_tabs))
    return tuple(markers)


def _looks_shell_path(value: str) -> bool:
    decoded = _decode_reference(value)
    return (
        _is_unsafe_host_reference(decoded)
        or _looks_explicit_path(decoded)
        or ("/" in decoded and _DYNAMIC_RE.search(decoded) is not None)
    )


def _looks_shell_command_path(value: str) -> bool:
    decoded = _decode_reference(value)
    if re.fullmatch(r"/[A-Za-z0-9_.-]+", decoded):
        return False
    return ("/" in decoded or "\\" in decoded) and _looks_shell_path(decoded)


def _shell_interpreter_script_index(
    tokens: list[str],
    command_index: int,
) -> int | None:
    interpreter = PurePosixPath(tokens[command_index]).name.casefold()
    if interpreter not in _SCRIPT_INTERPRETERS:
        return None
    index = command_index + 1
    if interpreter in {"bun", "deno"} and index < len(tokens) and tokens[index].casefold() == "run":
        index += 1
    while index < len(tokens):
        value = tokens[index]
        if value == "--":
            index += 1
            break
        if value.startswith("-"):
            if value in {"-c", "-e", "-m", "-p", "--eval", "--print"}:
                return None
            index += 1
            continue
        if _looks_shell_path(value):
            return index
        index += 1
    return None


def _shell_segment_references(
    tokens: list[str],
    offsets: list[int],
    *,
    base_offset: int,
) -> Iterable[_PathReference]:
    if not tokens:
        return
    index = 0
    if tokens[0] == "$":
        index += 1
    while index < len(tokens) and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=.*", tokens[index]):
        index += 1
    while index < len(tokens) and tokens[index] in {"env", "sudo"}:
        index += 1
    if index >= len(tokens):
        return
    command = tokens[index]
    operands = list(range(index + 1, len(tokens)))

    if _looks_shell_command_path(command):
        yield _PathReference(command, base_offset + offsets[index], "execute", "shell.command")

    script_index = _shell_interpreter_script_index(tokens, index)
    if script_index is not None:
        yield _PathReference(
            tokens[script_index],
            base_offset + offsets[script_index],
            "execute",
            "shell.interpreter",
        )

    for operand_index in operands:
        operand = tokens[operand_index]
        if operand in {"-o", "--out", "--output"} and operand_index + 1 < len(tokens):
            value_index = operand_index + 1
            yield _PathReference(
                tokens[value_index],
                base_offset + offsets[value_index],
                "write",
                "shell.output",
            )
        elif operand.startswith(("--out=", "--output=")):
            value = operand.split("=", 1)[1]
            yield _PathReference(
                value,
                base_offset + offsets[operand_index] + operand.find(value),
                "write",
                "shell.output",
            )

    if command.casefold() not in _SHELL_PATH_COMMANDS:
        return
    for operand_index in operands:
        operand = tokens[operand_index]
        if operand.startswith("-") or not _looks_shell_path(operand):
            continue
        yield _PathReference(
            operand,
            base_offset + offsets[operand_index],
            "read",
            "shell.operand",
        )
        if command in {".", "source"}:
            return


def _shell_path_references(
    content: str,
    *,
    base_offset: int = 0,
    fail_closed: bool = True,
) -> Iterable[_PathReference]:
    heredocs: list[tuple[str, bool]] = []
    for line, source_map in _shell_logical_lines(content):
        line_offset = source_map[0] if source_map else 0
        if heredocs:
            delimiter, strip_tabs = heredocs[0]
            comparable = line.lstrip("\t") if strip_tabs else line
            if comparable == delimiter:
                heredocs.pop(0)
            continue
        if line_offset == 0 and line.startswith("#!"):
            tokens, failed = _shell_tokens(line[2:])
            if failed:
                if fail_closed:
                    yield _PathReference(
                        "unparseable shell source",
                        base_offset,
                        "unknown",
                        "shell.parse_failure",
                    )
                return
            logical_offsets = _shell_token_offsets(line[2:], tokens)
            offsets = [
                source_map[min(offset + 2, len(source_map) - 1)] for offset in logical_offsets
            ]
            for index in range(1, len(tokens)):
                if _looks_shell_path(tokens[index]):
                    yield _PathReference(
                        tokens[index],
                        base_offset + offsets[index],
                        "execute",
                        "shell.shebang",
                    )
            continue
        tokens, failed = _shell_tokens(line)
        if failed:
            if fail_closed:
                yield _PathReference(
                    "unparseable shell source",
                    base_offset + line_offset,
                    "unknown",
                    "shell.parse_failure",
                )
            continue
        logical_offsets = _shell_token_offsets(line, tokens)
        offsets = [
            source_map[min(offset, len(source_map) - 1)] if source_map else line_offset
            for offset in logical_offsets
        ]
        segment_start = 0
        for index in range(len(tokens) + 1):
            if index < len(tokens) and tokens[index] not in {"&", "&&", ";", "|", "||"}:
                continue
            yield from _shell_segment_references(
                tokens[segment_start:index],
                offsets[segment_start:index],
                base_offset=base_offset,
            )
            segment_start = index + 1
        heredocs.extend(_shell_heredoc_markers(tokens))
    if heredocs and fail_closed:
        yield _PathReference(
            "unclosed shell heredoc",
            base_offset,
            "unknown",
            "shell.parse_failure",
        )


def _glob_pattern_variants(pattern: str) -> tuple[str, ...]:
    variants = {pattern}
    pending = [pattern]
    while pending:
        current = pending.pop()
        marker = current.find("/**/")
        if marker < 0:
            continue
        collapsed = f"{current[:marker]}/{current[marker + 4 :]}"
        if collapsed not in variants:
            variants.add(collapsed)
            pending.append(collapsed)
    return tuple(sorted(variants))


def _inventory_glob_references(
    value: str,
    *,
    entry_path: str,
    candidate_root: str,
    by_path: Mapping[str, InventoryEntry],
) -> tuple[str, ...]:
    decoded = _decode_reference(value)
    if _is_unsafe_host_reference(decoded):
        return (value,)
    inventory_value = unquote(value)
    if decoded != inventory_value and ".." in PurePosixPath(decoded).parts:
        return (value,)
    bases = (PurePosixPath(entry_path).parent, PurePosixPath(candidate_root))
    seen_bases: set[str] = set()
    saw_escape = False
    for base in bases:
        base_value = base.as_posix()
        if base_value in seen_bases:
            continue
        seen_bases.add(base_value)
        pattern, escaped = _collapse_path(base, inventory_value)
        if escaped or pattern is None:
            saw_escape = True
            continue
        variants = _glob_pattern_variants(pattern)
        matches = tuple(
            path
            for path, entry in sorted(by_path.items())
            if entry.kind == "file"
            and any(PurePosixPath(path).match(variant) for variant in variants)
        )
        if not matches:
            continue
        return tuple(path.removeprefix(f"{base_value}/") for path in matches)
    return (value,) if saw_escape else ()


def _structured_path_references(
    content: str,
    *,
    entry_path: str,
    candidate_root: str,
    by_path: Mapping[str, InventoryEntry],
) -> Iterable[_PathReference]:
    try:
        parsed: object = json.loads(content)
    except (ValueError, OverflowError, RecursionError):
        if PurePosixPath(entry_path).name.casefold() in {
            "deno.json",
            "jsconfig.json",
            "package.json",
            "tsconfig.json",
        }:
            yield _PathReference(
                "unparseable structured config",
                0,
                "unknown",
                "json.parse_failure",
            )
        return
    if not isinstance(parsed, Mapping):
        return

    values: list[tuple[str, str]] = []
    for field in _STRUCTURED_PATH_FIELDS:
        field_value = parsed.get(field)
        if isinstance(field_value, str):
            values.append((field, field_value))
        elif isinstance(field_value, list):
            values.extend((field, item) for item in field_value if isinstance(item, str))
    references = parsed.get("references")
    if isinstance(references, list):
        values.extend(
            ("references.path", item["path"])
            for item in references
            if isinstance(item, Mapping) and isinstance(item.get("path"), str)
        )

    cursor = 0
    for field, value in values:
        offset = content.find(value, cursor)
        offset = max(offset, 0)
        cursor = offset + len(value)
        expanded: tuple[str, ...] = (value,)
        syntax = f"json.{field}"
        if field in {"files", "include"} and any(marker in value for marker in "*?["):
            expanded = _inventory_glob_references(
                value,
                entry_path=entry_path,
                candidate_root=candidate_root,
                by_path=by_path,
            )
            syntax = "json.glob"
        for reference in expanded:
            yield _PathReference(reference, offset, "read", syntax)


def _fenced_code_path_references(
    language: str,
    body: str,
    *,
    entry_path: str,
    candidate_root: str,
    by_path: Mapping[str, InventoryEntry],
    base_offset: int,
) -> Iterable[_PathReference]:
    references: Iterable[_PathReference]
    if language in {"py", "python"}:
        references = _python_path_references(
            body,
            entry_path=entry_path,
            candidate_root=candidate_root,
            by_path=by_path,
            base_offset=base_offset,
            fail_closed=False,
        )
    elif language in {"javascript", "js", "jsx", "node", "ts", "tsx", "typescript"}:
        references = _javascript_path_references(
            body,
            entry_path=entry_path,
            base_offset=base_offset,
        )
    elif language in {"bash", "sh", "shell", "zsh"}:
        references = _shell_path_references(
            body,
            base_offset=base_offset,
            fail_closed=True,
        )
    else:
        return
    for reference in references:
        if reference.access == "import" and _decode_reference(reference.value).startswith(
            ("./", "../")
        ):
            yield _PathReference(
                reference.value,
                reference.offset,
                reference.access,
                f"markdown.fence.{reference.syntax}",
            )
        else:
            yield reference


def _markdown_inline_code_has_dependency_context(
    content: str,
    match: re.Match[str],
) -> bool:
    line_start = content.rfind("\n", 0, match.start()) + 1
    line_end = content.find("\n", match.end())
    if line_end < 0:
        line_end = len(content)
    prefix = content[line_start : match.start()]
    suffix = content[match.end() : line_end]
    body = match.group("body").strip()
    if not any(character.isspace() for character in body) and _looks_shell_path(body):
        proven_output_context = (
            re.search(r"<[^>]+>", body) is not None
            or _MARKDOWN_INLINE_DESTINATION_BEFORE_RE.search(prefix) is not None
            or _MARKDOWN_INLINE_DESTINATION_AFTER_RE.search(suffix) is not None
            or _MARKDOWN_INLINE_OPTIONAL_WORKSPACE_RE.search(prefix) is not None
        )
        return not proven_output_context
    tokens, failed = _shell_tokens(body)
    return not failed and len(tokens) > 1


def _development_fence_reference_is_relevant(reference: _PathReference) -> bool:
    decoded = _decode_reference(reference.value)
    path = PurePosixPath(decoded)
    if _PLUGIN_VARIABLE_RE.search(decoded) is not None or ".." in path.parts:
        return True
    name = path.name.casefold()
    return not (
        reference.access == "execute"
        and path.parts[:1] == ("scripts",)
        and re.match(r"(?:validate|lint|test|check)(?:[-_.]|$)", name) is not None
    )


def _markdown_frontmatter_bounds(content: str) -> tuple[int, int, int] | None:
    if not content.startswith("---"):
        return None
    opening_end = content.find("\n")
    if opening_end < 0:
        return None
    body_start = opening_end + 1
    closing = re.search(r"^---[ \t]*\r?$", content[body_start:], re.MULTILINE)
    if closing is None:
        return None
    body_end = body_start + closing.start()
    closing_end = body_start + closing.end()
    return body_start, body_end, closing_end


def _frontmatter_path_references(
    content: str,
    *,
    base_offset: int,
) -> Iterable[_PathReference]:
    scalar_indent: int | None = None
    for line_offset, line in _iter_lines_with_offsets(content):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        indent = len(line) - len(line.lstrip(" "))
        if scalar_indent is not None:
            if indent > scalar_indent:
                continue
            scalar_indent = None
        match = _YAML_FIELD_RE.match(line)
        if match is None:
            continue
        value = match.group("value").strip()
        if re.fullmatch(r"[|>](?:[+-][1-9]?|[1-9][+-]?)?", value):
            scalar_indent = len(match.group("indent"))
            continue
        if match.group("key").casefold() not in {"file", "path", "root", "source"}:
            continue
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
            value = value[1:-1]
        else:
            value = value.split(" #", 1)[0].strip()
        if not value:
            continue
        value_column = (
            line.find(match.group("value"))
            + len(match.group("value"))
            - len(match.group("value").lstrip())
        )
        yield _PathReference(
            _clean_reference(value),
            base_offset + line_offset + max(value_column, 0),
            "read",
            "markdown.frontmatter",
        )


def _merge_offset_ranges(
    ranges: Iterable[tuple[int, int]],
) -> tuple[tuple[int, int], ...]:
    merged: list[tuple[int, int]] = []
    for start, end in sorted(ranges):
        if start >= end:
            continue
        if merged and start <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        else:
            merged.append((start, end))
    return tuple(merged)


def _offset_in_ranges(offset: int, ranges: Sequence[tuple[int, int]]) -> bool:
    index = bisect_right(ranges, offset, key=lambda item: item[0]) - 1
    return index >= 0 and offset < ranges[index][1]


def _markdown_fences(content: str) -> tuple[_MarkdownFence, ...]:
    """Return CommonMark-style backtick and tilde fences in one linear pass."""
    fences: list[_MarkdownFence] = []
    active: tuple[str, int, str, int, int] | None = None
    offset = 0
    for physical_line in content.splitlines(keepends=True):
        line = physical_line.rstrip("\r\n")
        if active is None:
            opening = re.match(r"^ {0,3}(?P<marker>`{3,}|~{3,})(?P<info>.*)$", line)
            if opening is not None:
                marker = opening.group("marker")
                info = opening.group("info").strip()
                language = info.split(maxsplit=1)[0].casefold() if info else ""
                active = (marker[0], len(marker), language, offset, offset + len(physical_line))
        else:
            marker, marker_length, language, start, body_start = active
            closing = re.match(rf"^ {{0,3}}{re.escape(marker)}{{{marker_length},}}[ \t]*$", line)
            if closing is not None:
                fences.append(
                    _MarkdownFence(
                        language=language,
                        body_start=body_start,
                        body_end=offset,
                        start=start,
                        end=offset + len(physical_line),
                    )
                )
                active = None
        offset += len(physical_line)
    if active is not None:
        marker, marker_length, language, start, body_start = active
        del marker, marker_length
        fences.append(
            _MarkdownFence(
                language=language,
                body_start=body_start,
                body_end=len(content),
                start=start,
                end=len(content),
            )
        )
    return tuple(fences)


def _markdown_code_span_ranges(
    content: str,
    structural_exclusions: Sequence[tuple[int, int]],
) -> tuple[tuple[int, int], ...]:
    """Pair equal-length backtick runs without rescanning source prefixes."""
    runs: list[tuple[int, int, tuple[int, int]]] = []
    barrier = 0
    for match in re.finditer(r"`+", content):
        while (
            barrier < len(structural_exclusions)
            and match.start() >= structural_exclusions[barrier][1]
        ):
            barrier += 1
        if _offset_in_ranges(match.start(), structural_exclusions):
            continue
        runs.append(
            (
                match.start(),
                match.end(),
                (match.end() - match.start(), barrier),
            )
        )

    next_run: list[int | None] = [None] * len(runs)
    next_by_key: dict[tuple[int, int], int] = {}
    for index in range(len(runs) - 1, -1, -1):
        key = runs[index][2]
        next_run[index] = next_by_key.get(key)
        next_by_key[key] = index

    spans: list[tuple[int, int]] = []
    index = 0
    while index < len(runs):
        closing_index = next_run[index]
        if closing_index is None:
            index += 1
            continue
        spans.append((runs[index][0], runs[closing_index][1]))
        index = closing_index + 1
    return tuple(spans)


def _markdown_offset_is_escaped(content: str, offset: int) -> bool:
    backslashes = 0
    cursor = offset - 1
    while cursor >= 0 and content[cursor] == "\\":
        backslashes += 1
        cursor -= 1
    return backslashes % 2 == 1


def _markdown_development_ranges(
    content: str,
    excluded_ranges: Sequence[tuple[int, int]],
) -> tuple[tuple[int, int], ...]:
    ranges: list[tuple[int, int]] = []
    active: tuple[int, int] | None = None
    previous: tuple[int, str] | None = None

    def record_heading(offset: int, level: int, title: str) -> None:
        nonlocal active
        if active is not None and level <= active[1]:
            ranges.append((active[0], offset))
            active = None
        normalized = re.sub(r"[^a-z]+", " ", title.casefold()).strip()
        if active is None and normalized in _DEVELOPMENT_HEADING_TITLES:
            active = (offset, level)

    for offset, line in _iter_lines_with_offsets(content):
        if _offset_in_ranges(offset, excluded_ranges):
            previous = None
            continue
        match = _MARKDOWN_HEADING_RE.match(line)
        if match is not None:
            record_heading(offset, len(match.group("marker")), match.group("title"))
            previous = (offset, line)
            continue
        underline = re.match(r"^ {0,3}(?P<marker>=+|-+)[ \t]*$", line)
        if (
            underline is not None
            and previous is not None
            and previous[1].strip()
            and _MARKDOWN_HEADING_RE.match(previous[1]) is None
        ):
            level = 1 if underline.group("marker").startswith("=") else 2
            record_heading(previous[0], level, previous[1].strip())
            previous = None
            continue
        previous = (offset, line)
    if active is not None:
        ranges.append((active[0], len(content)))
    return _merge_offset_ranges(ranges)


def _markdown_reference_label(value: str) -> str:
    return " ".join(value.split()).casefold()


def _markdown_path_references(
    content: str,
    *,
    entry_path: str,
    candidate_root: str,
    by_path: Mapping[str, InventoryEntry],
) -> Iterable[_PathReference]:
    frontmatter = _markdown_frontmatter_bounds(content)
    fences = _markdown_fences(content)
    structural_ranges: list[tuple[int, int]] = [(fence.start, fence.end) for fence in fences]
    if frontmatter is not None:
        body_start, body_end, closing_end = frontmatter
        structural_ranges.append((0, closing_end))
        yield from _frontmatter_path_references(
            content[body_start:body_end],
            base_offset=body_start,
        )
    structural_exclusions = _merge_offset_ranges(structural_ranges)
    development_ranges = _markdown_development_ranges(content, structural_exclusions)
    excluded_ranges = structural_exclusions
    code_span_ranges = _markdown_code_span_ranges(content, structural_exclusions)
    reference_exclusions = _merge_offset_ranges((*excluded_ranges, *code_span_ranges))

    for match in _MARKDOWN_DESTINATION_RE.finditer(content):
        if _offset_in_ranges(match.start(), reference_exclusions) or _markdown_offset_is_escaped(
            content,
            match.start(),
        ):
            continue
        group = "angle" if match.group("angle") is not None else "plain"
        yield _PathReference(
            _clean_reference(match.group(group)),
            match.start(group),
            "read",
            "markdown.link",
        )

    definitions: dict[str, tuple[str, int]] = {}
    used_labels: set[str] = set()
    pending_definition: str | None = None
    for offset, line in _iter_lines_with_offsets(content):
        if _offset_in_ranges(offset, reference_exclusions):
            pending_definition = None
            continue
        if pending_definition is not None:
            destination = _MARKDOWN_REFERENCE_DESTINATION_RE.match(line)
            label = pending_definition
            pending_definition = None
            if destination is not None:
                group = "angle" if destination.group("angle") is not None else "plain"
                destination_offset = offset + destination.start(group)
                if not _offset_in_ranges(destination_offset, reference_exclusions):
                    definitions.setdefault(
                        label,
                        (
                            _clean_reference(destination.group(group)),
                            destination_offset,
                        ),
                    )
                    continue
        definition = _MARKDOWN_REFERENCE_DEFINITION_RE.match(line)
        if definition is not None:
            group = "angle" if definition.group("angle") is not None else "plain"
            definitions.setdefault(
                _markdown_reference_label(definition.group("label")),
                (
                    _clean_reference(definition.group(group)),
                    offset + definition.start(group),
                ),
            )
            continue
        definition_label = _MARKDOWN_REFERENCE_LABEL_RE.match(line)
        if definition_label is not None:
            pending_definition = _markdown_reference_label(definition_label.group("label"))
            continue
        for usage in _MARKDOWN_REFERENCE_USAGE_RE.finditer(line):
            usage_offset = offset + usage.start()
            if _offset_in_ranges(
                usage_offset,
                reference_exclusions,
            ) or _markdown_offset_is_escaped(content, usage_offset):
                continue
            label = usage.group("label") or usage.group("text")
            used_labels.add(_markdown_reference_label(label))
        for usage in _MARKDOWN_SHORTCUT_REFERENCE_RE.finditer(line):
            usage_offset = offset + usage.start()
            if _offset_in_ranges(
                usage_offset,
                reference_exclusions,
            ) or _markdown_offset_is_escaped(content, usage_offset):
                continue
            used_labels.add(_markdown_reference_label(usage.group("label")))
    for label in sorted(used_labels):
        resolved_definition = definitions.get(label)
        if resolved_definition is not None:
            value, offset = resolved_definition
            yield _PathReference(value, offset, "read", "markdown.reference")

    for fence in fences:
        references = _fenced_code_path_references(
            fence.language,
            content[fence.body_start : fence.body_end],
            entry_path=entry_path,
            candidate_root=candidate_root,
            by_path=by_path,
            base_offset=fence.body_start,
        )
        if _offset_in_ranges(fence.start, development_ranges):
            yield from (
                reference
                for reference in references
                if _development_fence_reference_is_relevant(reference)
            )
        else:
            yield from references

    for match in _MARKDOWN_INLINE_CODE_RE.finditer(content):
        if _offset_in_ranges(match.start(), excluded_ranges):
            continue
        if not _markdown_inline_code_has_dependency_context(content, match):
            continue
        yield from _shell_path_references(
            match.group("body"),
            base_offset=match.start("body"),
            fail_closed=False,
        )


def _path_references(
    entry: InventoryEntry,
    candidate_root: str,
    by_path: Mapping[str, InventoryEntry],
) -> Iterable[_PathReference]:
    content = entry.content
    if content is None:
        return
    suffix = PurePosixPath(entry.path).suffix.casefold()
    shebang = content.partition("\n")[0].casefold() if content.startswith("#!") else ""
    if suffix in {".md", ".markdown"}:
        yield from _markdown_path_references(
            content,
            entry_path=entry.path,
            candidate_root=candidate_root,
            by_path=by_path,
        )
    elif suffix == ".py" or "python" in shebang:
        yield from _python_path_references(
            content,
            entry_path=entry.path,
            candidate_root=candidate_root,
            by_path=by_path,
        )
    elif suffix in _JAVASCRIPT_SUFFIXES or any(
        runtime in shebang for runtime in ("bun", "deno", "node")
    ):
        yield from _javascript_path_references(content, entry_path=entry.path)
    elif suffix in _SHELL_SUFFIXES or entry.executable or content.startswith("#!"):
        yield from _shell_path_references(content)
    elif suffix == ".json":
        yield from _structured_path_references(
            content,
            entry_path=entry.path,
            candidate_root=candidate_root,
            by_path=by_path,
        )


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


def _resolve_local_reference(
    entry_path: str,
    candidate_root: str,
    raw: str,
    by_path: Mapping[str, InventoryEntry],
) -> tuple[str | None, bool]:
    """Resolve a local reference against immutable inventory coordinates."""
    decoded = _decode_reference(raw)
    if _is_unsafe_host_reference(decoded):
        return None, True
    inventory_value = unquote(raw)
    if decoded != inventory_value and ".." in PurePosixPath(decoded).parts:
        return None, True

    primary, escaped = _collapse_path(PurePosixPath(entry_path).parent, inventory_value)
    if escaped or primary is None:
        return None, True
    if primary in by_path:
        return primary, False

    if ".." in PurePosixPath(inventory_value).parts:
        return primary, False

    seen = {primary}
    for base in (PurePosixPath(candidate_root), PurePosixPath(".")):
        resolved, fallback_escaped = _collapse_path(base, inventory_value)
        if fallback_escaped or resolved is None or resolved in seen:
            continue
        seen.add(resolved)
        if resolved in by_path:
            return resolved, False
    return primary, False


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


@dataclass(frozen=True, slots=True)
class _RawPluginContext:
    inert_ranges: tuple[tuple[int, int], ...] = ()
    active_ranges: tuple[tuple[int, int], ...] = ()
    default_inert: bool = False


def _raw_plugin_match_is_inert(context: _RawPluginContext, offset: int) -> bool:
    if _offset_in_ranges(offset, context.active_ranges):
        return False
    return context.default_inert or _offset_in_ranges(offset, context.inert_ranges)


def _source_line_starts(content: str) -> tuple[int, ...]:
    starts = [0]
    starts.extend(match.end() for match in re.finditer("\n", content))
    return tuple(starts)


def _source_position_offset(
    line_starts: tuple[int, ...],
    position: tuple[int, int],
) -> int:
    line, column = position
    line_index = max(line - 1, 0)
    if line_index >= len(line_starts):
        return line_starts[-1]
    return line_starts[line_index] + column


def _python_raw_inert_ranges(
    content: str,
    *,
    base_offset: int = 0,
) -> tuple[tuple[int, int], ...]:
    line_starts = _source_line_starts(content)
    ranges: list[tuple[int, int]] = []
    try:
        tokens = tokenize.generate_tokens(io.StringIO(content).readline)
        for token in tokens:
            if token.type not in {
                tokenize.COMMENT,
                tokenize.FSTRING_MIDDLE,
                tokenize.STRING,
            }:
                continue
            ranges.append(
                (
                    base_offset + _source_position_offset(line_starts, token.start),
                    base_offset + _source_position_offset(line_starts, token.end),
                )
            )
    except (IndentationError, SyntaxError, tokenize.TokenError):
        pass
    return _merge_offset_ranges(ranges)


def _javascript_raw_context(
    content: str,
    *,
    base_offset: int = 0,
) -> _RawPluginContext:
    tokens, failed = _javascript_tokens(content)
    if failed:
        return _RawPluginContext()

    literal_ranges = _merge_offset_ranges(
        (
            base_offset + token.start,
            base_offset + token.end,
        )
        for token in tokens
        if token.kind in {"regex", "string", "template"}
    )
    active_ranges: list[tuple[int, int]] = [
        (base_offset + token.start, base_offset + token.end)
        for token in tokens
        if token.kind not in {"regex", "string", "template", "template_expression"}
    ]
    for token in tokens:
        if token.kind != "template_expression":
            continue
        for interpolation in re.finditer(r"(?<!\\)\$\{", content[token.start : token.end]):
            start = base_offset + token.start + interpolation.start()
            if not _offset_in_ranges(start, literal_ranges):
                active_ranges.append((start, start + 2))
    return _RawPluginContext(
        active_ranges=_merge_offset_ranges(active_ranges),
        default_inert=True,
    )


def _shell_heredoc_delimiter(line: str, offset: int) -> tuple[str, bool] | None:
    cursor = offset + 2
    strip_tabs = cursor < len(line) and line[cursor] == "-"
    if strip_tabs:
        cursor += 1
    while cursor < len(line) and line[cursor] in " \t":
        cursor += 1
    if cursor >= len(line):
        return None
    if line[cursor] in {'"', "'"}:
        quote = line[cursor]
        end = line.find(quote, cursor + 1)
        if end < 0:
            return None
        delimiter = line[cursor + 1 : end]
    else:
        match = re.match(r"[^\s;&|<>()]+", line[cursor:])
        if match is None:
            return None
        delimiter = match.group(0)
    return (delimiter, strip_tabs) if delimiter else None


def _shell_raw_context(
    content: str,
    *,
    base_offset: int = 0,
) -> _RawPluginContext:
    hard_inert: list[tuple[int, int]] = []
    double_quoted: list[tuple[int, int]] = []
    heredocs: list[tuple[str, bool]] = []
    line_offset = 0
    for line_number, physical_line in enumerate(content.splitlines(keepends=True)):
        line = physical_line.rstrip("\r\n")
        if heredocs:
            hard_inert.append(
                (
                    base_offset + line_offset,
                    base_offset + line_offset + len(physical_line),
                )
            )
            delimiter, strip_tabs = heredocs[0]
            candidate = line.lstrip("\t") if strip_tabs else line
            if candidate == delimiter:
                heredocs.pop(0)
            line_offset += len(physical_line)
            continue

        pending: list[tuple[str, bool]] = []
        cursor = 0
        while cursor < len(line):
            character = line[cursor]
            if character == "\\":
                cursor += 2
                continue
            if character in {'"', "'"}:
                quote = character
                end = cursor + 1
                while end < len(line):
                    if quote == '"' and line[end] == "\\":
                        end += 2
                        continue
                    if line[end] == quote:
                        end += 1
                        break
                    end += 1
                target = double_quoted if quote == '"' else hard_inert
                target.append(
                    (
                        base_offset + line_offset + cursor,
                        base_offset + line_offset + end,
                    )
                )
                cursor = end
                continue
            if (
                character == "#"
                and not (line_number == 0 and cursor == 0 and line.startswith("#!"))
                and (cursor == 0 or line[cursor - 1].isspace())
            ):
                hard_inert.append(
                    (
                        base_offset + line_offset + cursor,
                        base_offset + line_offset + len(line),
                    )
                )
                break
            if line.startswith("<<", cursor) and not line.startswith("<<<", cursor):
                heredoc_marker = _shell_heredoc_delimiter(line, cursor)
                if heredoc_marker is not None:
                    pending.append(heredoc_marker)
                cursor += 2
                continue
            cursor += 1
        heredocs.extend(pending)
        line_offset += len(physical_line)

    hard_ranges = _merge_offset_ranges(hard_inert)
    double_ranges = _merge_offset_ranges(double_quoted)
    active_ranges = _merge_offset_ranges(
        (base_offset + match.start(), base_offset + match.end())
        for match in _PLUGIN_VARIABLE_RE.finditer(content)
        if _offset_in_ranges(base_offset + match.start(), double_ranges)
        and not _offset_in_ranges(base_offset + match.start(), hard_ranges)
    )
    return _RawPluginContext(
        inert_ranges=_merge_offset_ranges((*hard_ranges, *double_ranges)),
        active_ranges=active_ranges,
    )


def _complement_offset_ranges(
    start: int,
    end: int,
    active_ranges: tuple[tuple[int, int], ...],
) -> tuple[tuple[int, int], ...]:
    ranges: list[tuple[int, int]] = []
    cursor = start
    for active_start, active_end in active_ranges:
        active_start = max(active_start, start)
        active_end = min(active_end, end)
        if active_start >= active_end:
            continue
        if cursor < active_start:
            ranges.append((cursor, active_start))
        cursor = max(cursor, active_end)
    if cursor < end:
        ranges.append((cursor, end))
    return tuple(ranges)


def _markdown_raw_context(content: str) -> _RawPluginContext:
    fences = _markdown_fences(content)
    ranges: list[tuple[int, int]] = []
    active_ranges: list[tuple[int, int]] = []
    python_languages = {"py", "python"}
    javascript_languages = {
        "javascript",
        "js",
        "jsx",
        "node",
        "ts",
        "tsx",
        "typescript",
    }
    shell_languages = {"bash", "sh", "shell", "zsh"}
    for fence in fences:
        body = content[fence.body_start : fence.body_end]
        if fence.language in python_languages:
            ranges.extend(_python_raw_inert_ranges(body, base_offset=fence.body_start))
        elif fence.language in javascript_languages:
            context = _javascript_raw_context(body, base_offset=fence.body_start)
            if context.default_inert:
                ranges.extend(
                    _complement_offset_ranges(
                        fence.body_start,
                        fence.body_end,
                        context.active_ranges,
                    )
                )
            else:
                ranges.extend(context.inert_ranges)
        elif fence.language in shell_languages:
            context = _shell_raw_context(body, base_offset=fence.body_start)
            ranges.extend(context.inert_ranges)
            active_ranges.extend(context.active_ranges)
        elif fence.language not in shell_languages:
            ranges.append((fence.start, fence.end))
    return _RawPluginContext(
        inert_ranges=_merge_offset_ranges(ranges),
        active_ranges=_merge_offset_ranges(active_ranges),
    )


def _raw_plugin_context(entry: InventoryEntry) -> _RawPluginContext:
    content = entry.content or ""
    suffix = PurePosixPath(entry.path).suffix.casefold()
    shebang = content.partition("\n")[0].casefold() if content.startswith("#!") else ""
    if suffix in {".md", ".markdown"}:
        return _markdown_raw_context(content)
    if suffix == ".py" or "python" in shebang:
        return _RawPluginContext(inert_ranges=_python_raw_inert_ranges(content))
    if suffix in _JAVASCRIPT_SUFFIXES or any(
        runtime in shebang for runtime in ("bun", "deno", "node")
    ):
        return _javascript_raw_context(content)
    if suffix in {".golden", ".snap", ".snapshot", ".txt"}:
        return _RawPluginContext(inert_ranges=((0, len(content)),))
    if suffix in _SHELL_SUFFIXES or content.startswith("#!"):
        return _shell_raw_context(content)
    return _RawPluginContext()


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
        raw_context = _raw_plugin_context(entry)
        for match in _MCP_TOOL_RE.finditer(content):
            if not collector.has_capacity(ReasonCode.PLUGIN_OWNED_MCP_TOOL):
                break
            if _raw_plugin_match_is_inert(raw_context, match.start()):
                continue
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
            if _raw_plugin_match_is_inert(raw_context, match.start()):
                continue
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
            if _raw_plugin_match_is_inert(raw_context, match.start()):
                continue
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
            if _raw_plugin_match_is_inert(raw_context, match.start()):
                continue
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
            if _raw_plugin_match_is_inert(raw_context, match.start()):
                continue
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
            if import_match is not None and not _raw_plugin_match_is_inert(
                raw_context,
                line_offset + import_match.start("module"),
            ):
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
            position = line.find(command) if command is not None else -1
            if (
                collector.has_capacity(ReasonCode.PLUGIN_RUNTIME_FILE_REFERENCE)
                and command is not None
                and not _raw_plugin_match_is_inert(
                    raw_context,
                    line_offset + max(position, 0),
                )
                and command.casefold() in owned.binaries
            ):
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


def _is_proven_package_context(reference: _PathReference) -> bool:
    if reference.access == "import" and reference.syntax.startswith("markdown.fence."):
        return False
    return reference.access == "import" or reference.syntax.startswith(
        (
            "json.",
            "markdown.",
            "python.repo_tainted.",
            "python.binding_overflow.",
            "javascript.repo_tainted.",
            "javascript.binding_overflow.",
        )
    )


def _missing_reference_is_package_context(
    reference: _PathReference,
    value: str,
) -> bool:
    if reference.access == "import" and reference.syntax.startswith("markdown.fence."):
        return False
    if reference.syntax.startswith(("json.", "markdown.")):
        return True
    if reference.syntax == "python.import":
        return True
    return reference.access == "import" and value.startswith(("./", "../"))


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
        raw_context = _raw_plugin_context(entry)
        for match in _PLUGIN_VARIABLE_RE.finditer(content):
            if not collector.has_capacity(ReasonCode.PLUGIN_ROOT_VARIABLE):
                break
            if _raw_plugin_match_is_inert(raw_context, match.start()):
                continue
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
            if _raw_plugin_match_is_inert(raw_context, match.start()):
                continue
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

        written_values: set[str] = set()
        references = sorted(
            _path_references(entry, candidate.root, by_path),
            key=lambda item: (item.offset, item.access != "write"),
        )
        for reference in references:
            raw = reference.value
            offset = reference.offset
            decoded = _decode_reference(raw)
            if reference.access == "write":
                written_values.add(decoded)
                continue
            if reference.syntax.endswith(".parse_failure"):
                if _is_proven_package_context(reference) and collector.has_capacity(
                    ReasonCode.DYNAMIC_REFERENCE_UNRESOLVED
                ):
                    collector.add(
                        ReasonCode.DYNAMIC_REFERENCE_UNRESOLVED,
                        _text_evidence(
                            entry.path,
                            content,
                            offset,
                            raw,
                            f"static.forward.{reference.syntax}",
                            field="source",
                        ),
                    )
                continue
            if _is_unsafe_host_reference(decoded):
                continue
            if not _is_candidate_local_reference(decoded):
                continue
            if reference.access == "read" and decoded in written_values:
                continue
            plugin_variable = _PLUGIN_VARIABLE_RE.search(decoded)
            if plugin_variable is not None:
                if collector.has_capacity(ReasonCode.PLUGIN_ROOT_VARIABLE):
                    collector.add(
                        ReasonCode.PLUGIN_ROOT_VARIABLE,
                        _text_evidence(
                            entry.path,
                            content,
                            offset + plugin_variable.start(),
                            plugin_variable.group(0),
                            "static.forward.plugin_root_variable",
                        ),
                    )
                continue
            if reference.syntax.endswith(".expression") or (
                reference.syntax != "json.glob" and _DYNAMIC_RE.search(decoded) is not None
            ):
                if _is_proven_package_context(reference) and collector.has_capacity(
                    ReasonCode.DYNAMIC_REFERENCE_UNRESOLVED
                ):
                    collector.add(
                        ReasonCode.DYNAMIC_REFERENCE_UNRESOLVED,
                        _text_evidence(
                            entry.path,
                            content,
                            offset,
                            decoded,
                            "static.forward.dynamic_reference",
                            field="path",
                        ),
                    )
                continue

            resolved, escaped = _resolve_local_reference(
                entry.path,
                candidate.root,
                raw,
                by_path,
            )
            if escaped or resolved is None:
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
            elif _missing_reference_is_package_context(
                reference,
                decoded,
            ) and collector.has_capacity(ReasonCode.MISSING_LOCAL_RESOURCE):
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
        boundary_relative_root = _relative_to(candidate.root, boundary.root)
        searchable_skill_roots = {candidate.root, boundary_relative_root}
        path_matches = tuple(
            match
            for skill_root in searchable_skill_roots
            if (
                match := re.search(
                    rf"(?<![A-Za-z0-9_./-])(?:\./)?{re.escape(skill_root)}"
                    rf"(?:/[A-Za-z0-9_./-]+)?(?![A-Za-z0-9_.-])",
                    path_search_content,
                )
            )
            is not None
        )
        exact_match = min(path_matches, key=lambda item: item.start(), default=None)
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
