# Env Autoload and Documentation Redesign Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Автоматически читать `FM_API_KEY` из локального `.env` без CLI option и разделить документацию на короткий tech-lead brief, decision algorithm и подробную internal reference.

**Architecture:** Новый модуль `env_config.py` безопасно и без shell evaluation читает только `.env` текущей рабочей директории и возвращает effective FM key с process-environment precedence. CLI создаёт pipeline с этим key provider; library API остаётся без неявного filesystem configuration. Подробный текущий tech-lead документ переносится, а два коротких документа описывают product I/O и решение об автономности.

**Tech Stack:** Python 3.12, Click 8, pytest, стандартная библиотека; новые runtime dependencies не добавляются.

## Global Constraints

- Не добавлять `--env-file` или API-key CLI argument.
- Не искать `.env` внутри source repository или по parent directories.
- Не исполнять и не интерполировать содержимое `.env`; неизвестные variables не экспортировать.
- Process environment переопределяет одноимённые file values; `FM_API_KEY` остаётся primary относительно `LLM_API_KEY`.
- `.env` должен оставаться untracked, `.env.example` — tracked.
- Не менять FM endpoint, model, prompt, confidence threshold или static classifications.

---

## File Structure

- Create `src/skill_importer/env_config.py`: bounded dotenv parser и effective API-key selection.
- Create `tests/test_env_config.py`: unit contract parser/precedence/safety.
- Modify `src/skill_importer/cli.py`: единая CLI pipeline factory для `scan` и `import`.
- Modify `tests/test_cli_e2e.py`: подтверждение автозагрузки обеими командами и отсутствия secret leakage.
- Modify `.gitignore`; create `.env.example`; create local ignored `.env`.
- Rename `docs/TECH_LEAD_IMPORTER_ALGORITHM.md` to `docs/INTERNAL_IMPLEMENTATION_REFERENCE.md`.
- Create a new concise `docs/TECH_LEAD_IMPORTER_ALGORITHM.md`.
- Create `docs/IMPORT_DECISION_ALGORITHM.md`.
- Modify `README.md` and `AUDIT_AND_NEXT_STEPS.md`: links, `.env` contract and examples.

---

### Task 1: Bounded `.env` key loader

**Files:**
- Create: `src/skill_importer/env_config.py`
- Create: `tests/test_env_config.py`
- Modify: `.gitignore`
- Create: `.env.example`
- Create locally, do not stage: `.env`

**Interfaces:**
- Consumes: `skill_importer.errors.ImporterError`, `Path.cwd()`, `os.environ`.
- Produces: `load_cli_api_key(*, directory: Path | None = None, environ: Mapping[str, str] | None = None) -> str | None`.

- [ ] **Step 1: Write failing loader tests**

Create `tests/test_env_config.py` with focused cases:

```python
from pathlib import Path

import pytest

from skill_importer.env_config import load_cli_api_key
from skill_importer.errors import ImporterError


def test_loads_primary_key_from_current_directory_env(tmp_path: Path) -> None:
    (tmp_path / ".env").write_text("FM_API_KEY=file-key\n", encoding="utf-8")
    assert load_cli_api_key(directory=tmp_path, environ={}) == "file-key"


def test_process_primary_overrides_file_without_legacy_fallback(tmp_path: Path) -> None:
    (tmp_path / ".env").write_text(
        "FM_API_KEY=file-key\nLLM_API_KEY=file-legacy\n", encoding="utf-8"
    )
    assert load_cli_api_key(directory=tmp_path, environ={"FM_API_KEY": ""}) == ""


def test_primary_file_key_beats_process_legacy_key(tmp_path: Path) -> None:
    (tmp_path / ".env").write_text("FM_API_KEY=file-key\n", encoding="utf-8")
    assert load_cli_api_key(directory=tmp_path, environ={"LLM_API_KEY": "legacy"}) == "file-key"


def test_missing_env_uses_process_legacy_fallback(tmp_path: Path) -> None:
    assert load_cli_api_key(directory=tmp_path, environ={"LLM_API_KEY": "legacy"}) == "legacy"


def test_env_inside_source_is_not_used_as_cli_configuration(tmp_path: Path) -> None:
    working_directory = tmp_path / "working"
    source = tmp_path / "source"
    working_directory.mkdir()
    source.mkdir()
    (source / ".env").write_text("FM_API_KEY=source-secret\n", encoding="utf-8")
    assert load_cli_api_key(directory=working_directory, environ={}) is None


def test_env_value_is_not_interpolated_or_exported(tmp_path: Path) -> None:
    (tmp_path / ".env").write_text(
        "OTHER=secret\nFM_API_KEY='${OTHER}'\n", encoding="utf-8"
    )
    environ: dict[str, str] = {}
    assert load_cli_api_key(directory=tmp_path, environ=environ) == "${OTHER}"
    assert environ == {}


def test_malformed_env_fails_without_echoing_secret(tmp_path: Path) -> None:
    secret = "secret-that-must-not-leak"
    (tmp_path / ".env").write_text(f"FM_API_KEY='{secret}\n", encoding="utf-8")
    with pytest.raises(ImporterError) as error:
        load_cli_api_key(directory=tmp_path, environ={})
    assert "INVALID_ENV_FILE" in str(error.value)
    assert secret not in str(error.value)
```

- [ ] **Step 2: Verify RED**

Run:

```bash
uv run pytest -q tests/test_env_config.py
```

Expected: collection fails because `skill_importer.env_config` does not exist.

- [ ] **Step 3: Implement the minimal strict parser**

Create `src/skill_importer/env_config.py` with these exact public semantics:

```python
from __future__ import annotations

import os
import re
import stat
from collections.abc import Mapping
from pathlib import Path

from .errors import ImporterError

_MAX_ENV_BYTES = 64 * 1024
_KEYS = ("FM_API_KEY", "LLM_API_KEY")
_NAME_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


def _invalid_env(line: int | None = None) -> ImporterError:
    suffix = "" if line is None else f" at line {line}"
    return ImporterError("INVALID_ENV_FILE", f".env is not valid configuration{suffix}")


def _parse_value(raw: str, line: int) -> str:
    value = raw.strip()
    if not value:
        return ""
    if value[0] in {"'", '"'}:
        quote = value[0]
        escaped = False
        closing = None
        for index, character in enumerate(value[1:], start=1):
            if escaped:
                escaped = False
            elif character == "\\" and quote == '"':
                escaped = True
            elif character == quote:
                closing = index
                break
        if closing is None or value[closing + 1 :].strip().lstrip("#").strip():
            raise _invalid_env(line)
        parsed = value[1:closing]
        if quote == '"':
            parsed = parsed.replace(r"\\\"", '"').replace(r"\\\\", "\\")
        return parsed
    comment = re.search(r"\s+#", value)
    return value[: comment.start()].rstrip() if comment is not None else value


def _file_values(path: Path) -> dict[str, str]:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return {}
    except OSError as exc:
        raise _invalid_env() from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise _invalid_env()
    if metadata.st_size > _MAX_ENV_BYTES:
        raise _invalid_env()
    try:
        text = path.read_bytes().decode("utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise _invalid_env() from exc
    if "\x00" in text:
        raise _invalid_env()
    result: dict[str, str] = {}
    for line_number, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line.removeprefix("export ").lstrip()
        if "=" not in line:
            raise _invalid_env(line_number)
        name, raw_value = line.split("=", 1)
        name = name.strip()
        if _NAME_RE.fullmatch(name) is None:
            raise _invalid_env(line_number)
        value = _parse_value(raw_value, line_number)
        if name in _KEYS:
            result[name] = value
    return result


def load_cli_api_key(
    *,
    directory: Path | None = None,
    environ: Mapping[str, str] | None = None,
) -> str | None:
    values = _file_values((directory or Path.cwd()) / ".env")
    process = os.environ if environ is None else environ
    for key in _KEYS:
        if key in process:
            values[key] = process[key]
    if "FM_API_KEY" in values:
        return values["FM_API_KEY"]
    return values.get("LLM_API_KEY")
```

- [ ] **Step 4: Verify GREEN and safety edges**

Run:

```bash
uv run pytest -q tests/test_env_config.py
uv run ruff check src/skill_importer/env_config.py tests/test_env_config.py
uv run mypy src
```

Expected: all commands exit 0.

- [ ] **Step 5: Add safe repository files**

Append to `.gitignore`:

```gitignore
.env
.env.*
!.env.example
```

Create tracked `.env.example`:

```dotenv
# Cloud.ru FM API key used only for statically ambiguous candidates.
FM_API_KEY=

# Optional compatibility fallback. Leave unset when FM_API_KEY is used.
LLM_API_KEY=
```

Create local `.env` with `FM_API_KEY=` and verify `git status --short` does not list it.

- [ ] **Step 6: Commit loader/config contract**

```bash
git add .gitignore .env.example src/skill_importer/env_config.py tests/test_env_config.py
git commit -m "feat: load FM key from local env file"
```

### Task 2: Wire both CLI operations to `.env`

**Files:**
- Modify: `src/skill_importer/cli.py`
- Modify: `tests/test_cli_e2e.py`

**Interfaces:**
- Consumes: `load_cli_api_key()` from Task 1.
- Produces: `_cli_pipeline() -> SkillImporterPipeline`; both commands use the same configured pipeline.

- [ ] **Step 1: Add failing command wiring tests**

Add tests that monkeypatch `cli_module.load_cli_api_key` with a counting provider, invoke real local
`scan --no-llm --json` and `import --no-llm`, and assert one eager load per command. Extend the
existing fake importer test so its constructor accepts `pipeline: SkillImporterPipeline` and
assert that a pipeline was supplied.

```python
def test_scan_and_import_initialize_cli_env_once_each(monkeypatch, runner, tmp_path):
    calls = 0
    def load_key():
        nonlocal calls
        calls += 1
        return "secret-not-rendered"
    monkeypatch.setattr(cli_module, "load_cli_api_key", load_key)
    source = tmp_path / "source"
    source.mkdir()
    write_tree(source, {"SKILL.md": _skill("env-wiring")})
    scan = runner.invoke(cli, ["scan", str(source), "--no-llm", "--json"])
    out = tmp_path / "out"
    imported = runner.invoke(
        cli, ["import", str(source), "--out", str(out), "--no-llm"]
    )
    assert scan.exit_code == 0
    assert imported.exit_code == 0
    assert calls == 2
    assert "secret-not-rendered" not in scan.output + imported.output
```

- [ ] **Step 2: Verify RED**

Run the new test and expect `AttributeError` because `cli_module.load_cli_api_key` is absent.

- [ ] **Step 3: Implement one CLI pipeline factory**

In `src/skill_importer/cli.py` import `load_cli_api_key` and add:

```python
def _cli_pipeline() -> SkillImporterPipeline:
    api_key = load_cli_api_key()
    return SkillImporterPipeline(api_key_provider=lambda: api_key)
```

Use `_cli_pipeline().scan(...)` in `scan_command`. Use
`SkillImporter(pipeline=_cli_pipeline()).import_source(...)` in `import_command`. Keep both calls
inside the existing `try/except ImporterError`, so invalid `.env` becomes safe Click stderr.

- [ ] **Step 4: Verify GREEN**

```bash
uv run pytest -q tests/test_cli_e2e.py tests/test_env_config.py
uv run ruff check src/skill_importer/cli.py tests/test_cli_e2e.py
uv run mypy src
```

Expected: exit 0 and no secret in output.

- [ ] **Step 5: Commit CLI wiring**

```bash
git add src/skill_importer/cli.py tests/test_cli_e2e.py
git commit -m "feat: use local env key in CLI"
```

### Task 3: Split and simplify documentation

**Files:**
- Rename: `docs/TECH_LEAD_IMPORTER_ALGORITHM.md` → `docs/INTERNAL_IMPLEMENTATION_REFERENCE.md`
- Create: `docs/TECH_LEAD_IMPORTER_ALGORITHM.md`
- Create: `docs/IMPORT_DECISION_ALGORITHM.md`
- Modify: `README.md`
- Modify: `AUDIT_AND_NEXT_STEPS.md`

**Interfaces:**
- Consumes: final CLI and classification contracts.
- Produces: three documents with non-overlapping audiences.

- [ ] **Step 1: Preserve the detailed reference**

Rename the current 600+ line document without changing its technical content. Update its title and
opening paragraph to state that it is an internal implementation reference, not the tech-lead
summary.

- [ ] **Step 2: Write the concise tech-lead brief**

Create a roughly one-page document with these exact sections:

```markdown
# Импорт самостоятельных skills из произвольного репозитория

## Задача
Repository может смешивать skills, marketplace, plugins, examples и обычный код. Importer должен
найти каждый skill отдельно и перенести только тот, который полезен без окружающего plugin.

## Что подаётся на вход
- local directory, Git/GitHub repository/tree/blob URL;
- optional ref и subpath;
- optional FM_API_KEY в `.env` текущей директории.

## Что возвращает scan
Таблица candidates: root, classification, причины/evidence, enclosing package, requirements,
duplicates/conflicts и итоговые counts. Source не изменяется.

## Что возвращает import
Новый output directory: payload каждого итогового portable skill и import-manifest.json с source
URL, commit SHA, original root и content hash. Rejected candidates не копируются.

## Краткая логика
Найти SKILL.md → определить plugin boundary → проверить зависимости наружу и ссылки plugin внутрь
→ отправить только ambiguous в FM → импортировать только portable.

## Пример
Показать repository с standalone, `${PLUGIN_ROOT}`-dependent и mixed ambiguous skills, затем scan
verdicts и import output только для подтверждённых portable.
```

Add a compact five-row classification table and a link to the decision algorithm.

- [ ] **Step 3: Write the standalone decision algorithm**

Create `docs/IMPORT_DECISION_ALGORITHM.md` in plain language with the six steps approved in the
design, a decision table, pseudocode and two examples. The pseudocode must end with:

```text
if final_classification == portable:
    copy only files inside skill_root
else:
    reject candidate and preserve reasons/evidence
```

- [ ] **Step 4: Update README configuration and links**

Replace the statement that dotenv is never loaded with:

```markdown
CLI автоматически читает `.env` только из текущей рабочей директории. Process environment
переопределяет одноимённые значения; `FM_API_KEY` остаётся primary, `LLM_API_KEY` — compatibility
fallback. `.env` внутри переданного source специально не ищется и никогда не исполняется.
```

Add setup commands:

```bash
cp .env.example .env
# заполнить FM_API_KEY в .env
uv run skill-importer scan https://github.com/openclaw/agent-skills
```

Update README and audit links to all three documents.

- [ ] **Step 5: Validate documentation structure**

```bash
rg -n "Что подаётся на вход|Что возвращает scan|Что возвращает import|Пример" \
  docs/TECH_LEAD_IMPORTER_ALGORITHM.md
rg -n "portable|plugin_bound|ambiguous|invalid|blocked" \
  docs/IMPORT_DECISION_ALGORITHM.md
rg -n "INTERNAL_IMPLEMENTATION_REFERENCE|IMPORT_DECISION_ALGORITHM" README.md
git diff --check
```

Expected: every required section/link is present and diff-check exits 0.

- [ ] **Step 6: Commit documentation split**

```bash
git add README.md AUDIT_AND_NEXT_STEPS.md docs
git commit -m "docs: split tech lead and importer decision guides"
```

### Task 4: Release verification and publication

**Files:**
- Verify all changed files; no new source changes unless a gate exposes a defect.

**Interfaces:**
- Consumes: Tasks 1–3.
- Produces: tested and published `main`.

- [ ] **Step 1: Run the full local gate**

```bash
uv run pytest -q
uv run ruff check .
uv run ruff format --check .
uv run mypy src
uv lock --check
git diff --check
git status --short
```

Expected: all commands exit 0; `.env` is absent from status.

- [ ] **Step 2: Run installed-wheel `.env` smoke**

Build wheel/sdist, install the wheel in a fresh Python 3.12 environment, create a temporary working
directory containing `.env` and an ambiguous fixture, inject a fake bounded FM transport in the
test harness, and verify the key reaches only the Authorization header and never output artifacts.
Also run ordinary installed CLI `scan --no-llm` to prove packaging contains `env_config.py`.

- [ ] **Step 3: Review the final diff**

Review `origin/main...HEAD` for secrets, accidental `.env` staging, source-repository env lookup,
CLI key leakage and broken document links. Any Critical/Important finding returns to the relevant
TDD task.

- [ ] **Step 4: Push and verify remote**

```bash
git push origin main
git ls-remote origin refs/heads/main
git rev-parse HEAD
```

Expected: remote and local SHA match exactly.
