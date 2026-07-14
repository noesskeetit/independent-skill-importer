# План реализации package-aware skill importer

> **Для agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Цель:** Точно извлекать самостоятельные skills из repository/marketplace/plugin layouts, не смешивая package autonomy с runtime security checking.

**Архитектура:** Inventory-only resolver определяет только package dependencies и plugin ownership. Host runtime inputs/outputs не участвуют в verdict; безопасностью содержимого занимается отдельный skill checker.

**Стек:** Python 3.12 standard library, существующие immutable models, pytest, Ruff, strict mypy, uv/hatchling.

## Общие ограничения

- Никогда не исполнять repository code, не устанавливать dependencies и не инициализировать submodules.
- Никогда не читать referenced host path и не копировать файлы за пределами skill root.
- Импортируются только `portable`; остальные classifications остаются non-importable.
- `blocked` используется для unsafe extraction mechanics: source/archive traversal, symlink escape, collisions и limits.
- Runtime host paths и опасность кода не оцениваются importer-ом.
- FM проверяет только автономность относительно enclosing plugin.
- Tests/fixtures сохраняются в inventory и import payload.

---

### Task 1: Inventory coordinate-system resolver

**Статус:** реализовано и прошло отдельный review.

**Файлы:**
- `src/skill_importer/static_analysis.py`
- `tests/test_static_analysis.py`

**Контракт:** `_resolve_local_reference(...)` использует только inventory и
precedence entry → candidate → repository. Existing target снаружи skill root
не включается в payload.

### Task 2: Package-aware context extraction

**Файлы:**
- Modify: `src/skill_importer/static_analysis.py`
- Test: `tests/test_static_analysis.py`
- Test: `tests/test_acceptance_fixtures.py`

**Интерфейсы:**
- `_PathReference(value, offset, access, syntax)` описывает доказанный package context.
- Resolver из Task 1 остаётся единственным способом найти target.

- [ ] **Step 1: Зафиксировать границу importer vs checker в RED tests**

Проверить, что `/tmp/output`, `/etc/passwd`, home/Windows paths, dynamic user
inputs и write destinations не меняют portability. При этом source/archive
traversal и symlink escape в inventory/import tests остаются blocked.

- [ ] **Step 2: Сохранить реальные package dependency controls**

Проверить relative imports, Markdown resource links, relative executable paths,
`${PLUGIN_ROOT}`, plugin-owned modules/components и reverse runtime references.
Existing target снаружи root остаётся `plugin_bound`; inert fixture text не
создаёт finding.

- [ ] **Step 3: Реализовать package-only downstream policy**

Игнорировать absolute/dynamic runtime I/O и `access=write`. Анализировать
relative file/API operand только когда он разрешается в inventory или является
доказанным resource/import/executable context. Не делать raw-all-text fallback.

- [ ] **Step 4: Проверить и закоммитить**

Run:

```bash
uv run pytest tests/test_static_analysis.py tests/test_acceptance_fixtures.py -q
uv run ruff check src/skill_importer/static_analysis.py tests/test_static_analysis.py
uv run mypy src
```

Expected: PASS, затем отдельный task review.

### Task 3: Real-world benchmark из 10 pinned cases

**Файлы:**
- Create: `benchmarks/real_world/cases.json`
- Create: `benchmarks/real_world/run.py`
- Create: `benchmarks/real_world/README.md`
- Create: `tests/test_real_world_benchmark.py`

**Интерфейсы:**
- Manifest хранит source URL, immutable commit SHA, optional subpath, manual
  expected candidates/classifications/reason codes и provenance ссылки.
- Runner вызывает только public scan API и никогда не исполняет source code.

- [ ] **Step 1: Исследовать и вручную разметить 10 cases**

Использовать primary public GitHub sources из OpenAI/Codex, Claude Code official
marketplace/plugins, OpenClaw и соседних agent-skill ecosystems. Покрыть
standalone, monorepo, skills-only plugin, mixed plugin, explicit plugin-bound,
reverse dependency, duplicate layout и сложный ambiguous case.

- [ ] **Step 2: Реализовать manifest validation и runner**

Одна команда создаёт JSON и Markdown summary: resolved SHA, candidates, actual
verdict, expected verdict, agreement, reason-code match, scan duration и error.
Обычный pytest использует mocked/offline scan; online corpus запускается явно.

- [ ] **Step 3: Прогнать pinned corpus**

Ни один case не использует mutable branch label. Зафиксировать фактические
расхождения как benchmark result, а не подгонять manual labels под scanner.

### Task 4: Tech-lead document и closeout

**Файлы:**
- Create: `docs/TECH_LEAD_IMPORTER_ALGORITHM.md`
- Modify: `README.md`
- Modify: `AUDIT_AND_NEXT_STEPS.md`

- [ ] **Step 1: Написать русскоязычный code-grounded документ**

Описать проблему и pipeline `SourceResolver → RepositoryInventory →
PackageBoundaryDetector → SkillCandidateDiscoverer → SkillValidator →
PortabilityAnalyzer → optional FM → ImportPlan → SkillImporter`, identity,
provenance, dedupe/conflicts, reason/evidence, atomic import, extraction limits,
Mermaid-схему, JSON example, portable/rejected cases и production next steps.
Явно отделить importer от skill checker.

- [ ] **Step 2: Полный gate**

Run:

```bash
uv run pytest -q
uv run ruff check .
uv run mypy src
uv lock --check
uv build
```

- [ ] **Step 3: Installed-wheel и live proof**

Установить wheel в свежий Python 3.12 env, выполнить scan→import standalone
fixture и pinned GitHub cases. `.env` не читать и не менять.

- [ ] **Step 4: Final review и публикация**

Провести независимый whole-branch review. Только после clean verdict и всех
зелёных gates интегрировать feature branch и push `main` в origin.
