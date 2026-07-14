# Аудит и следующие функциональные правки

## Статус POC

Репозиторий содержит Python 3.12 POC универсального импортера самостоятельных agent skills. Он
не исполняет код источника, не устанавливает dependencies и не запускает plugin runtime, MCP,
hooks или submodules. Архитектурный контракт зафиксирован в
[`docs/TECH_LEAD_IMPORTER_ALGORITHM.md`](docs/TECH_LEAD_IMPORTER_ALGORITHM.md).

После исходного targeted review реализована отдельная серия функциональных исправлений анализа
реальных repository layouts и добавлен pinned corpus из десяти GitHub cases. Это не означает
production readiness. Пользователь намеренно отложил **единый финальный combined audit** до
завершения feature branch: его нужно выполнить заново на точном commit, который будет
интегрирован и опубликован.

Отдельные task-level pytest/Ruff/mypy проверки не заменяют этот gate, installed-wheel smoke,
online corpus и независимый whole-branch security review.

## Что уже исправлено после исходного аудита

Исторический scan `openclaw/agent-skills` на commit
`4887c1d540febb1f55140e96da7e4aae3e5163ba` находил шесть candidates, пять из которых получили
`blocked`; разбор evidence выявил false-positive path findings. Этот result был диагностическим
baseline, а не manual oracle и не актуальный verdict.

По найденным проблемам реализовано:

1. **Repository-root-relative references.** Resolver package paths использует immutable inventory
   и проверяет entry-relative, candidate-root-relative и exact repository-root-relative
   coordinates. Путь с уже указанным `skills/<name>/...` больше не прибавляется к skill root
   автоматически.
2. **Raw source coordinates.** Evidence сохраняет исходное найденное значение и source offset,
   а decoding/normalization выполняется отдельно для resolution. Это предотвращает неверные line
   и matched-value после percent decoding.
3. **Package-aware contexts.** Python, JavaScript/TypeScript, shell, Markdown и structured config
   анализируются по роли read/import/write и синтаксическому context. Inert comments, strings,
   fixture snippets, heredocs, unknown Markdown fences и generated/write outputs не становятся
   package dependency только из-за похожего path literal.
4. **Граница importer vs checker.** Absolute/dynamic host runtime inputs и outputs не считаются
   package dependency и не читаются importer-ом. Source/archive traversal, path collision и
   escaping symlink остаются fail-closed extraction findings/errors.
5. **Plugin ownership.** Сохранились detectors реальных forward/reverse links: plugin-root
   variables, resource/import paths за skill root, owned MCP/commands/agents/hooks/providers,
   runtime modules/binaries, outer plugin ownership и runtime orchestration references.
6. **Markdown reference parsing.** Обрабатываются inline/reference-style links, multiline
   definitions, code spans/fences и development sections без raw-all-text fallback.
7. **Bounded findings.** Static reason collector сохраняет не более 64 уникальных evidence records
   на reason code. Отдельных counters для отброшенных повторов пока нет; это остаётся production
   observability backlog.
8. **Static path composition.** Bounded propagation распознаёт consumed Python paths от
   `Path(__file__)`, `parents[N]`, `/`, `joinpath()` и JavaScript `path.join(__dirname, ...)`, не
   исполняя source code. Активный plugin-root literal через `expandvars`/subprocess больше не
   скрывается как fixture string.
9. **Extraction aliases.** Local snapshot консервативно отклоняет regular files с hardlink count,
   отличным от одного, до публикации payload. Root-level OpenClaw extension declaration сохраняет
   mixed package и не позволяет выдать plugin runtime за skill payload.
10. **Markdown fail-closed contexts.** Explicit parent traversal и plugin-root variables не
    скрываются заголовками Development/Tests/Validate; dev-only bare validator commands и
    доказанные write/destination examples по-прежнему не считаются runtime dependency.

Регрессии закреплены focused tests в `tests/test_static_analysis.py` и acceptance fixtures. Реальный
corpus хранится отдельно и не подменяет unit/fixture coverage.

## Real-world benchmark

[`benchmarks/real_world/cases.json`](benchmarks/real_world/cases.json) содержит ровно десять manual
cases, pinned на full commit SHA. Они покрывают GitHub blob-parent scope, monorepo, skills-only и
mixed plugins, forward/reverse dependency, standalone skill вне plugin boundary, scale/invalid
case, duplicate layout и complex ambiguous candidates.

Runner вызывает только public `SkillImporterPipeline.scan()`, не исполняет source content и не
изменяет manual labels. Offline tests используют injected fake scan:

```bash
uv run pytest -q tests/test_real_world_benchmark.py
```

Последний полный online static corpus дал **9/9 source/semantic matches, 1/1 expected operational
guard и 0 disagreements**. Повторяемая команда:

```bash
uv run python benchmarks/real_world/run.py \
  --online \
  --manifest benchmarks/real_world/cases.json \
  --json-out .artifacts/real-world-benchmark.json \
  --markdown-out .artifacts/real-world-benchmark.md
```

OpenClaw scale case честно ожидает текущий operational `SCAN_LIMIT_EXCEEDED`; его semantic oracle
для будущего selective inventory хранится отдельно в том же manifest. Runner не меняет этот label,
если поведение resolver-а изменится.

## Что проверить при возобновлении combined audit

1. Зафиксировать точный commit и убедиться, что worktree/index чистые.
2. Выполнить `pytest`, Ruff, strict mypy, `uv lock --check`, wheel/sdist build и installed-wheel
   CLI smoke в свежем Python 3.12 environment.
3. Повторить security review source resolver, static analyzer, FM context и atomic publisher уже
   на финальном commit.
4. Выполнить offline acceptance suite и explicit online pinned corpus; сохранить JSON/Markdown
   artifacts, resolved SHA, duration и все disagreements без автоматической правки labels.
5. Отдельно запустить FM lane только для static `ambiguous`; redaction, truncation, missing key,
   invalid evidence или transport failure не должны повышать verdict до `portable`.
6. Выполнить standalone fixture scan→import installed-wheel smoke и проверить exact payload,
   manifest provenance, duplicate/name-conflict behavior и no-clobber failure path.
7. Подтвердить, что API key/credentials не попадают в Git subprocess, ScanReport, import manifest,
   logs и error messages; `.env` не читается и не изменяется.
8. Провести независимый whole-branch review; интегрировать/push только после clean verdict.

## Оставшиеся production-задачи

- quota-controlled Git fetch с disk/network isolation: archive cap не ограничивает exact incoming
  pack bytes до завершения fetch;
- server-side egress allowlist, DNS/IP/SSRF controls и credential broker для private Git;
- versioned plugin-schema/language adapters и новые pinned regressions по мере эволюции ecosystems;
- versioned FM prompt/model policy, evals, telemetry и drift gates;
- transactional registry/object-storage adapter с теми же provenance/no-clobber invariants;
- publishers для дополнительных platforms/filesystems;
- private importer-owned staging parent и audited residual sweeper;
- отдельный post-import skill checker для malicious/destructive behavior и execution permissions;
- optional evidence suppression counters без расширения unbounded report.

## Неизменяемые принципы следующих итераций

- Не расширять проект до plugin importer и не конвертировать plugin runtime в skill.
- `portable` остаётся разрешением только при доказанной самодостаточности.
- `plugin_bound`, `ambiguous`, `invalid` и `blocked` не импортируются.
- Если skill требует часть plugin, его нужно отклонить с reason/evidence, а не «починить» скрытым
  копированием внешних files.
- Новые detectors сначала получают fixture/focused test, затем regression на pinned real source.
- API key передаётся только через process environment (`FM_API_KEY`, либо `LLM_API_KEY` fallback)
  в момент FM review; `.env` не читается и не изменяется.
- Runtime security checking остаётся отдельной подсистемой после package-autonomy import decision.
