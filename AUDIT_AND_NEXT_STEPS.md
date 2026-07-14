# Аудит и следующие функциональные правки

## Статус POC

Репозиторий содержит Python 3.12 POC универсального импортера самостоятельных agent skills. Он
не исполняет код источника, не устанавливает dependencies и не запускает plugin runtime, MCP,
hooks или submodules. Короткий контракт для техлида зафиксирован в
[`docs/TECH_LEAD_IMPORTER_ALGORITHM.md`](docs/TECH_LEAD_IMPORTER_ALGORITHM.md), дерево решений — в
[`docs/IMPORT_DECISION_ALGORITHM.md`](docs/IMPORT_DECISION_ALGORITHM.md), подробности реализации —
в [`docs/INTERNAL_IMPLEMENTATION_REFERENCE.md`](docs/INTERNAL_IMPLEMENTATION_REFERENCE.md).

После исходного targeted review реализована отдельная серия функциональных исправлений анализа
реальных repository layouts и добавлен pinned corpus из десяти GitHub cases. Независимые scoped
re-audits уже прошли по source resolver/ref routing, static/boundary analysis и atomic staging
integrity. Найденные ими fail-open и TOCTOU-adjacent cases закрыты regression-тестами в текущей
feature branch. Это не означает production readiness и не заменяет финальный whole-branch review на
точном release commit: ограничения и gate ниже остаются явными.

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
   fixture snippets, quoted heredocs, unknown Markdown fences и generated/write outputs не
   становятся package dependency только из-за похожего path literal; unquoted heredoc сохраняет
   shell expansion и анализируется.
4. **Граница importer vs checker.** Absolute/dynamic host runtime inputs и outputs не считаются
   package dependency и не читаются importer-ом. Source/archive traversal, path collision и
   escaping symlink остаются fail-closed extraction findings/errors.
5. **Plugin ownership.** Сохранились detectors реальных forward/reverse links: plugin-root
   variables, resource/import paths за skill root, owned MCP/commands/agents/hooks/providers,
   runtime modules/binaries, outer plugin ownership и runtime orchestration references.
6. **Markdown reference parsing.** Обрабатываются inline/reference-style links, multiline
   definitions, code spans/fences и development sections без raw-all-text fallback.
7. **Bounded findings.** Static reason collector сохраняет не более 64 уникальных evidence records
   на reason code, поэтому report остаётся ограниченным по размеру.
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
11. **Adversarial path consumers.** `exec`, static shell variables, Python `system`/`run_path`,
    JavaScript `spawn`, bare Markdown actions и structured JSON/YAML/TOML/INI path fields больше не
    позволяют вынести runtime dependency за пределы skill root незамеченной.
12. **Resolver и publication hardening.** GitHub tree/blob URL принимает full commit SHA без
    обязательного `--ref`; route-derived blob target после extraction обязан существовать как exact
    regular file без symlink ancestors. Candidate count ограничен. Перед atomic publish staging
    заново сверяется с creation ledger: full child set и identities, exact symlink targets,
    directory modes, а для files — mode, size и SHA-256 перечитанных bytes. Directory symlink graph
    проверяется на cycles и static analyzer-ом, и защитно перед copy.
13. **Package boundaries.** CONTRIBUTING/SECURITY/CODE_OF_CONDUCT/ARCHITECTURE, repository config и
    metadata-only `package.json` не превращают skills-only package в mixed, тогда как runtime или
    scripts declarations по-прежнему делают его mixed.
14. **Residual static uncertainty.** Active literal/dataflow за пределы skill root, который нельзя
    надёжно квалифицировать language-specific detector-ом, больше не остаётся false-portable. Он
    получает `STATIC_ANALYSIS_INCOMPLETE`, static classification `ambiguous` и попадает в обычную
    FM-review lane; unavailable/invalid FM оставляет import запрещённым. Literal/expression/depth
    limits сами дают incomplete verdict. Ruby adapter покрывает assignment, `+`, `File.join`, calls
    с/без скобок, line-anchored `=begin`/`=end` и не доверяет unqualified write-like functions.
15. **Zero-candidate repositories.** Repository без skills — валидный scan/import: preview имеет
    нулевые counts, import публикует только пустой manifest. Отдельный subprocess E2E фиксирует этот
    контракт.

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

Post-fix online corpus повторён на implementation checkpoint
`87cfb513d1ad40d891e2b666ddb01cca4142cc0f`: **9/9 source/semantic matches, 1/1 expected
operational guard, 0 disagreements**. Повторяемая команда:

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

## Пройденные независимые scoped-аудиты

- **Source resolver и GitHub ref routing.** Независимый review перепроверил full-SHA tree/blob URL,
  slash refs, explicit `--ref`, ambiguous routes и exact blob target validation. Critical/Important
  findings после исправлений не осталось.
- **Atomic importer integrity.** Независимый review перепроверил no-clobber publication, mutation
  file bytes/mode, directory mode, child-set ledger, cleanup identity и directory symlink graph.
  Critical/Important/Moderate findings после исправлений не осталось.
- **Static/boundary analysis.** Независимый re-audit нашёл residual alias/dataflow bypasses; они
  закрыты общим `STATIC_ANALYSIS_INCOMPLETE -> ambiguous -> FM review` fallback и focused tests.
  Повторный adversarial review воспроизвёл compound paths, Ruby bare consumers и evaluator limits
  уже как fail-closed; итоговый scoped verdict — `Ready: YES`, Critical/Important не осталось.

На том же implementation checkpoint выполнены `993 passed`, Ruff, format, strict mypy,
`uv lock --check` и `git diff --check`. Wheel/sdist собраны; wheel установлен в чистый Python
3.12.12 environment, installed CLI успешно выполнил scan→import exact fixture payload. Live static
scan `openclaw/agent-skills` resolved commit
`8184e2b5f10cdaac636b6d18aa01ee8abfed3bb4` и нашёл 6/6 `portable` candidates.

## Финальный gate перед публикацией

1. Зафиксировать финальный commit и убедиться, что worktree/index чистые.
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
   logs и error messages; CLI читает только локальный `.env` из своей current working directory.
8. Провести независимый whole-branch review; интегрировать/push только после clean verdict.

## Оставшиеся production-задачи

- quota-controlled Git fetch с disk/network isolation: archive cap не ограничивает exact incoming
  pack bytes до завершения fetch;
- safe immutable-SHA fast path для GitHub tree/blob routes без обязательного полного
  `ls-remote`, сохраняющий disambiguation SHA-похожих branch/tag names;
- pre-index/cache для static и reverse analysis: текущий worst case —
  `O(candidates * runtime files)`;
- server-side egress allowlist, DNS/IP/SSRF controls и credential broker для private Git;
- versioned plugin-schema/language adapters и новые pinned regressions по мере эволюции ecosystems;
- versioned FM prompt/model policy, evals, telemetry и drift gates;
- transactional registry/object-storage adapter с теми же provenance/no-clobber invariants;
- publishers для дополнительных platforms/filesystems;
- private importer-owned staging parent и audited residual sweeper: ledger обнаруживает многие
  вмешательства, но не устраняет финальный same-UID pathname-check TOCTOU;
- отдельный post-import skill checker для malicious/destructive behavior и execution permissions;

## Неизменяемые принципы следующих итераций

- Не расширять проект до plugin importer и не конвертировать plugin runtime в skill.
- `portable` остаётся разрешением только при доказанной самодостаточности.
- `plugin_bound`, `ambiguous`, `invalid` и `blocked` не импортируются.
- Если skill требует часть plugin, его нужно отклонить с reason/evidence, а не «починить» скрытым
  копированием внешних files.
- Новые detectors сначала получают fixture/focused test, затем regression на pinned real source.
- CLI загружает `FM_API_KEY` из локального `.env` текущей директории; source-repository `.env` не
  используется как конфигурация. Ключ не должен попадать в reports, manifests или logs.
- Runtime security checking остаётся отдельной подсистемой после package-autonomy import decision.
