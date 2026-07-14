# Аудит и следующие функциональные правки

## Статус POC

Этот репозиторий содержит Python 3.12 POC универсального импортера самостоятельных
agent skills. Он не исполняет код источника, не устанавливает зависимости и не
запускает plugin runtime, MCP, hooks или submodules.

На момент публикации завершён targeted review статического анализа, ownership
plugin runtime и FM review scope. Пользователь намеренно поставил **combined
финальный аудит** на паузу: перед production-использованием его нужно запустить
заново на опубликованном commit.

## Что проверить при возобновлении аудита

1. Выполнить полный combined gate: `pytest`, Ruff, strict mypy, lock check,
   wheel/sdist build и installed-wheel CLI smoke.
2. Повторить security review source resolver, static analyzer, FM context и
   atomic publisher уже на commit, опубликованном в этом репозитории.
3. Прогнать corpus реальных GitHub repositories, сохраняя SHA, ScanReport и
   ручной verdict для каждого classification.
4. Проверить FM-review только на `ambiguous` candidates; redaction, truncation
   или неполный runtime scope никогда не должны повышать verdict до `portable`.
5. Подтвердить, что секреты не попадают в Git subprocess, ScanReport,
   import manifest, logs и error messages.

## Regression corpus: `openclaw/agent-skills`

Статический scan GitHub source
`https://github.com/openclaw/agent-skills` на commit
`4887c1d540febb1f55140e96da7e4aae3e5163ba` нашёл шесть candidates:

- `skills/behavior-validator` — `portable`;
- пять остальных были `blocked`.

Этот результат нельзя считать готовым решением для импорта всего repository.
Evidence выявил нужные функциональные улучшения POC:

1. **Repository-root-relative references.** Путь вида
   `skills/session-viewer/scripts/session-viewer.ts`, записанный внутри
   `skills/session-viewer/SKILL.md`, сейчас может быть повторно прибавлен к
   skill root. Нужно различать skill-relative и repository-root-relative
   literal paths без ослабления traversal checks.
2. **Test and fixture content.** Static forward analysis не должен принимать
   тестовые строки, generated fixture paths и regex/CSS fragments за runtime
   dependency. При этом `tests/` остаётся обычным payload и по-прежнему
   копируется при разрешённом import.
3. **Host temporary outputs.** `/tmp/...` и аналогичные output paths сейчас
   блокируются как `PATH_TRAVERSAL`. Нужно разделить чтение непроверенного
   host resource и явный temporary output workflow; второй случай должен
   давать прозрачное requirement/ambiguous verdict, но не неявный import.
4. **Dynamic path syntax.** Format strings, glob patterns и shell/JSON
   snippets требуют language/context-aware parsing. Неизвестная динамика
   остаётся fail-closed, но нельзя классифицировать как dependency простой
   тестовый литерал.
5. **Bounded evidence.** Для больших skills report должен сохранять
   representative evidence и counters, а не раздуваться тысячами почти
   одинаковых findings.

## Принципы для следующих итераций

- Не расширять проект до plugin importer и не конвертировать plugin runtime в
  skill.
- `portable` остаётся разрешением только при доказанной самодостаточности.
- `plugin_bound`, `ambiguous`, `invalid` и `blocked` не импортируются.
- Новые detectors сначала получают fixture, затем regression test на реальном
  repository snapshot с зафиксированным SHA.
- API key передаётся только через process environment в момент FM review;
  `.env` не читается и не изменяется.
