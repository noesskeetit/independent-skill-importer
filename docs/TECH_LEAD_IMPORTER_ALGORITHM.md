# Импорт самостоятельных skills из произвольного репозитория

## Задача

В одном репозитории могут одновременно лежать самостоятельные skills, marketplace, skillset,
плагины Claude/Codex/OpenClaw, примеры и обычный код. Импортер не устанавливает репозиторий целиком:
он находит каждый каталог с `SKILL.md` отдельно и переносит только skill, полезный без окружающего
plugin runtime.

## Что подаётся на вход

- локальная директория, Git URL или GitHub repository/tree/blob URL;
- при необходимости `--ref` и `--subpath`;
- для дополнительной проверки спорных кандидатов — `FM_API_KEY` в `.env` папки, из которой
  запускается CLI.

```bash
uv run skill-importer scan https://github.com/acme/skills-repo --json
uv run skill-importer import https://github.com/acme/skills-repo --out ./imported
```

Remote ref всегда резолвится в конкретный commit SHA. Код, hooks, MCP, scripts и dependencies из
репозитория во время анализа не запускаются.

## Что возвращает `scan`

`scan` ничего не импортирует и не изменяет source. Он возвращает preview:

- все найденные skill roots;
- classification каждого кандидата;
- machine-readable reasons и evidence с путём/строкой/значением;
- enclosing plugin/package и внешние требования;
- группы дубликатов и конфликтов имён;
- итоговые counts.

| Classification | Решение |
|---|---|
| `portable` | Skill самодостаточен, автоматический import разрешён. |
| `plugin_bound` | Skill зависит от компонента enclosing plugin или используется его runtime. |
| `ambiguous` | Статика не доказала автономность; можно проверить только этот кандидат через FM. |
| `invalid` | Некорректный entrypoint/frontmatter. |
| `blocked` | Небезопасный путь, traversal, symlink escape или другой extraction blocker. |

## Что возвращает `import`

`import` заново выполняет scan и атомарно создаёт новый output directory. В нём находятся:

- полные каталоги только итоговых `portable` skills;
- `import-manifest.json` с source URL, commit SHA, original root, content hash и provenance;
- сведения об отклонённых candidates без копирования их payload.

`plugin_bound`, оставшиеся `ambiguous`, `invalid` и `blocked` не импортируются. Импортер не
подтягивает файлы из plugin root и не переписывает `SKILL.md`, чтобы искусственно «починить» skill.

## Краткая логика

```text
найти SKILL.md/skill.md
→ определить root каждого skill и enclosing plugin boundary
→ проверить ссылки skill наружу и ссылки plugin runtime на skill
→ классифицировать очевидные случаи статически
→ отправить в FM только ambiguous (если ключ настроен)
→ импортировать только final portable и только файлы внутри skill root
```

Подробное человеческое дерево решений: [IMPORT_DECISION_ALGORITHM.md](IMPORT_DECISION_ALGORITHM.md).

## Пример

На вход передан смешанный репозиторий:

```text
repo/
├── standalone/SKILL.md
├── plugin/
│   ├── plugin.json
│   ├── scripts/tool.py
│   └── skills/internal/SKILL.md   # запускает ${PLUGIN_ROOT}/scripts/tool.py
└── mixed/
    ├── plugin.json
    ├── src/runtime.py
    └── skills/reviewer/SKILL.md   # явной связи с runtime не найдено
```

Сокращённый результат `scan`:

```json
{
  "skills": [
    {"root": "standalone", "classification": "portable", "reasons": ["STANDALONE_NO_PLUGIN_BOUNDARY"]},
    {"root": "plugin/skills/internal", "classification": "plugin_bound", "reasons": ["PLUGIN_ROOT_VARIABLE"]},
    {"root": "mixed/skills/reviewer", "classification": "ambiguous", "reasons": ["MIXED_PLUGIN_AUTONOMY_UNPROVEN"]}
  ],
  "counts": {"total": 3, "portable": 1, "plugin_bound": 1, "ambiguous": 1}
}
```

FM вызывается только для `mixed/skills/reviewer`. Если FM подтверждает автономность, итоговый
`import` создаст, например:

```text
imported/
├── standalone--<content-hash>/
│   └── SKILL.md
├── reviewer--<content-hash>/
│   └── SKILL.md
└── import-manifest.json
```

`plugin/skills/internal` не попадёт в output: без `${PLUGIN_ROOT}/scripts/tool.py` он бесполезен,
а переносить plugin runtime внутрь skill — не задача импортера.

## Граница ответственности

Инструмент отвечает за автономность package и безопасное извлечение. Проверку того, опасны ли
команды уже самостоятельного skill, выполняет отдельный skill checker платформы.
