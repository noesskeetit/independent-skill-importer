# Как понять, какой skill можно импортировать из репозитория

Главное правило: **репозиторий не считается одним skill или одним plugin**. Сначала разбираются все
найденные skills по отдельности. Даже внутри plugin часть skills может быть самостоятельной, а
часть — внутренними компонентами runtime.

## Алгоритм

### 1. Найти кандидатов

Рекурсивно найти все `SKILL.md` и совместимые `skill.md`. Директория, где лежит такой файл, —
`skill_root`. Путь не обязан выглядеть как `skills/*`.

Если entrypoint не найден, результат нормальный: импортировать из этого репозитория нечего.

### 2. Найти окружающий package

По plugin manifests определяется ближайшая enclosing plugin boundary. Manifest нужен только для
понимания границы: сам plugin никогда не импортируется и не запускается.

Отсутствие plugin boundary — хороший сигнал автономности. `skills-only` plugin также допустим,
если каждый skill использует только файлы внутри собственного root.

### 3. Проверить, зависит ли skill от plugin

Ищутся forward dependencies — всё, без чего инструкции skill не работают:

- ссылка на `../shared/...` или другой файл вне `skill_root`;
- `${PLUGIN_ROOT}`, `${CLAUDE_PLUGIN_ROOT}`, `extensionPath` и аналоги;
- запуск script/binary/server из plugin root;
- использование MCP tool, command, agent, hook или provider, поставляемого этим plugin;
- symlink, выходящий за root;
- отсутствующий или динамически вычисляемый локальный ресурс.

Зависимость от обычной внешней утилиты (`git`, `gh`, `docker`) не привязывает skill к plugin. Она
записывается как `externalRequirements`.

### 4. Проверить обратную зависимость

Затем анализируется plugin runtime, но он не исполняется. Если hook, command, agent, MCP/runtime
code или config явно читает этот skill, его prompt/resources либо использует его в orchestration
flow, skill считается внутренним компонентом plugin.

README, changelog и обычная документация не являются runtime dependency.

### 5. Вынести статическое решение

| Что найдено | Classification | Импорт |
|---|---|---|
| Plugin boundary нет, все локальные ресурсы внутри root | `portable` | Да |
| Skills-only package, plugin dependencies нет | `portable` | Да |
| Есть forward или reverse dependency от plugin | `plugin_bound` | Нет |
| Mixed plugin есть, но автономность ни доказана, ни опровергнута | `ambiguous` | Пока нет |
| Broken frontmatter | `invalid` | Нет |
| Traversal или symlink escape | `blocked` | Нет |

Каждый verdict содержит reason codes и evidence: файл, поле/строку и найденное значение.

### 6. При необходимости проверить только `ambiguous` через FM

FM получает ограниченное статическое dossier кандидата и отвечает, доказана ли автономность.
Очевидные `portable`, `plugin_bound`, `invalid` и `blocked` через FM не прогоняются. Если FM
недоступна, не уверена или вернула некорректный ответ, candidate остаётся `ambiguous` и не
импортируется.

### 7. Скопировать только разрешённый root

```text
for each directory containing SKILL.md or skill.md:
    validate candidate
    find enclosing plugin boundary
    analyze forward dependencies from skill to plugin
    analyze reverse dependencies from plugin runtime to skill
    classify statically
    if classification == ambiguous and FM review is enabled:
        request bounded FM decision

    if final_classification == portable:
        copy only files inside skill_root
    else:
        reject candidate and preserve reasons/evidence
```

## Два коротких примера

Самостоятельный skill:

```text
repo/translate/
├── SKILL.md
├── scripts/translate.py
└── references/formats.md
```

Все нужные файлы находятся внутри `translate/`, plugin boundary нет. Результат: `portable`, весь
каталог `translate/` можно импортировать.

Внутренний skill плагина:

```text
repo/
├── plugin.json
├── scripts/tool.py
└── skills/run-tool/SKILL.md  # «запусти ${PLUGIN_ROOT}/scripts/tool.py»
```

Entry point найден, но skill требует script за пределами своего root и переменную plugin runtime.
Результат: `plugin_bound` с `PLUGIN_ROOT_VARIABLE`/`REFERENCE_OUTSIDE_SKILL_ROOT`; импорт запрещён.
