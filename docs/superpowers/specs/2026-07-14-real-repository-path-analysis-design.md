# Дизайн анализа package-зависимостей в реальных репозиториях

## Проблема

Importer должен находить skills в произвольном repository/marketplace/plugin
layout и решать, можно ли скопировать конкретный skill root без окружающего
plugin package. Он не является анализатором вредоносности skill: это отдельная
фича skill checker.

Текущий POC смешивает package dependency с runtime I/O. Любая строка со слэшем
может стать `MISSING_LOCAL_RESOURCE`, `DYNAMIC_REFERENCE_UNRESOLVED` или
`PATH_TRAVERSAL`: CSS, regex, test fixture, пользовательский input path и
`/tmp` output ошибочно влияют на импортируемость.

## Граница ответственности

Importer анализирует только:

- находится ли требуемый package-файл внутри skill root;
- ссылается ли skill на файл или компонент enclosing plugin;
- использует ли plugin runtime этот skill;
- можно ли безопасно извлечь inventory и атомарно скопировать только skill root.

Importer не оценивает shell-команды, доступ к host-файлам, утечки секретов и
вредоносность runtime-кода. Абсолютные host paths, runtime inputs и outputs не
являются package dependency и не меняют portability verdict. Skill checker
проверяет их после импорта отдельным процессом.

## Алгоритм

1. Inventory остаётся единственным источником истины: analyzer не читает host
   filesystem и не исполняет repository code.
2. Текст классифицируется по роли: `SKILL.md`, source, structured config или
   opaque asset. Tests остаются в payload, но fixture-текст не становится
   dependency автоматически.
3. Extractor ищет только package-bearing contexts:
   Markdown resource links, relative imports, relative executable/module paths,
   plugin-root variables и ссылки на plugin-owned components. Runtime file API
   с absolute/dynamic user data и write destinations игнорируется.
4. Relative reference разрешается по immutable inventory в порядке:
   entry-relative, candidate-root-relative, exact repository-root-relative.
5. Existing target внутри skill root автономен. Existing target снаружи даёт
   `REFERENCE_OUTSIDE_SKILL_ROOT`; plugin-owned target получает дополнительный
   specific reason. Missing path считается dependency только в доказанном
   package context.
6. Static uncertainty о связи с mixed plugin остаётся `ambiguous` и может быть
   дополнительно проверена FM. FM не используется как malware checker.

## Безопасность самого импортера

`blocked` относится к механике извлечения: unsafe archive/source path,
symlink escape из skill root, path collision и scan/file limits. Runtime-текст
вроде `cat /etc/passwd` не является importer finding и не заставляет importer
читать или копировать этот путь.

## Не делаем

- plugin importer;
- перенос plugin runtime внутрь skill;
- автоматическое исправление несамостоятельного skill;
- security/malware verdict содержимого skill;
- исполнение scripts, hooks, MCP, commands или dependency installation.

## Проверка

Нужны focused RED/GREEN tests, полный pytest, Ruff, strict mypy, package build,
installed-wheel smoke и real-world benchmark из десяти pinned cases. Manual
labels benchmark оценивают standalone/plugin-bound/ambiguous detection, а не
безопасность поведения skill.
