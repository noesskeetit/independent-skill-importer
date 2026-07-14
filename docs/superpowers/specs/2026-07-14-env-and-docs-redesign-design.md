# Автозагрузка FM API key и разделение документации

## Цель

Упростить локальный запуск FM-review и разделить документацию по аудиториям: короткое описание
продукта для техлида, отдельный алгоритм принятия решения об импорте и подробная внутренняя
реализация для разработчиков/агентов.

## `.env`

- CLI-команды `scan` и `import` перед созданием pipeline автоматически читают только файл `.env`
  из текущей рабочей директории.
- CLI option для пути к env-файлу не добавляется.
- Файл разбирается как dotenv-данные без исполнения shell-кода и без interpolation.
- Из файла используются только `FM_API_KEY` и legacy fallback `LLM_API_KEY`; остальные значения не
  экспортируются в process environment.
- Уже заданные process environment variables имеют приоритет. После объединения действует прежнее
  правило: наличие `FM_API_KEY` важнее `LLM_API_KEY`, даже если primary value пустое и затем
  fail-closed отклоняется reviewer-ом.
- Отсутствующий `.env` не является ошибкой. Ошибка чтения либо некорректное dotenv-содержимое даёт
  безопасную CLI configuration error без вывода секретов.
- Library API не ищет `.env` автоматически: автозагрузка является только удобством CLI и не меняет
  детерминированное поведение embedded pipeline.
- Repository, переданный как `source`, никогда не используется как место поиска env-файла. Его
  внутренний `.env` остаётся недоверенным payload и не становится источником credentials.

В корне проекта:

- локальный `.env` с `FM_API_KEY=` создаётся и игнорируется Git;
- `.env.example` с пустыми placeholders коммитится;
- `.gitignore` запрещает commit `.env`, но разрешает `.env.example`.

## Документы

1. `docs/TECH_LEAD_IMPORTER_ALGORITHM.md` становится коротким product brief:
   задача, вход, результаты `scan` и `import`, краткий pipeline, decision table, безопасность и
   минимальные команды запуска.
2. `docs/IMPORT_DECISION_ALGORITHM.md` содержит самостоятельный пошаговый алгоритм:
   discovery candidates, package boundaries, validation, forward/reverse dependencies,
   `portable/plugin_bound/ambiguous/invalid/blocked`, optional FM и правило import-only-portable.
3. Текущий подробный документ переносится без потери технических деталей в
   `docs/INTERNAL_IMPLEMENTATION_REFERENCE.md`.
4. README-ссылки и описание FM key обновляются под новую структуру и автозагрузку `.env`.

### Форма документа для техлида

Документ про решение об импорте должен отвечать на один практический вопрос: «нам передали
произвольный repository, где вперемешку могут лежать marketplace, skillsets, Codex/Claude/другие
plugins, examples и обычный code; как importer понимает, какие skills можно безопасно забрать на
платформу?» Объяснение помещается примерно на одну страницу и строится простым языком:

1. Importer не пытается сначала угадать тип всего repository; он рекурсивно находит каждую
   директорию с `SKILL.md`/`skill.md` и рассматривает её отдельно.
2. Для candidate определяется enclosing plugin/package boundary, но сам plugin никогда не
   импортируется.
3. Проверяется, всё ли необходимое находится внутри skill root. Ссылки или вызовы plugin runtime,
   MCP, hooks, commands, agents, providers, scripts/resources снаружи означают зависимость.
4. Проверяется обратная связь: использует ли runtime/конфигурация plugin этот skill как внутреннюю
   часть orchestration.
5. Если зависимости нет и автономность доказана — `portable`; явная зависимость — `plugin_bound`;
   некорректный skill — `invalid`; traversal/symlink escape — `blocked`; недостаток статических
   доказательств — `ambiguous` и только тогда optional FM review.
6. `import` копирует только итоговые `portable` и только содержимое их skill root.

Текст должен сопровождаться одной небольшой decision table и двумя примерами: standalone skill,
который импортируется, и skill внутри plugin, вызывающий `${PLUGIN_ROOT}/scripts/tool`, который
отбрасывается. Названия внутренних Python classes, детали hashing/TOCTOU и полный перечень regex
detectors остаются только в internal reference.

Короткий `TECH_LEAD_IMPORTER_ALGORITHM.md` также обязан явно показать:

- **Вход:** local path или Git/GitHub URL, optional ref/subpath и optional `FM_API_KEY` из локального
  `.env` текущей директории.
- **Выход scan:** список найденных skill roots, classification, причины/evidence, enclosing package,
  external requirements, conflicts/duplicates и counts; repository при этом не изменяется.
- **Выход import:** новый output directory только с payloads итоговых `portable` skills и
  `import-manifest.json` с provenance; остальные candidates перечислены как rejected.
- **Сквозной пример:** в одном repository лежат standalone skill, plugin-bound skill и mixed-plugin
  ambiguous skill; документ показывает их scan verdicts, optional FM только для ambiguous и то,
  что import копирует лишь подтверждённые portable payloads.

## Проверки

- TDD: `.env` key используется обеими CLI-командами; process env побеждает; legacy fallback
  сохраняется; missing file безопасен; source `.env` не читается; значение key не появляется в
  stdout/stderr/JSON/manifest.
- Полный pytest, Ruff, format, strict mypy, lock и diff-check.
- Installed-wheel smoke из директории с локальным `.env` подтверждает реальный CLI contract.

## Не входит в изменение

- Передача API key через CLI argument.
- Автопоиск `.env` по parent directories или внутри source repository.
- Изменение FM endpoint, model, prompt, confidence threshold или static classification rules.
