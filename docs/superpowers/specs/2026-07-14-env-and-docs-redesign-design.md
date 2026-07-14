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
