# Universal Skill Importer

Universal Skill Importer — standalone POC для безопасного поиска и извлечения самостоятельных
agent skills из локальной директории, Git-репозитория или GitHub URL. Он решает практическую
проблему монорепозиториев и plugin-пакетов: наличие `SKILL.md` ещё не означает, что skill можно
оторвать от plugin runtime и использовать отдельно.

Импортер сначала строит проверяемый preview с provenance, классификацией, reason codes и evidence,
а затем отдельной свежей операцией копирует только доказанно `portable` payloads в новый output.

> Это **не plugin importer**. Инструмент не устанавливает, не конвертирует и не запускает plugins,
> repository code, dependencies, hooks, MCP servers, runtime-компоненты или Git submodules.

## Что именно делает pipeline

Одна операция `scan` проходит следующие этапы:

1. `SourceSpec` валидирует local/Git/GitHub input, optional `ref` и relative `subpath`.
2. `SourceResolver` создаёт private temporary snapshot. Local source копируется без follow-symlinks;
   remote source fetch-ится в isolated bare repository и извлекается через `git archive`.
3. `RepositoryInventory` без исполнения файлов фиксирует paths, kinds, sizes, executable bits,
   symlink targets, SHA-256 и доступный UTF-8 text.
4. `PackageBoundaryDetector` на всём snapshot находит enclosing plugin boundaries и различает
   `skills_only` и `mixed` packages.
5. `SkillCandidateDiscoverer` рекурсивно ищет `SKILL.md` и совместимый `skill.md` внутри discovery
   scope. `SkillValidator` безопасно разбирает bounded YAML frontmatter.
6. `StaticPortabilityAnalyzer` проверяет forward/reverse plugin dependencies, local resources,
   traversal, symlinks, plugin-owned symbols и external requirements. Если active path
   dataflow выходит за skill root, но static analyzer не может надёжно доказать его роль,
   candidate получает `STATIC_ANALYSIS_INCOMPLETE` и остаётся `ambiguous`, а не fail-open
   `portable`.
7. Только statically `ambiguous` candidates при включённом FM проходят bounded Cloud.ru review.
8. Pipeline вычисляет content hashes, duplicate groups, name-conflict groups и формирует
   детерминированный `ScanReport` schema `1.0`.

`import` не принимает старый scan report. Он заново выполняет весь pipeline в новом snapshot,
строит `ImportPlan`, повторно проверяет bytes, hashes, modes и symlinks при копировании, пишет
manifest и публикует новый output через native atomic no-clobber API.

`subpath` ограничивает только discovery. Boundary detection, inventory и reverse-dependency
analysis по-прежнему видят весь bounded snapshot, поэтому blob URL внутри plugin не маскирует
enclosing runtime.

## Архитектурный документ и real-world benchmark

- [Tech-lead описание алгоритма](docs/TECH_LEAD_IMPORTER_ALGORITHM.md) связывает product decision
  «plugin-bound skill бесполезен отдельно» с фактическими модулями, reason/evidence contract,
  optional FM adjudication и atomic import. Там же явно проведена граница между importer и
  отдельным skill security checker.
- [Real-world benchmark](benchmarks/real_world/README.md) запускает public read-only scan path по
  десяти вручную размеченным GitHub cases, pinned на полные commit SHA. Manifest находится в
  [`benchmarks/real_world/cases.json`](benchmarks/real_world/cases.json); обычные tests полностью
  offline, а сеть включается только явным `--online`. Проверенный static baseline:
  [9/9 source/semantic cases + 1 expected operational guard](benchmarks/real_world/BASELINE.md)
  без disagreements.
- [Аудит и следующие шаги](AUDIT_AND_NEXT_STEPS.md) отделяет уже реализованные функциональные
  исправления и подтверждённые re-audit findings от отдельного production backlog.

```bash
# Offline contract tests benchmark runner-а
uv run pytest -q tests/test_real_world_benchmark.py

# Explicit online static corpus; labels manifest не переписываются
uv run python benchmarks/real_world/run.py \
  --online \
  --manifest benchmarks/real_world/cases.json \
  --json-out .artifacts/real-world-benchmark.json \
  --markdown-out .artifacts/real-world-benchmark.md
```

## Требования и установка

- Python `>=3.12`;
- `uv`;
- Git для remote sources.

```bash
cd independent-skill-importer
uv sync --python 3.12 --group dev
uv run skill-importer --help
```

Runtime dependencies заданы в `pyproject.toml`: Click 8.x и PyYAML 6.x.

## CLI и источники

```text
skill-importer scan SOURCE [--ref REF] [--subpath PATH] [--json]
                           [--model MODEL_ID] [--no-llm]
skill-importer import SOURCE --out DIR [--ref REF] [--subpath PATH]
                                      [--model MODEL_ID] [--no-llm]
```

### Local directory

```bash
uv run skill-importer scan ../my-skills --no-llm --json
uv run skill-importer import ../my-skills --out ../imported-skills --no-llm
```

Для local source `--ref` запрещён. `--subpath` должен быть normalized relative POSIX directory:

```bash
uv run skill-importer scan ../monorepo --subpath packages/skills --no-llm
```

### Обычный Git URL

Поддерживаются `https://`, `ssh://`, `git://` и SCP-style
`user@host:owner/repository.git`. Production path запрещает `file://`, remote helpers вроде
`ext::`, inline passwords и URL query/fragment.

```bash
uv run skill-importer scan \
  https://git.example.org/platform/agent-skills.git \
  --ref main \
  --subpath packages \
  --json
```

`--ref` резолвится в полный 40-character commit SHA. Resolver использует shallow fetch без tags и
submodules, затем `git archive`; checkout и repository hooks не выполняются.

### GitHub repository, tree и blob

Repository URL:

```bash
uv run skill-importer scan https://github.com/acme/agent-skills --ref main --json
```

Tree URL:

```bash
uv run skill-importer scan \
  https://github.com/acme/agent-skills/tree/main/packages/demo \
  --ref main \
  --json
```

Blob URL на entrypoint:

```bash
uv run skill-importer scan \
  https://github.com/acme/agent-skills/blob/main/packages/demo/SKILL.md \
  --ref main \
  --json
```

Для blob URL discovery scope автоматически становится parent directory выбранного файла. Если
scope берётся из route, resolver после extraction проверяет через `lstat`, что exact blob target
существует в resolved revision, каждый промежуточный component является directory без symlink, а
сам target — regular file. Missing target, directory или symlink отклоняются как `INVALID_SOURCE`.
Явный `--subpath` переопределяет route-derived scope. Resolver сверяет advertised branch/tag names
через `git ls-remote`, выбирает самый длинный совпавший ref и только при отсутствии такого ref
трактует первый 40-hex component как commit SHA. Для неоднозначного route можно передать точный
`--ref`; его slash-components целиком исключаются из discovery scope.

### `scan` и свежий `import`

`scan` создаёт только temporary snapshot и preview; source и output не изменяются. Human output
показывает revision, candidates, classifications, package boundaries, requirements, reasons,
duplicate/name-conflict groups и counts. `--json` выдаёт stable schema `1.0`.

`import` всегда делает новый scan. Изменения source после preview поэтому попадут в import только
после повторной классификации. Parent directory для `--out` должен существовать, сам `--out` —
не существовать. Existing file, directory или symlink никогда не перезаписывается.

Repository без `SKILL.md`/`skill.md` — валидный zero-result, а не ошибка: `scan` возвращает
`skills: []` и нулевые counts. `import` завершается успешно и атомарно публикует только
`import-manifest.json` с пустыми `imported` и `rejected`, не создавая skill payload directories.

## Классификации, reasons и evidence

| Classification | Значение |
|---|---|
| `portable` | Автоматический import разрешён: payload самодостаточен либо автономность доказана FM review. |
| `plugin_bound` | Есть доказанная зависимость от enclosing plugin/runtime либо skill является внутренним orchestration-компонентом. |
| `ambiguous` | Автономность не доказана; без дополнительного доказательства import запрещён. |
| `invalid` | `SKILL.md`/`skill.md` или обязательный frontmatter некорректен. |
| `blocked` | Обнаружено unsafe состояние, которое можно привязать к candidate: например traversal или escaping symlink. |

Static precedence неизменяем:

```text
blocked > invalid > plugin_bound > ambiguous > portable
```

Source-global collision или limit overflow может остановить всю операцию контролируемой ошибкой
до формирования candidates; такой случай не маскируется искусственным `blocked` result.

FM не вызывается для static `portable`, `plugin_bound`, `invalid` или `blocked` и не может ослабить
детерминированное решение. Без `--no-llm` FM рассматривает только static `ambiguous`.

`STATIC_ANALYSIS_INCOMPLETE` означает, что conservative residual pass увидел active path literal
или dataflow за пределы skill root, но не смог безопасно квалифицировать его как доказанную plugin
dependency. Такой candidate классифицируется как static `ambiguous`; доступный inventory target
добавляется в bounded review context, и только обычная FM-review lane может дополнительно доказать
автономность. Bounded Ruby dataflow восстанавливает literals, assignments, `+`, `File.join` и
known/unknown consumers; достижение literal/expression/depth limits само даёт
`STATIC_ANALYSIS_INCOMPLETE`, а не обрывает анализ fail-open. Без FM или при любом fail-closed
результате import запрещён.

Каждый `DecisionReason` содержит:

- machine-readable `code`, например `REFERENCE_OUTSIDE_SKILL_ROOT`, `PATH_TRAVERSAL` или
  `FM_PORTABLE_VERIFIED`;
- bounded human-readable `message`;
- source-addressable `evidence`: relative `path`, optional `line`/`field`, bounded `value` и
  detector, который получил факт.

`externalRequirements` отделены от plugin dependencies. Например, `git`, `docker` или
`WORKSPACE_ID` могут быть требованиями portable skill и сами по себе не делают его plugin-bound.

## FM review через Cloud.ru

По умолчанию CLI использует:

- endpoint: `https://foundation-models.api.cloud.ru/v1/chat/completions`;
- model: `zai-org/GLM-5.1` (переопределяется через `--model`);
- timeout: 20 seconds;
- `temperature: 0`, JSON response format и disabled thinking.

Ключ берётся **только** из process environment. `FM_API_KEY` — primary name;
`LLM_API_KEY` поддерживается как compatibility fallback, только если primary variable вообще
отсутствует:

```bash
export FM_API_KEY='...'
uv run skill-importer scan ../source
```

Импортер не загружает dotenv и не использует `.env` как источник конфигурации или API key. Файл
`.env`, лежащий внутри source, всё ещё считается недоверенным repository data: он может попасть в
inventory и, если находится внутри portable skill root, быть скопирован как часть payload, но
исключается из FM envelope. Ключ нельзя передать CLI option; он не включается в semantic request
body, scan JSON, errors или import manifest.

Если static `ambiguous` требует review, но оба ключа отсутствуют либо выбранный по этому precedence
ключ некорректен, network call не выполняется: candidate остаётся `ambiguous` с
`FM_REVIEW_UNAVAILABLE`. Явно заданный пустой/некорректный `FM_API_KEY` не откатывается к legacy
key. То же fail-closed поведение применяется к timeout, transport failure, invalid JSON, hash
mismatch и invented evidence.

Перед отправкой repository data ограничиваются context budget, sensitive files исключаются, а
credential-like values редактируются. Ответ привязан к SHA-256 exact canonical envelope; evidence
перепроверяется по строкам и hash immutable inventory. Повышение `ambiguous -> portable` возможно
только при confidence `>= 0.90`, непустом валидном evidence и полностью непрерывном,
не redacted context. Redaction или truncation запрещают это повышение.

Для полностью offline/deterministic режима используйте `--no-llm`; в этом режиме API key не
нужен, а static `ambiguous` остаются `ambiguous`.

## Что никогда не исполняется и не импортируется

Repository content считается недоверенным data. Импортер:

- не запускает `SKILL.md`, scripts, binaries или любой repository code;
- не устанавливает dependencies и не вызывает package managers;
- не выполняет Git checkout filters или repository hooks;
- не инициализирует и не загружает Git submodules;
- не запускает MCP servers, commands, agents, hooks, providers или plugin runtime;
- не импортирует plugin manifests/runtime как executable package;
- не переписывает skill и не добавляет к нему files снаружи skill root.

Сам процесс `git` используется только с argv-only вызовами, isolated temporary `HOME`, disabled
system/global config, disabled hooks, non-interactive mode и protocol allowlist. Отдельный
Cloud.ru HTTP request возможен для любого source только на этапе FM review.

В output копируются только safe entries выбранного portable skill root: `SKILL.md`, локальные
`assets`, `references`, `scripts`, пустые directories и другие вложенные payload files. Safe
relative symlinks внутри того же root сохраняются после повторной проверки цепочки. Внешний
resource не подтягивается автоматически.

## Identity, одинаковые names и duplicates

`candidateId` привязан к immutable provenance:

- remote: canonical URL + resolved commit SHA + skill root;
- local: canonical file URL + snapshot SHA-256 + skill root.

`name` не является primary key.

- Одинаковый `name` при разном payload создаёт `NAME_CONFLICT`, но оба portable payloads остаются
  отдельными и получают разные hash-suffixed destinations.
- Одинаковый content hash создаёт `DUPLICATE_CONTENT`: physical payload копируется один раз, а
  `candidateIds` и `provenance` сохраняют все исходные candidates.

Content hash учитывает relative path, entry kind, executable bit и file bytes либо symlink target.
Representative для duplicate group выбирается детерминированно.

## Output layout и atomic no-clobber publication

Пример результата:

```text
imported-skills/
├── import-manifest.json
├── first-skill--24c4e40a9bd1/
│   ├── SKILL.md
│   ├── assets/
│   └── scripts/
└── first-skill--f83a91145e72/
    └── SKILL.md
```

Destination имеет форму `<normalized-name>--<content-hash-prefix>`. Prefix начинается с 12 hex
characters и при collision расширяется до минимальной уникальной длины. Поэтому одинаковые names
с разным content не clobber друг друга, а byte-identical payloads дедуплицируются.

Publication работает так:

1. В sibling directory создаётся случайный staging mode `0700`.
2. Весь `ImportPlan` и manifest строятся до destination writes.
3. Каждый destination directory создаётся mode `0700`; regular files получают `0600` или `0700`
   для executable payload, manifest — `0600`. Setuid/setgid не сохраняются.
4. Copy повторно проверяет source inode/type/size/hash/link count и safe symlink chain. До записи
   весь payload directory/symlink graph проверяется на cycles; importer повторяет эту проверку даже
   для неконсистентного внешнего `ImportPlan`. Regular files синхронизируются через `fsync` строго,
   directories — там, где filesystem это поддерживает.
5. macOS публикует staging через `renameatx_np(..., RENAME_EXCL)`, Linux — через
   `renameat2(..., RENAME_NOREPLACE)`. Unsafe `os.replace`/`os.rename` fallback отсутствует.
6. Если native no-clobber API или filesystem semantics недоступны, операция fail-closed с
   `ATOMIC_NOREPLACE_UNSUPPORTED`; existing output сохраняется.

Creation ledger хранит path, kind, device/inode и link count каждой созданной entry; для symlink —
exact target, для directory — ожидаемый mode, для regular file — ожидаемые mode, size и SHA-256
exact bytes. Непосредственно перед publication importer заново открывает ledger entries через
fd-relative no-follow path, проверяет полный child set и directory modes, перечитывает file bytes
для hash comparison и повторно сверяет symlink targets. Подмена manifest/payload in-place, mode
change, replacement или добавленная entry дают `STAGING_CHANGED` и не публикуются. Cleanup
повторяет эти проверки; mismatch оставляет residual вместо принятия или удаления неизвестной entry.

Это best-effort защита, а не inode-conditioned delete: POSIX `unlink`/`rmdir` оставляют финальное
окно между последней проверкой pathname и syscall, а активный malicious same-UID процесс может
пытаться менять данные уже после preflight. Поэтому production security boundary должен включать
private importer-owned output parent.

При безопасно обнаруженном mismatch `--out` не появляется, но рядом может остаться orphan вида
`.OUT.skill-importer-*`. После подтверждения staging identity importer применяет `fchmod(0700)`;
при сбое до этой точки исходный `mkdir(0700)` с учётом `umask` создаёт mode не более разрешающий,
чем `0700`. Оператор должен проверить и удалить residual вручную; его наличие не означает
опубликованный import.

## Scan JSON schema `1.0`

Ниже полный representative result для одного local standalone skill. Это валидный JSON без
псевдополей и ellipsis:

```json
{
  "schemaVersion": "1.0",
  "source": {
    "kind": "local",
    "input": "/srv/skill-source",
    "canonicalUrl": "file:///srv/skill-source",
    "resolvedCommitSha": null,
    "snapshotSha256": "c5b4c2e528c37b114c66f0089d7cbf37878154abe18aa2c590762639b871b911",
    "discoveryScope": "."
  },
  "skills": [
    {
      "candidateId": "sha256:e44cb1ef54e409fe4a8145157214220256f2a49b5c645781b2cb592e8de98879",
      "provenance": {
        "kind": "local",
        "input": "/srv/skill-source",
        "canonicalUrl": "file:///srv/skill-source",
        "resolvedCommitSha": null,
        "snapshotSha256": "c5b4c2e528c37b114c66f0089d7cbf37878154abe18aa2c590762639b871b911",
        "discoveryScope": "."
      },
      "root": "skill",
      "entrypoint": "skill/SKILL.md",
      "name": "standalone-tool",
      "description": "Standalone skill with a complete local payload",
      "classification": "portable",
      "staticClassification": "portable",
      "analysisMethod": "static",
      "enclosingPackage": null,
      "validation": {
        "valid": true,
        "name": "standalone-tool",
        "description": "Standalone skill with a complete local payload",
        "frontmatter": {
          "name": "standalone-tool",
          "description": "Standalone skill with a complete local payload",
          "requires": {
            "bins": ["git", "docker"],
            "env": ["WORKSPACE_ID"]
          }
        },
        "reasons": [],
        "warnings": []
      },
      "reasons": [
        {
          "code": "STANDALONE_NO_PLUGIN_BOUNDARY",
          "message": "skill has no enclosing plugin boundary",
          "evidence": [
            {
              "path": "skill/SKILL.md",
              "line": 1,
              "field": "enclosingPackage",
              "value": "none",
              "detector": "static.classification.standalone"
            }
          ]
        }
      ],
      "externalRequirements": {
        "binaries": ["docker", "git"],
        "environment": ["WORKSPACE_ID"]
      },
      "contentHash": "bcbef522af32d8750a0cf7da39139f638af84cd8341e398af9a20c301ae9b53a",
      "duplicateGroup": null,
      "nameConflictGroup": null,
      "fmReview": null
    }
  ],
  "duplicates": [],
  "nameConflicts": [],
  "counts": {
    "total": 1,
    "portable": 1,
    "plugin_bound": 0,
    "ambiguous": 0,
    "invalid": 0,
    "blocked": 0
  },
  "warnings": [],
  "errors": []
}
```

CLI сериализует JSON детерминированно с sorted keys. Private temporary `snapshotRoot` в public
schema не входит.

## `import-manifest.json`

Manifest — canonical allowlisted JSON с trailing newline. Его top-level schema содержит только
`schemaVersion`, `source`, `imported` и `rejected`. Полный пример:

```json
{
  "schemaVersion": "1.0",
  "source": {
    "canonicalSourceUrl": "file:///srv/skill-source",
    "resolvedCommitSha": null,
    "snapshotSha256": "c5b4c2e528c37b114c66f0089d7cbf37878154abe18aa2c590762639b871b911"
  },
  "imported": [
    {
      "name": "standalone-tool",
      "contentHash": "bcbef522af32d8750a0cf7da39139f638af84cd8341e398af9a20c301ae9b53a",
      "destination": "standalone-tool--bcbef522af32",
      "candidateIds": [
        "sha256:e44cb1ef54e409fe4a8145157214220256f2a49b5c645781b2cb592e8de98879"
      ],
      "provenance": [
        {
          "candidateId": "sha256:e44cb1ef54e409fe4a8145157214220256f2a49b5c645781b2cb592e8de98879",
          "originalRoot": "skill",
          "entrypoint": "skill/SKILL.md"
        }
      ]
    }
  ],
  "rejected": []
}
```

`source` здесь намеренно уже, чем scan provenance: это exact
`canonicalSourceUrl`/`resolvedCommitSha`/`snapshotSha256`. Manifest не включает API key, full
frontmatter, FM rationale, analysis evidence, temporary paths или repository content. Rejected
records содержат bounded name/root, truncation flags, classification и reason codes.

## Resource limits

Defaults из `Limits` применяются на соответствующих этапах scan/import operation:

| Поле | Default | Что ограничивает |
|---|---:|---|
| `git_timeout_seconds` | 60 s | Каждый bounded Git command/archive stream. |
| `fm_timeout_seconds` | 20 s | Один Cloud.ru FM HTTP request. |
| `max_archive_bytes` | 100 MiB | Tar stream от `git archive`. |
| `max_entries` | 10,000 | Entries source и import payload. |
| `max_candidates` | 1,000 | Skill candidates, анализируемые за одну scan operation. |
| `max_scan_bytes` | 250 MiB | Суммарные regular-file bytes snapshot/import. |
| `max_file_bytes` | 10 MiB | Один regular file. |
| `max_depth` | 64 | Path depth. |
| `max_fm_context_chars` | 128 Ki characters | Canonical FM analysis envelope. |
| `max_fm_response_bytes` | 1 MiB | Raw FM response body. |
| `max_fm_reviews` | 50 | FM calls за одну pipeline operation. |
| `max_manifest_bytes` | 10 MiB | Canonical import manifest, включая trailing newline. |

Limit violation не приводит к исполнению fallback-кода. Source-global overflow завершает
операцию безопасной ошибкой; candidate-addressable unsafe facts отражаются в classification и
evidence там, где pipeline может локализовать их к candidate.

## Ограничения POC и шаги до production

- Static dependency detection использует conservative structured/regex detectors, а не полные AST
  всех языков. Возможны false positives и нераспознанные динамические связи; ambiguous нельзя
  автоматически считать portable.
- Текущий reverse/static analysis в худшем случае повторно просматривает runtime-relevant files для
  каждого candidate (`O(candidates * runtime files)`). Production нужен pre-index/cache ownership и
  references, не ослабляющий reason/evidence contract.
- `git fetch` ограничен timeout, но exact byte quota на входящий pack до его завершения не
  гарантируется. Production нужен quota-controlled fetch service с disk/network isolation.
- Protocol validation не является universal host allowlist или SSRF policy. Server deployment
  требует egress allowlist, DNS/IP controls и отдельный credential broker для private Git.
- Local source snapshot охватывает весь supplied root; `subpath` не уменьшает source-global
  resource cost.
- FM review вероятностный и отправляет sanitized repository context во внешний Cloud.ru endpoint.
  Production требует versioned prompt/model policy, curated eval corpus, telemetry и regression
  benchmarks.
- Native atomic publication реализована только для macOS и Linux/filesystems с соответствующей
  no-replace семантикой. Другие platforms fail-closed до появления проверенного publisher.
- Same-UID процесс может вмешаться в sibling staging. Ledger обнаруживает многие replacements и
  оставляет restrictive orphan, но не устраняет финальный pathname-check → `unlink`/`rmdir` race;
  production требует private importer-owned parent и audited residual cleanup.
- POC публикует только новый filesystem output. Production integration должна преобразовывать
  `ImportPlan` в транзакцию registry/object storage и сохранить те же provenance/no-clobber
  invariants.
- Package schemas, plugin markers и language detectors требуют versioned adapters по мере развития
  ecosystems.

До production нужны quota-isolated fetch, egress/credential policy, platform publishers,
операционный residual sweeper с trusted ownership checks, versioned FM policy/evals и
transactional registry adapter. Даже после этих расширений инструмент должен оставаться skill
extractor, а не plugin installer.
