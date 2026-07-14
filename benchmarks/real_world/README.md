# Real-world importer benchmark

Этот corpus прогоняет public read-only `SkillImporterPipeline.scan()` по десяти
официальным GitHub sources, зафиксированным на полных commit SHA. Он измеряет,
насколько фактические candidates, classifications и reason codes совпадают с
ручным oracle из `cases.json`.

Benchmark ничего не импортирует и не исполняет из source repositories:

- не запускает `scripts`, hooks, commands, agents, MCP или plugin runtime;
- не устанавливает dependencies;
- не инициализирует submodules;
- передаёт каждый SHA в importer как explicit Git ref;
- использует тот же bounded resolver и inventory, что команда `scan`.

## Explicit online run

Обычный pytest полностью offline. Реальная сеть включается только отдельной
командой с обязательным acknowledgement `--online`:

```bash
uv run python benchmarks/real_world/run.py \
  --online \
  --manifest benchmarks/real_world/cases.json \
  --json-out .artifacts/real-world-benchmark.json \
  --markdown-out .artifacts/real-world-benchmark.md
```

По умолчанию это deterministic static lane (`ScanOptions(use_llm=False)`). Для
сравнения final labels после review только статически ambiguous candidates:

```bash
uv run python benchmarks/real_world/run.py \
  --online \
  --with-llm \
  --manifest benchmarks/real_world/cases.json \
  --json-out .artifacts/real-world-benchmark-fm.json \
  --markdown-out .artifacts/real-world-benchmark-fm.md
```

FM lane использует уже существующую конфигурацию importer и `LLM_API_KEY` из
process environment. Runner не читает и не создаёт `.env`, не реализует свой FM
client и не вызывает FM для deterministic decisions.

## Что находится в manifest

Каждый из ровно десяти cases хранит:

- input и canonical GitHub URL;
- immutable 40-character commit SHA;
- optional discovery `subpath`;
- `exact` либо `focused` coverage mode;
- manual static и final classifications;
- обязательное подмножество reason codes;
- source-addressable provenance links.

`focused` используется только для Microsoft duplicate case: scan под `.github`
возвращает много candidates, а oracle сравнивает две известные exact copies.
Остальные candidates остаются в JSON result и не скрываются.

Manual labels никогда не переписываются фактическим output. Несовпадение
становится benchmark result (`agreement=false`), а не новой «истиной» manifest.

## Expected operational error

OpenClaw case честно размечен двумя слоями:

- при текущем full-repository archive ожидается `SCAN_LIMIT_EXCEEDED`, потому что
  pinned tree превышает default `maxEntries`;
- semantic oracle после будущего selective inventory — candidate
  `extensions/lobster` с `INVALID_FRONTMATTER`.

Если resolver начнёт успешно обрабатывать этот source, прежний operational
expectation даст disagreement. После ручной проверки manifest можно будет
изменить отдельным review; runner сам labels не мутирует.

## Outputs

JSON сохраняет для каждого case:

- expected и resolved SHA;
- expected и все actual candidates;
- selected expected/actual classification;
- reason-code match;
- SHA, candidate, error и overall agreement;
- duration и bounded public error.

Markdown — компактная таблица для человека. Полная информация всегда остаётся
в JSON.

## Offline tests

```bash
uv run pytest -q tests/test_real_world_benchmark.py
```

Тесты передают injected fake scan с полным public JSON shape. Они не monkeypatch
внутренности importer, не открывают сеть и проверяют реальное поведение manifest
validation/comparison/rendering.
