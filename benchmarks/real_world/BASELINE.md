# Verified static baseline

Проверено 2026-07-14 на Python 3.12 тем же public `SkillImporterPipeline.scan()`, который
использует CLI. Все источники зафиксированы на SHA из `cases.json`; FM review выключен.

Итог: **10/10 cases совпали с manual oracle**. Это agreement по текущему корпусу, а не
универсальная метрика точности на всех существующих repositories.

| Case | Ожидаемый результат | Фактический результат |
|---|---|---|
| C01 OpenAI blob parent | `portable` | `portable` |
| C02 OpenAI system monorepo | 5 × `portable` | 5 × `portable` |
| C03 Anthropic skills-only plugin | `portable` | `portable` |
| C04 Anthropic mixed independent | `ambiguous` | `ambiguous` |
| C05 Anthropic reverse dependency | `plugin_bound` | `plugin_bound` |
| C06 OpenAI Figma plugin | `plugin_bound` | `plugin_bound` |
| C07 standalone рядом с plugins | `portable` | `portable` |
| C08 OpenClaw archive limit | `SCAN_LIMIT_EXCEEDED` | `SCAN_LIMIT_EXCEEDED` |
| C09 Microsoft duplicate layouts | 2 × `portable`, duplicate | 2 × `portable`, duplicate |
| C10 Hugging Face mixed package | `ambiguous` | `ambiguous` |

FM lane в этот baseline не входит: он требует `LLM_API_KEY` и отдельно проверяет только C04/C10.
Runner сохраняет полный JSON с actual candidates, reason codes, resolved SHA и operational errors.

