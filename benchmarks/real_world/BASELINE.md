# Verified static baseline

Проверено 2026-07-14 на Python 3.12 тем же public `SkillImporterPipeline.scan()`, который
использует CLI. Все источники зафиксированы на SHA из `cases.json`; FM review выключен.

Post-fix implementation checkpoint:
`87cfb513d1ad40d891e2b666ddb01cca4142cc0f`. На нём corpus повторён после финального static,
resolver и atomic-import hardening; результат ниже не перенесён со старого запуска.

Итог: **9/9 source/semantic cases совпали с manual oracle, плюс совпал 1/1 expected
operational guard; disagreements — 0**. C08 не включается в semantic numerator: ранний
`SCAN_LIMIT_EXCEEDED` не доказывает canonical source, commit SHA или candidate verdict.

| Case | Ожидаемый результат | Фактический результат |
|---|---|---|
| C01 OpenAI blob parent | `portable` | `portable` |
| C02 OpenAI system monorepo | 5 × `portable` | 5 × `portable` |
| C03 Anthropic skills-only plugin | `portable` | `portable` |
| C04 Anthropic mixed independent | `ambiguous` | `ambiguous` |
| C05 OpenAI reverse dependency | `plugin_bound` | `plugin_bound` |
| C06 OpenAI Figma plugin | `plugin_bound` | `plugin_bound` |
| C07 standalone рядом с plugins | `portable` | `portable` |
| C08 OpenClaw archive limit | expected guard `SCAN_LIMIT_EXCEEDED` | guard matched |
| C09 Microsoft duplicate layouts | 2 × `portable`, duplicate | 2 × `portable`, duplicate |
| C10 Hugging Face mixed package | `ambiguous` | `ambiguous` |

FM lane в этот baseline не входит: он требует `FM_API_KEY` (либо `LLM_API_KEY` fallback) и
отдельно проверяет только C04/C10. Runner сохраняет полный JSON с actual candidates, reason codes,
resolved SHA и operational errors.
