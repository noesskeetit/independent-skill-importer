# Task 2 report: context-aware dependency extraction

## Status

DONE

## Scope

- Modified `src/skill_importer/static_analysis.py`.
- Added focused regression coverage in `tests/test_static_analysis.py`.
- Did not touch `.env`, domain models, documentation, or unrelated modules.
- Preserved the Task 1 entry-relative, candidate-root-relative, then repository-root-relative inventory resolver.

## TDD evidence

RED was observed before production changes:

- `uv run pytest tests/test_static_analysis.py -k 'inert_code or source_sink or tsconfig_glob' -q`
  produced `6 failed, 3 passed, 190 deselected`.
- The failures were the four inert-content cases, the inventory glob case, and the quoted Python fixture creating false missing evidence.
- Real Python, JavaScript, shell, and Markdown sinks already remained nonportable controls.
- The later fail-closed parser invariant was separately reproduced with
  `uv run pytest tests/test_static_analysis.py -k 'known_source_parse_failure' -q`, which produced `1 failed, 199 deselected` because broken Python source was incorrectly portable.

## Implementation

- Added internal `_PathReference(value, offset, access, syntax)` records.
- Replaced raw all-text path scanning with role-specific extraction:
  - Markdown links, structured frontmatter path values, and fenced/inline command contexts;
  - Python `ast.parse` call/import nodes with UTF-8-safe source offsets;
  - JavaScript/TypeScript call/import sinks guarded by a bounded lexical mask for comments, strings, template bodies, and regex literals;
  - shell command/operand extraction through the standard-library `shlex` tokenizer;
  - JSON `extends`, `files`, `include`, and `references[].path` fields.
- Structured-config globs expand only over `inventory.by_path`; no host filesystem globbing or source execution occurs.
- Known Python/source and structured-config parse failures produce file-level `DYNAMIC_REFERENCE_UNRESOLVED` evidence without falling back to raw text scanning.
- Tests and fixtures are analyzed by syntax and context; no directory-name-based skip was added.
- Existing slash-command behavior and blocked host/traversal controls remain intact.

## Verification

- Required focused GREEN:
  - `uv run pytest tests/test_static_analysis.py -k 'inert_code or source_sink or tsconfig_glob or missing_local or dynamic_local or known_source_parse_failure' -q`
  - `12 passed, 188 deselected`.
- Static-analysis regression file:
  - `uv run pytest tests/test_static_analysis.py -q`
  - `200 passed`.
- Full suite:
  - `uv run pytest -q`
  - `694 passed`.
- Lint:
  - `uv run ruff check .`
  - `All checks passed!`.
- Strict typing:
  - `uv run mypy src`
  - `Success: no issues found in 13 source files`.
- `git diff --check` passed.

## Concerns

- JavaScript/TypeScript intentionally uses a bounded lexical layer rather than a full language parser, matching the approved design and avoiding a new parser dependency.
- Invalid Python source files now fail closed. One unrelated ownership test used placeholder text in a `.py` file; its fixture was changed to valid `pass` source so that it continues testing ownership rather than parser failure.
- No source file was executed and no referenced host path was read.
