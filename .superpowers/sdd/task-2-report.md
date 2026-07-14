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

## Review remediation wave

### Review outcome

- Addressed every concrete Task 2 review reproduction without adding a public reason code, domain model, or pipeline contract.
- Kept host-output policy out of this task; unsafe host paths are still rejected before write-role filtering, while candidate-local generated outputs are not treated as input dependencies.
- Did not touch `.env` or execute analyzed source.

### TDD evidence

RED was reproduced before the remediation implementation:

- `uv run pytest tests/test_static_analysis.py -k 'review_' -q`
- `15 failed, 1 passed, 200 deselected`.

The 16 focused regressions cover the supplied JavaScript/TypeScript lexical contexts, Python `Path` aliases and subprocess argv, read/write receiver roles, generated outputs, shell continuations and heredocs, Markdown fenced/frontmatter isolation, and candidate-scoped JSON globs.

### Implementation

- Replaced JavaScript/TypeScript prefix rescans and masking with a single-pass lexical/token state machine. It distinguishes code, strings, comments, regex literals, template text, and `${...}` expressions; incomplete lexical input fails closed. Dynamic template evidence is bounded, so nested templates do not introduce prefix-rescan or nested-slice quadratic behavior.
- Added Python import-alias discovery for `pathlib` and `subprocess`, receiver-aware `Path(...).read_*`/`write_*` access, and command extraction from subprocess argv position zero.
- Propagated access roles through forward-path analysis: candidate-local writes are outputs, and an exact later read of the same generated path is not an external input. Unsafe host writes remain blocked for the later Task 3 policy decision.
- Joined shell backslash continuations while retaining original source offsets, and made heredoc bodies inert with fail-closed unclosed-heredoc handling.
- Isolated Markdown frontmatter and fenced ranges before scanning links/inline code. Only explicitly supported Python, JavaScript/TypeScript, and shell fences are analyzed; unknown and `text` fences are inert. YAML block-scalar bodies are not interpreted as path fields.
- Restricted structured-config glob expansion to the entry directory and candidate root. It no longer falls back to repository siblings and still uses only immutable inventory entries.

### Verification

- Focused review GREEN:
  - `uv run pytest tests/test_static_analysis.py -k 'review_' -q`
  - `16 passed, 200 deselected`.
- Static-analysis regression file:
  - `uv run pytest tests/test_static_analysis.py -q`
  - `216 passed`.
- Full suite:
  - `uv run pytest -q`
  - `710 passed`.
- Lint:
  - `uv run ruff check .`
  - `All checks passed!`.
- Strict typing:
  - `uv run mypy src`
  - `Success: no issues found in 13 source files`.
- `git diff --check` passed.

### Remaining concern

- JavaScript/TypeScript extraction remains an intentionally bounded lexical analyzer rather than a complete parser. The review-specific ambiguity cases now have regression coverage and the scanner remains linear in source size.
