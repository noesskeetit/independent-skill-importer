# Real Repository Path Analysis Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Remove the demonstrated real-repository false positives without weakening fail-closed traversal, symlink, plugin ownership, or atomic import guarantees.

**Architecture:** Keep all analysis inventory-only. Add context-bearing path references inside `static_analysis.py`, resolve them through explicit entry/candidate/repository coordinate systems, and route only proven temporary outputs to a non-FM-promotable ambiguity.

**Tech Stack:** Python 3.12 standard library (`ast`, `re`, `pathlib`), existing immutable domain models, pytest, Ruff, strict mypy, uv/hatchling.

## Global Constraints

- Never execute repository scripts, install dependencies, initialize submodules, or read a referenced host file.
- Never copy files outside the skill root and never silently rewrite `SKILL.md`.
- `plugin_bound`, `ambiguous`, `invalid`, and `blocked` remain non-importable.
- Relative traversal, `file:` URLs, sensitive host reads, and symlink escape remain blocked.
- FM review may resolve plugin-autonomy ambiguity only; it may not override deterministic safety ambiguity.
- Preserve every source file in inventory/import payload, including tests and fixtures.

---

### Task 1: Inventory coordinate-system resolver

**Files:**
- Modify: `src/skill_importer/static_analysis.py`
- Test: `tests/test_static_analysis.py`

**Interfaces:**
- Produces: `_resolve_local_reference(entry_path, candidate_root, raw, by_path) -> tuple[str | None, bool]`.
- Precedence: entry-relative, candidate-root-relative, exact repository-root-relative; duplicate targets are collapsed.

- [ ] **Step 1: Write the repository-root RED tests**

Cover `skills/session-viewer/scripts/session-viewer.ts` from the candidate
entrypoint, an exact repository-root target outside the candidate, normal
`references/guide.md`, and `../../../../etc/passwd` as a blocked control.

- [ ] **Step 2: Verify RED**

Run: `uv run pytest tests/test_static_analysis.py -k 'repository_root_relative' -q`

Expected: the internal repository-root case fails with duplicated skill-root evidence.

- [ ] **Step 3: Implement inventory-only resolution**

Use `_collapse_path` for each relative base, never `Path.resolve()` or host
filesystem I/O. Do not use fallback for absolute, encoded traversal, NUL, or
backslash paths. Return an exact outside-inventory target as outside evidence;
never add it to the import payload.

- [ ] **Step 4: Verify and commit**

Run: `uv run pytest tests/test_static_analysis.py -k 'repository_root_relative or parent_resource or traversal' -q`

Expected: PASS.

Commit: `git commit -am 'fix: resolve repository-root skill references'`

### Task 2: Context-aware dependency extraction

**Files:**
- Modify: `src/skill_importer/static_analysis.py`
- Test: `tests/test_static_analysis.py`

**Interfaces:**
- Produces: internal `_PathReference(value, offset, access, syntax)` records.
- Produces: role-specific extractors for Markdown, Python AST, JS/TS lexical calls, shell operands, and known structured-config path fields.
- Consumes: the resolver from Task 1.

- [ ] **Step 1: Write inert-content RED tests**

Create candidates containing CSS `font: 16px/1.62`, JS regex
`instructions/u.test`, Python fixture strings `a/file-{index}.txt`, JSON test
data `/tmp/project`, and `tsconfig.include = ["scripts/**/*.ts"]`. Assert that
these produce none of `MISSING_LOCAL_RESOURCE`,
`DYNAMIC_REFERENCE_UNRESOLVED`, or `PATH_TRAVERSAL`.

- [ ] **Step 2: Write fail-closed sink controls**

Verify that actual `open("../../../runtime/engine.py")`,
`require("../../../runtime/engine.js")`, shell `source ../shared/env.sh`, and a
dynamic Markdown resource link remain nonportable. Keep a quoted fixture such
as `fixture = 'open("../../../runtime/not-real.py")'` inert.

- [ ] **Step 3: Verify RED**

Run: `uv run pytest tests/test_static_analysis.py -k 'inert_code or source_sink or tsconfig_glob' -q`

Expected: inert examples currently create false evidence.

- [ ] **Step 4: Implement role/context extraction**

Use `ast.parse` for Python call/import nodes and line/column offsets. For JS/TS
and shell, accept only bounded call/command patterns whose identifier begins
outside a comment, quoted string, template body, or regex literal. Parse JSON
with `json.loads`; resolve known fields such as `extends`, `files`, `include`,
and `references[].path`, expanding globs only against `inventory.by_path`.
Never fall back to raw-all-text scanning after parse failure.

- [ ] **Step 5: Verify and commit**

Run: `uv run pytest tests/test_static_analysis.py -k 'inert_code or source_sink or tsconfig_glob or missing_local or dynamic_local' -q`

Expected: PASS.

Commit: `git commit -am 'fix: analyze paths only in dependency contexts'`

### Task 3: Temporary-output safety ambiguity

**Files:**
- Modify: `src/skill_importer/models.py`
- Modify: `src/skill_importer/static_analysis.py`
- Modify: `src/skill_importer/pipeline.py`
- Test: `tests/test_static_analysis.py`
- Test: `tests/test_pipeline.py`

**Interfaces:**
- Produces: `ReasonCode.HOST_TEMP_OUTPUT`.
- Produces: `StaticAnalysisResult.fm_reviewable` which is false when a
  deterministic host/safety ambiguity remains.

- [ ] **Step 1: Write RED and security-control tests**

Verify `--out /tmp/session.html` becomes static `ambiguous` with
`HOST_TEMP_OUTPUT`, while `cat /tmp/token`, `open('/etc/passwd')`, `file:` URLs,
Windows/home secrets, and relative traversal remain `blocked`. Verify the
pipeline does not call injected FM transport for host-output-only ambiguity.

- [ ] **Step 2: Verify RED**

Run: `uv run pytest tests/test_static_analysis.py tests/test_pipeline.py -k 'temp_output or host_paths' -q`

Expected: `/tmp` output is currently `PATH_TRAVERSAL` and FM review lacks a policy gate.

- [ ] **Step 3: Implement strict output recognition and FM gate**

Recognize only normalized `/tmp/` or `/var/tmp/` literals without `..` in an
explicit `--out`, `--output`, or shell output-redirection context. All read or
unknown contexts keep existing fail-closed behavior. Classify the new reason as
ambiguous and expose `fm_reviewable=False` whenever it is present.

- [ ] **Step 4: Verify and commit**

Run: `uv run pytest tests/test_static_analysis.py tests/test_pipeline.py -k 'temp_output or host_paths or fm_transport' -q`

Expected: PASS.

Commit: `git commit -am 'fix: separate temporary outputs from host reads'`

### Task 4: Pinned real-repository regression, tech-lead document, and closeout

**Files:**
- Create: `tests/test_real_repository_regression.py`
- Create: `docs/TECH_LEAD_IMPORTER_ALGORITHM.md`
- Modify: `AUDIT_AND_NEXT_STEPS.md`
- Modify: `README.md`

**Interfaces:**
- Consumes: public CLI `skill-importer scan` and the pinned
  `openclaw/agent-skills` commit.
- Produces: a network-optional marker/test plus a checked-in minimal synthetic
  corpus that runs offline in the default suite.

- [ ] **Step 1: Add offline corpus assertions**

Reproduce repository-root commands, inert CSS/regex/test fixtures, and a temp
output in a compact fixture. Assert exact reason codes and source-addressable
evidence.

- [ ] **Step 2: Run the focused end-to-end test**

Run: `uv run pytest tests/test_real_repository_regression.py -q`

Expected: PASS after Tasks 1-3.

- [ ] **Step 3: Run the pinned GitHub scan**

Run: `uv run skill-importer scan https://github.com/openclaw/agent-skills --ref 4887c1d540febb1f55140e96da7e4aae3e5163ba --no-llm --json`

Expected: no duplicated `skills/<name>/skills/<name>/...` evidence; no CSS,
regex, or inert test-fixture evidence; strict temp outputs are ambiguous rather
than blocked. Genuine outside/runtime/host-read evidence remains.

- [ ] **Step 4: Write and verify the tech-lead algorithm document**

Create a Russian-language, code-grounded document covering the product problem,
the exact `SourceResolver → RepositoryInventory → PackageBoundaryDetector →
SkillCandidateDiscoverer → SkillValidator → PortabilityAnalyzer → ImportPlan →
SkillImporter` flow, source URL/ref/subpath normalization, plugin-boundary
detection, static and optional FM decisions, identity/provenance/deduplication,
the scan JSON contract, atomic import, security limits, one portable and one
rejected example, current POC limitations, and production next steps. Include a
Mermaid flowchart and link every implementation stage to its concrete Python
module. Cross-check every claim against current code and tests; do not describe
planned behavior as implemented.

- [ ] **Step 5: Update remaining docs and run all gates**

Run:

```bash
uv run pytest -q
uv run ruff check .
uv run mypy src tests
uv lock --check
uv build
```

Expected: all commands exit 0.

- [ ] **Step 6: Installed-wheel smoke, review, commit, and push**

Install the built wheel into a fresh temporary Python 3.12 environment and run
`skill-importer scan` then `skill-importer import` on the standalone fixture.
Run the repository's structured review helper if available, verify every
finding against source, commit the docs/regression update, and push `main` to
`origin` only after the working tree is clean and all gates are green.
