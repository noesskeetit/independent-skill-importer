# Real-repository path analysis hardening design

## Problem

The POC currently treats almost every slash-containing string in every UTF-8
file as a package resource dependency. On `openclaw/agent-skills` this turns CSS,
regular expressions, test fixtures, repository-root command paths, and `/tmp`
outputs into `MISSING_LOCAL_RESOURCE`, `DYNAMIC_REFERENCE_UNRESOLVED`, or
`PATH_TRAVERSAL`. The scan therefore reports one portable skill and five blocked
skills even though most evidence is not a packaging dependency.

The importer must remain fail closed: it may not execute repository code, follow
host filesystem paths, weaken traversal/symlink gates, or copy anything outside
the selected skill root.

## Chosen approach

Use a context-aware extractor and an inventory-only resolver.

1. Classify text by role without changing the inventory or import payload:
   `SKILL.md` instructions, source, test source, structured config, or opaque
   asset.
2. In Markdown, inspect actual links and command/code contexts. Development and
   validation examples may prove that bundled test files exist, but their own
   external fixtures are not runtime package dependencies.
3. In source files, inspect path-consuming operations (imports, file APIs,
   shell `source`, and executable argv), not arbitrary strings. Python uses the
   standard-library AST; JavaScript/TypeScript and shell use bounded lexical
   extraction that rejects matches beginning inside comments, strings, template
   data, or regex literals.
4. Resolve a local reference only against the immutable inventory, in this
   order: entry-relative, candidate-root-relative, then exact repository-root
   relative. Existing targets outside the skill root remain nonportable.
5. Keep relative traversal, `file:` URLs, symlink escape, and explicit sensitive
   host reads blocked. A strictly recognized temporary output receives a new
   evidence-backed ambiguity reason and is not automatically importable or
   eligible for FM promotion.
## Rejected alternatives

- Blanket-ignore `tests/` or fixtures: fast, but misses real import/file/runtime
  dependencies located in tests and makes directory naming a security bypass.
- Add one-off regex exceptions for CSS, `/u.test`, and format strings: this is
  an unbounded false-positive whack-a-mole.
- Add full tree-sitter parsers for every language in this POC: more precise, but
  expands dependencies and parser attack surface beyond this iteration.

## Classification policy

- A repository-root literal that resolves to a file inside the candidate is an
  internal dependency and does not change portability.
- An exact existing target outside the candidate yields
  `REFERENCE_OUTSIDE_SKILL_ROOT`; plugin-owned targets also retain the more
  specific plugin runtime reason.
- A proven relative/sensitive host read or traversal remains `blocked`.
- A proven conventional temporary output yields `HOST_TEMP_OUTPUT` and static
  `ambiguous`. This ambiguity is a safety policy result, not plugin-autonomy
  uncertainty, so FM cannot promote it to `portable`.
- Inert fixture/CSS/regex text yields no dependency evidence.
- An actual unresolved dynamic dependency in a recognized sink remains fail
  closed.

## Verification

The change is accepted only if focused RED/GREEN tests, the whole pytest suite,
Ruff, strict mypy, package build, installed-wheel CLI smoke, and a pinned live
scan of `openclaw/agent-skills` pass. The live regression assertion checks the
removal of the known false evidence rather than assuming every upstream skill
must be portable; genuine sibling tools and host resources remain nonportable.
