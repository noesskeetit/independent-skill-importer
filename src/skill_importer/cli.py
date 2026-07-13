"""Click command-line interface for deterministic scan previews."""

from __future__ import annotations

import json
import unicodedata

import click

from .errors import ImporterError
from .fm_review import DEFAULT_FM_MODEL
from .models import ScanReport
from .pipeline import ScanOptions, SkillImporterPipeline
from .source import parse_source_spec


def _model_option(
    context: click.Context,
    parameter: click.Parameter | None,
    value: str,
) -> str:
    del context, parameter
    try:
        ScanOptions(model=value)
    except ValueError as exc:
        raise click.BadParameter(str(exc)) from None
    return value


def _escape_terminal(value: object) -> str:
    text = str(value)
    escaped: list[str] = []
    for character in text:
        category = unicodedata.category(character)
        if category in {"Cc", "Cf", "Cs"} or character in {"\u2028", "\u2029"}:
            codepoint = ord(character)
            if codepoint <= 0xFFFF:
                escaped.append(f"\\u{codepoint:04x}")
            else:
                escaped.append(f"\\U{codepoint:08x}")
        elif character == "\\":
            escaped.append("\\\\")
        else:
            escaped.append(character)
    return "".join(escaped)


def _render_values(values: tuple[str, ...]) -> str:
    return "[" + ", ".join(_escape_terminal(value) for value in values) + "]"


def _render_human(report: ScanReport) -> str:
    source = report.source
    revision = source.resolved_commit_sha or source.snapshot_sha256
    lines = [
        f"Source: {_escape_terminal(source.canonical_url)}",
        f"Revision: {_escape_terminal(revision)}",
        "Skills:",
    ]
    if not report.skills:
        lines.append("  (none)")
    for skill in report.skills:
        reason_codes = ",".join(reason.code.value for reason in skill.reasons)
        lines.append(
            "  root="
            + _escape_terminal(skill.candidate.root)
            + " name="
            + _escape_terminal(skill.name or "-")
            + " classification="
            + _escape_terminal(skill.classification.value)
        )
        boundary = skill.candidate.enclosing_boundary
        if boundary is None:
            lines.append("    package: none")
        else:
            lines.append(
                "    package: root="
                + _escape_terminal(boundary.root)
                + " manifest="
                + _escape_terminal(boundary.manifest_path)
                + " kind="
                + _escape_terminal(boundary.manifest_kind)
                + " packageKind="
                + _escape_terminal(boundary.package_kind)
            )
        requirements = skill.external_requirements
        lines.append(
            "    externalRequirements: binaries="
            + _render_values(requirements.binaries)
            + " environment="
            + _render_values(requirements.environment)
        )
        lines.append("    reasons: " + _escape_terminal(reason_codes))

    lines.append("Duplicate groups:")
    if not report.duplicates:
        lines.append("  (none)")
    for duplicate_group in report.duplicates:
        lines.append(
            "  groupId="
            + _escape_terminal(duplicate_group.group_id)
            + " contentHash="
            + _escape_terminal(duplicate_group.content_hash)
            + " candidates="
            + _render_values(duplicate_group.candidate_ids)
        )
    lines.append("Name conflict groups:")
    if not report.name_conflicts:
        lines.append("  (none)")
    for conflict_group in report.name_conflicts:
        lines.append(
            "  groupId="
            + _escape_terminal(conflict_group.group_id)
            + " name="
            + _escape_terminal(conflict_group.name)
            + " candidates="
            + _render_values(conflict_group.candidate_ids)
        )
    counts = report.counts
    lines.append(
        "Counts: "
        + " ".join(
            f"{key}={counts[key]}"
            for key in (
                "total",
                "portable",
                "plugin_bound",
                "ambiguous",
                "invalid",
                "blocked",
            )
        )
    )
    return "\n".join(lines)


@click.group()
def cli() -> None:
    """Safely discover standalone agent skills without executing repository code."""


@cli.command("scan")
@click.argument("source", required=True)
@click.option("--ref", "ref_value", metavar="REF", default=None)
@click.option("--subpath", metavar="PATH", default=None)
@click.option("--json", "json_output", is_flag=True, help="Emit stable schema 1.0 JSON.")
@click.option(
    "--model",
    default=DEFAULT_FM_MODEL,
    show_default=True,
    callback=_model_option,
    help="Cloud.ru FM model used only for ambiguous candidates.",
)
@click.option("--no-llm", is_flag=True, help="Disable FM review and keep static ambiguity.")
def scan_command(
    source: str,
    ref_value: str | None,
    subpath: str | None,
    json_output: bool,
    model: str,
    no_llm: bool,
) -> None:
    """Scan SOURCE and preview every discovered skill candidate."""
    try:
        spec = parse_source_spec(source, ref_value, subpath)
        report = SkillImporterPipeline().scan(
            spec,
            ScanOptions(use_llm=not no_llm, model=model),
        )
    except ImporterError as exc:
        raise click.ClickException(str(exc)) from None

    if json_output:
        click.echo(
            json.dumps(
                report.to_dict(),
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            )
        )
    else:
        click.echo(_render_human(report))
