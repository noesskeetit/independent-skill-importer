"""Pure import planning and fd-relative atomic skill publication."""

from __future__ import annotations

import ctypes
import errno
import hashlib
import json
import os
import re
import secrets
import stat
import sys
import unicodedata
from collections.abc import Callable, Mapping, Sequence
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Protocol

from .errors import ImporterError
from .limits import Limits
from .models import (
    AnalyzedSkill,
    Classification,
    ImportPlan,
    ImportRecord,
    InventoryEntry,
    PackageBoundary,
    ScanReport,
    SourceKind,
    SourceSpec,
)
from .pipeline import ScanOperation, ScanOptions, SkillImporterPipeline, compute_skill_content_hash

_READ_CHUNK_SIZE = 64 * 1024
_MAX_SLUG_BYTES = 80
_MAX_REJECTED_NAME_CHARS = 512
_MAX_REJECTED_ROOT_CHARS = 4096
_MAX_SYMLINK_STEPS = 128
_WINDOWS_DRIVE_RE = re.compile(r"[A-Za-z]:")
_UNSUPPORTED_FSYNC_ERRNOS = frozenset(
    value
    for value in (
        errno.EINVAL,
        getattr(errno, "ENOTSUP", None),
        getattr(errno, "EOPNOTSUPP", None),
    )
    if value is not None
)
_UNSUPPORTED_RENAME_ERRNOS = frozenset(
    value
    for value in (
        errno.ENOSYS,
        errno.EINVAL,
        getattr(errno, "ENOTSUP", None),
        getattr(errno, "EOPNOTSUPP", None),
    )
    if value is not None
)


@dataclass(frozen=True, slots=True)
class ImportResult:
    """Immutable result assembled before an output directory is published."""

    output_path: Path
    imported: tuple[ImportRecord, ...]
    skipped: tuple[AnalyzedSkill, ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "imported", tuple(self.imported))
        object.__setattr__(self, "skipped", tuple(self.skipped))

    def to_dict(self) -> dict[str, object]:
        """Serialize only bounded result metadata, never full analysis evidence."""
        return {
            "outputPath": str(self.output_path),
            "imported": [record.to_dict() for record in self.imported],
            "skipped": [
                {
                    "candidateId": skill.candidate_id,
                    "name": skill.name,
                    "classification": skill.classification.value,
                    "root": skill.candidate.root,
                }
                for skill in self.skipped
            ],
        }


class AtomicPublisher(Protocol):
    """Kernel-backed no-clobber publication seam."""

    def publish(self, parent_fd: int, staging_name: str, output_name: str) -> None: ...


class NativeAtomicPublisher:
    """Publish with renameatx_np/renameat2 and no unsafe fallback."""

    _RENAME_EXCL = 0x00000004
    _RENAME_NOREPLACE = 0x00000001

    def publish(self, parent_fd: int, staging_name: str, output_name: str) -> None:
        for name in (staging_name, output_name):
            if not name or name in {".", ".."} or "\x00" in name or "/" in name or "\\" in name:
                raise ImporterError("PUBLISH_FAILED", "publication names must be safe basenames")
        if sys.platform == "darwin":
            symbol = "renameatx_np"
            flag = self._RENAME_EXCL
        elif sys.platform.startswith("linux"):
            symbol = "renameat2"
            flag = self._RENAME_NOREPLACE
        else:
            raise ImporterError(
                "ATOMIC_NOREPLACE_UNSUPPORTED",
                "native no-clobber publication is unsupported on this platform",
            )

        try:
            library = ctypes.CDLL(None, use_errno=True)
            function = getattr(library, symbol)
        except (AttributeError, OSError) as exc:
            raise ImporterError(
                "ATOMIC_NOREPLACE_UNSUPPORTED",
                "native no-clobber publication is unavailable",
            ) from exc

        function.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        ]
        function.restype = ctypes.c_int
        ctypes.set_errno(0)
        result = function(
            parent_fd,
            os.fsencode(staging_name),
            parent_fd,
            os.fsencode(output_name),
            flag,
        )
        if result == 0:
            return
        error_number = ctypes.get_errno()
        if error_number in {errno.EEXIST, errno.ENOTEMPTY}:
            raise ImporterError("OUTPUT_EXISTS", "output path already exists")
        if error_number in _UNSUPPORTED_RENAME_ERRNOS:
            raise ImporterError(
                "ATOMIC_NOREPLACE_UNSUPPORTED",
                "filesystem does not support native no-clobber publication",
            )
        raise ImporterError("PUBLISH_FAILED", "atomic output publication failed")


def _slugify_name(name: str) -> str:
    normalized = unicodedata.normalize("NFC", name).strip()
    characters: list[str] = []
    previous_separator = False
    for character in normalized:
        category = unicodedata.category(character)
        if (
            character.isalnum()
            or character in {"-", "_", "."}
            or (category.startswith("M") and characters)
        ):
            candidate = character
            previous_separator = False
        elif previous_separator:
            continue
        else:
            candidate = "-"
            previous_separator = True
        if len("".join((*characters, candidate)).encode("utf-8")) > _MAX_SLUG_BYTES:
            break
        characters.append(candidate)
    slug = "".join(characters).strip("-._")
    if not slug or slug in {".", ".."}:
        return "skill"
    return slug


def _destination_key(value: str) -> str:
    return unicodedata.normalize("NFC", value).casefold()


def _destination_prefix_lengths(groups: Sequence[tuple[str, str]]) -> tuple[int, ...]:
    lengths: list[int] = []
    for index, (slug, content_hash) in enumerate(groups):
        prefix_length = 12
        while prefix_length < len(content_hash):
            candidate = _destination_key(f"{slug}--{content_hash[:prefix_length]}")
            if all(
                other_index == index
                or candidate != _destination_key(f"{other_slug}--{other_hash[:prefix_length]}")
                for other_index, (other_slug, other_hash) in enumerate(groups)
            ):
                break
            prefix_length += 1
        lengths.append(prefix_length)
    return tuple(lengths)


def _bounded_rejected_text(value: str | None, limit: int) -> str | None:
    if value is None:
        return None
    return value[:limit]


def _build_manifest(
    selected: tuple[AnalyzedSkill, ...],
    rejected: tuple[AnalyzedSkill, ...],
    records: tuple[ImportRecord, ...],
) -> dict[str, object]:
    selected_by_id = {skill.candidate_id: skill for skill in selected}
    imported: list[dict[str, object]] = []
    for record in records:
        provenance = []
        for candidate_id in record.candidate_ids:
            skill = selected_by_id[candidate_id]
            source = skill.candidate.source
            provenance.append(
                {
                    "candidateId": candidate_id,
                    "canonicalSourceUrl": source.canonical_url,
                    "resolvedCommitSha": source.resolved_commit_sha,
                    "snapshotSha256": source.snapshot_sha256,
                    "originalRoot": skill.candidate.root,
                    "entrypoint": skill.candidate.entrypoint,
                }
            )
        imported.append(
            {
                "name": record.name,
                "contentHash": record.content_hash,
                "destination": record.destination,
                "candidateIds": list(record.candidate_ids),
                "provenance": provenance,
            }
        )
    rejected_summary = [
        {
            "candidateId": skill.candidate_id,
            "name": _bounded_rejected_text(skill.name, _MAX_REJECTED_NAME_CHARS),
            "classification": skill.classification.value,
            "originalRoot": _bounded_rejected_text(skill.candidate.root, _MAX_REJECTED_ROOT_CHARS),
            "reasonCodes": sorted(reason.code.value for reason in skill.reasons),
        }
        for skill in rejected
    ]
    return {
        "schemaVersion": "1.0",
        "imported": imported,
        "rejected": rejected_summary,
    }


def build_import_plan(report: ScanReport) -> ImportPlan:
    """Build a deterministic, pure, exact partition of one scan report."""
    selected = tuple(
        sorted(
            (skill for skill in report.skills if skill.classification is Classification.PORTABLE),
            key=lambda skill: skill.candidate_id,
        )
    )
    rejected = tuple(
        sorted(
            (
                skill
                for skill in report.skills
                if skill.classification is not Classification.PORTABLE
            ),
            key=lambda skill: skill.candidate_id,
        )
    )
    report_ids = tuple(skill.candidate_id for skill in report.skills)
    if len(report_ids) != len(set(report_ids)):
        raise ValueError("scan report candidate IDs must be unique")
    if {skill.candidate_id for skill in (*selected, *rejected)} != set(report_ids):
        raise ValueError("import plan must exactly partition the scan report")

    grouped: dict[str, list[AnalyzedSkill]] = {}
    for skill in selected:
        skill._validate_portable_for_import()
        if skill.name is None or not skill.name.strip():
            raise ValueError("portable skill requires a non-empty parsed name")
        if skill.content_hash is None or re.fullmatch(r"[0-9a-f]{64}", skill.content_hash) is None:
            raise ValueError("portable skill requires a full content hash")
        grouped.setdefault(skill.content_hash, []).append(skill)

    representatives: list[tuple[AnalyzedSkill, str]] = []
    for content_hash, members in sorted(grouped.items()):
        representative = min(members, key=lambda skill: (skill.candidate.root, skill.candidate_id))
        if representative.name is None:  # pragma: no cover - checked above
            raise ValueError("portable skill requires a parsed name")
        representatives.append((representative, content_hash))
    slug_hashes = tuple(
        (_slugify_name(representative.name or "skill"), content_hash)
        for representative, content_hash in representatives
    )
    prefix_lengths = _destination_prefix_lengths(slug_hashes)
    records = tuple(
        ImportRecord(
            name=representative.name or "skill",
            content_hash=content_hash,
            destination=f"{slug}--{content_hash[:prefix_length]}",
            candidate_ids=tuple(sorted(skill.candidate_id for skill in grouped[content_hash])),
        )
        for (representative, content_hash), (slug, _), prefix_length in zip(
            representatives, slug_hashes, prefix_lengths, strict=True
        )
    )
    records = tuple(sorted(records, key=lambda record: (record.destination, record.content_hash)))
    return ImportPlan(
        selected=selected,
        rejected=rejected,
        records=records,
        manifest_payload=_build_manifest(selected, rejected, records),
    )


@dataclass(frozen=True, slots=True)
class _OutputHandle:
    parent_path: Path
    output_path: Path
    output_name: str
    parent_fd: int
    parent_device: int
    parent_inode: int


@dataclass(frozen=True, slots=True)
class _StagingHandle:
    name: str
    path: Path
    file_fd: int
    device: int
    inode: int


@dataclass(frozen=True, slots=True)
class _Payload:
    record: ImportRecord
    representative: AnalyzedSkill
    entries: tuple[tuple[str, InventoryEntry], ...]


def _lstat_at(directory_fd: int, name: str) -> os.stat_result | None:
    try:
        return os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    except FileNotFoundError:
        return None


def _prepare_output(out: Path) -> _OutputHandle:
    requested = out.expanduser()
    output_name = requested.name
    if not output_name or output_name in {".", ".."} or "\x00" in output_name:
        raise ImporterError("UNSAFE_OUTPUT", "output must have a safe basename")
    try:
        parent_path = requested.parent.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise ImporterError(
            "OUTPUT_PARENT_UNAVAILABLE", "output parent directory is unavailable"
        ) from exc
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        parent_fd = os.open(parent_path, flags)
        parent_stat = os.fstat(parent_fd)
    except OSError as exc:
        raise ImporterError(
            "OUTPUT_PARENT_UNAVAILABLE", "output parent directory is unavailable"
        ) from exc
    if not stat.S_ISDIR(parent_stat.st_mode):
        os.close(parent_fd)
        raise ImporterError("OUTPUT_PARENT_UNAVAILABLE", "output parent is not a directory")
    if _lstat_at(parent_fd, output_name) is not None:
        os.close(parent_fd)
        raise ImporterError("OUTPUT_EXISTS", "output path already exists")
    return _OutputHandle(
        parent_path=parent_path,
        output_path=parent_path / output_name,
        output_name=output_name,
        parent_fd=parent_fd,
        parent_device=parent_stat.st_dev,
        parent_inode=parent_stat.st_ino,
    )


def _path_contains(root: Path, candidate: Path) -> bool:
    try:
        candidate.relative_to(root)
    except ValueError:
        return False
    return True


def _validate_output_relationships(
    spec: SourceSpec,
    operation: ScanOperation,
    output_path: Path,
) -> None:
    roots = [operation.resolved.snapshot_root.resolve()]
    if spec.kind is SourceKind.LOCAL:
        try:
            roots.append(Path(spec.value).expanduser().resolve(strict=True))
        except (OSError, RuntimeError) as exc:
            raise ImporterError("SOURCE_UNAVAILABLE", "local source path is unavailable") from exc
    for root in roots:
        if _path_contains(root, output_path) or _path_contains(output_path, root):
            raise ImporterError(
                "UNSAFE_OUTPUT",
                "output cannot overlap the source or operation snapshot",
            )


def _create_staging(output: _OutputHandle) -> _StagingHandle:
    prefix = f".{output.output_name[:48]}.skill-importer-"
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    for _ in range(64):
        name = f"{prefix}{secrets.token_hex(16)}"
        try:
            os.mkdir(name, 0o700, dir_fd=output.parent_fd)
        except FileExistsError:
            continue
        except OSError as exc:
            raise ImporterError(
                "STAGING_CREATE_FAILED", "staging directory could not be created"
            ) from exc
        try:
            file_fd = os.open(name, flags, dir_fd=output.parent_fd)
            os.fchmod(file_fd, 0o700)
            current = os.fstat(file_fd)
            if not stat.S_ISDIR(current.st_mode):
                raise ImporterError("STAGING_CHANGED", "staging path is not a directory")
            return _StagingHandle(
                name=name,
                path=output.parent_path / name,
                file_fd=file_fd,
                device=current.st_dev,
                inode=current.st_ino,
            )
        except BaseException:
            with suppress(OSError):
                os.rmdir(name, dir_fd=output.parent_fd)
            raise
    raise ImporterError("STAGING_CREATE_FAILED", "a unique staging directory could not be created")


def _relative_payload_path(path: str, root: str) -> str | None:
    if root == ".":
        return path
    prefix = f"{root}/"
    if path.startswith(prefix):
        return path[len(prefix) :]
    return None


def _repo_path(root: str, relative_path: str) -> str:
    if root == ".":
        return relative_path
    return f"{root}/{relative_path}"


def _root_contains(root: str, path: str) -> bool:
    return root == "." or path == root or path.startswith(f"{root}/")


def _validate_mixed_boundaries(
    selected: Sequence[AnalyzedSkill], boundaries: Sequence[PackageBoundary]
) -> None:
    for skill in selected:
        for boundary in boundaries:
            if boundary.package_kind == "mixed" and _root_contains(
                skill.candidate.root, boundary.root
            ):
                raise ImporterError(
                    "PLUGIN_RUNTIME_INSIDE_SKILL_ROOT",
                    "portable selection contains a mixed plugin boundary",
                )


def _validate_copy_plan(
    operation: ScanOperation,
    plan: ImportPlan,
    limits: Limits,
) -> tuple[_Payload, ...]:
    _validate_mixed_boundaries(plan.selected, operation.boundaries)
    selected_by_id = {skill.candidate_id: skill for skill in plan.selected}
    for skill in plan.selected:
        actual_hash = compute_skill_content_hash(skill.candidate, operation.inventory)
        if actual_hash != skill.content_hash:
            raise ImporterError(
                "SOURCE_CHANGED", "selected payload hash no longer matches inventory"
            )

    payloads: list[_Payload] = []
    total_entries = 0
    total_bytes = 0
    for record in plan.records:
        members = [selected_by_id[candidate_id] for candidate_id in record.candidate_ids]
        representative = min(members, key=lambda skill: (skill.candidate.root, skill.candidate_id))
        entries: list[tuple[str, InventoryEntry]] = []
        for entry in operation.inventory.entries:
            relative_path = _relative_payload_path(entry.path, representative.candidate.root)
            if relative_path is not None:
                entries.append((relative_path, entry))
        entries.sort(key=lambda item: (len(PurePosixPath(item[0]).parts), item[0]))
        if representative.candidate.entrypoint not in {
            entry.path for _, entry in entries if entry.kind == "file"
        }:
            raise ImporterError("SOURCE_CHANGED", "selected skill entrypoint is unavailable")
        for relative_path, entry in entries:
            total_entries += 1
            if total_entries > limits.max_entries:
                raise ImporterError("SCAN_LIMIT_EXCEEDED", "import exceeds the entry count limit")
            depth = len(PurePosixPath(relative_path).parts)
            if depth > limits.max_depth:
                raise ImporterError("SCAN_LIMIT_EXCEEDED", "import exceeds the path depth limit")
            if entry.kind == "file":
                if entry.size > limits.max_file_bytes:
                    raise ImporterError("FILE_TOO_LARGE", "import file exceeds the file size limit")
                total_bytes += entry.size
                if total_bytes > limits.max_scan_bytes:
                    raise ImporterError("SCAN_LIMIT_EXCEEDED", "import exceeds the byte limit")
            elif entry.kind not in {"directory", "symlink"}:
                raise ImporterError(
                    "UNSUPPORTED_ENTRY", "selected payload has an unsupported entry"
                )
        payloads.append(_Payload(record, representative, tuple(entries)))
    return tuple(payloads)


def _open_directory_chain(root_fd: int, parts: Sequence[str]) -> int:
    current_fd = os.dup(root_fd)
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        for part in parts:
            next_fd = os.open(part, flags, dir_fd=current_fd)
            os.close(current_fd)
            current_fd = next_fd
        current = os.fstat(current_fd)
        if not stat.S_ISDIR(current.st_mode):
            raise OSError(errno.ENOTDIR, "not a directory")
        return current_fd
    except BaseException:
        with suppress(OSError):
            os.close(current_fd)
        raise


def _source_parent_fd(snapshot_fd: int, repository_path: str) -> tuple[int, str]:
    parts = PurePosixPath(repository_path).parts
    if not parts:
        raise ImporterError("SOURCE_CHANGED", "source entry path is invalid")
    try:
        return _open_directory_chain(snapshot_fd, parts[:-1]), parts[-1]
    except OSError as exc:
        raise ImporterError("SOURCE_CHANGED", "source directory changed during import") from exc


def _destination_parent_fd(staging_fd: int, parts: Sequence[str]) -> tuple[int, str]:
    if not parts:
        raise ImporterError("COPY_FAILED", "destination entry path is invalid")
    try:
        return _open_directory_chain(staging_fd, parts[:-1]), parts[-1]
    except OSError as exc:
        raise ImporterError("COPY_FAILED", "staging directory changed during import") from exc


def _kind_from_mode(mode: int) -> str:
    if stat.S_ISREG(mode):
        return "file"
    if stat.S_ISDIR(mode):
        return "directory"
    if stat.S_ISLNK(mode):
        return "symlink"
    return "unsupported"


def _observe(
    observer: Callable[[InventoryEntry], None] | None,
    entry: InventoryEntry,
) -> None:
    if observer is None:
        return
    try:
        observer(entry)
    except ImporterError:
        raise
    except Exception as exc:
        raise ImporterError("COPY_FAILED", "injected copy observer failed") from exc


def _regular_signature(value: os.stat_result) -> tuple[int, int, int, int, int, int, int]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_size,
        value.st_mode & 0o111,
        value.st_nlink,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def _validate_regular_stat(value: os.stat_result, entry: InventoryEntry) -> None:
    if not stat.S_ISREG(value.st_mode):
        raise ImporterError("SOURCE_CHANGED", "source file changed to an unsafe type")
    if value.st_nlink != 1:
        raise ImporterError("SOURCE_CHANGED", "source file has an unsafe hardlink count")
    if value.st_mode & (stat.S_ISUID | stat.S_ISGID):
        raise ImporterError("SOURCE_CHANGED", "source file has unsafe special mode bits")
    if value.st_size != entry.size or bool(value.st_mode & 0o111) != entry.executable:
        raise ImporterError("SOURCE_CHANGED", "source file metadata changed during import")


def _write_all(file_fd: int, content: bytes) -> None:
    offset = 0
    while offset < len(content):
        written = os.write(file_fd, content[offset:])
        if written <= 0:
            raise OSError(errno.EIO, "short write")
        offset += written


def _fsync_file(file_fd: int) -> None:
    try:
        os.fsync(file_fd)
    except OSError as exc:
        raise ImporterError("FSYNC_FAILED", "output file could not be synchronized") from exc


def _fsync_directory(file_fd: int) -> None:
    try:
        os.fsync(file_fd)
    except OSError as exc:
        if exc.errno in _UNSUPPORTED_FSYNC_ERRNOS:
            return
        raise ImporterError("FSYNC_FAILED", "output directory could not be synchronized") from exc


def _copy_regular_file(
    snapshot_fd: int,
    staging_fd: int,
    source_path: str,
    destination_parts: Sequence[str],
    entry: InventoryEntry,
    limits: Limits,
    observer: Callable[[InventoryEntry], None] | None,
) -> None:
    source_parent, source_name = _source_parent_fd(snapshot_fd, source_path)
    destination_parent = -1
    source_file = -1
    destination_file = -1
    try:
        pre_open = os.stat(source_name, dir_fd=source_parent, follow_symlinks=False)
        _validate_regular_stat(pre_open, entry)
        _observe(observer, entry)
        source_file = os.open(
            source_name,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=source_parent,
        )
        opened = os.fstat(source_file)
        _validate_regular_stat(opened, entry)
        if _regular_signature(pre_open) != _regular_signature(opened):
            raise ImporterError("SOURCE_CHANGED", "source file changed before it was opened")

        destination_parent, destination_name = _destination_parent_fd(staging_fd, destination_parts)
        output_mode = 0o700 if entry.executable else 0o600
        destination_file = os.open(
            destination_name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            output_mode,
            dir_fd=destination_parent,
        )
        os.fchmod(destination_file, output_mode)
        digest = hashlib.sha256()
        copied = 0
        while True:
            chunk = os.read(source_file, _READ_CHUNK_SIZE)
            if not chunk:
                break
            copied += len(chunk)
            if copied > entry.size or copied > limits.max_file_bytes:
                raise ImporterError("SOURCE_CHANGED", "source file grew during import")
            digest.update(chunk)
            _write_all(destination_file, chunk)
        after_read = os.fstat(source_file)
        _validate_regular_stat(after_read, entry)
        if _regular_signature(opened) != _regular_signature(after_read):
            raise ImporterError("SOURCE_CHANGED", "source file mutated while being copied")
        current_path = os.stat(source_name, dir_fd=source_parent, follow_symlinks=False)
        _validate_regular_stat(current_path, entry)
        if _regular_signature(current_path) != _regular_signature(after_read):
            raise ImporterError("SOURCE_CHANGED", "source file path changed while being copied")
        if copied != entry.size or digest.hexdigest() != entry.sha256:
            raise ImporterError("FILE_HASH_MISMATCH", "source file content changed during import")
        _fsync_file(destination_file)
    except ImporterError:
        raise
    except OSError as exc:
        raise ImporterError("COPY_FAILED", "regular file copy failed safely") from exc
    finally:
        for file_fd in (destination_file, source_file, destination_parent, source_parent):
            if file_fd >= 0:
                with suppress(OSError):
                    os.close(file_fd)


def _normalize_symlink_target(relative_path: str, target: str) -> tuple[str, ...]:
    if (
        not target
        or "\x00" in target
        or "\\" in target
        or target.startswith("/")
        or _WINDOWS_DRIVE_RE.match(target) is not None
    ):
        raise ImporterError("SYMLINK_UNSAFE", "symlink has an unsafe target")
    stack = list(PurePosixPath(relative_path).parent.parts)
    if stack == ["."]:
        stack = []
    for part in PurePosixPath(target).parts:
        if part in {"", "."}:
            continue
        if part == "..":
            if not stack:
                raise ImporterError("SYMLINK_ESCAPE", "symlink target escapes the skill root")
            stack.pop()
        else:
            stack.append(part)
    return tuple(stack)


def _lstat_repository_path(snapshot_fd: int, path: str) -> os.stat_result:
    parent_fd, name = _source_parent_fd(snapshot_fd, path)
    try:
        return os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except OSError as exc:
        raise ImporterError("SYMLINK_DANGLING", "symlink chain target is unavailable") from exc
    finally:
        os.close(parent_fd)


def _readlink_repository_path(snapshot_fd: int, path: str) -> tuple[str, os.stat_result]:
    parent_fd, name = _source_parent_fd(snapshot_fd, path)
    try:
        before = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        if not stat.S_ISLNK(before.st_mode):
            raise ImporterError("SYMLINK_CHANGED", "symlink chain entry changed kind")
        target = os.readlink(name, dir_fd=parent_fd)
        after = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        if (before.st_dev, before.st_ino, before.st_mode) != (
            after.st_dev,
            after.st_ino,
            after.st_mode,
        ):
            raise ImporterError("SYMLINK_CHANGED", "symlink changed while being read")
        return target, after
    except ImporterError:
        raise
    except OSError as exc:
        raise ImporterError("SYMLINK_CHANGED", "symlink could not be revalidated") from exc
    finally:
        os.close(parent_fd)


def _validate_symlink_chain(
    snapshot_fd: int,
    payload: _Payload,
    start_relative_path: str,
) -> None:
    entries = {relative: entry for relative, entry in payload.entries}
    start = entries[start_relative_path]
    if start.symlink_target is None:
        raise ImporterError("SYMLINK_CHANGED", "symlink inventory target is unavailable")
    pending = list(_normalize_symlink_target(start_relative_path, start.symlink_target))
    visited: set[str] = {start_relative_path}
    steps = 0
    index = 0
    while index < len(pending):
        steps += 1
        if steps > _MAX_SYMLINK_STEPS:
            raise ImporterError("SYMLINK_CYCLE", "symlink chain exceeds the safe step limit")
        relative_path = PurePosixPath(*pending[: index + 1]).as_posix()
        inventory_entry = entries.get(relative_path)
        if inventory_entry is None:
            raise ImporterError("SYMLINK_DANGLING", "symlink chain has a missing target")
        repository_path = _repo_path(payload.representative.candidate.root, relative_path)
        current_stat = _lstat_repository_path(snapshot_fd, repository_path)
        if _kind_from_mode(current_stat.st_mode) != inventory_entry.kind:
            raise ImporterError("SYMLINK_CHANGED", "symlink chain entry changed kind")
        if inventory_entry.kind == "symlink":
            if relative_path in visited:
                raise ImporterError("SYMLINK_CYCLE", "symlink chain contains a cycle")
            visited.add(relative_path)
            current_target, _ = _readlink_repository_path(snapshot_fd, repository_path)
            if current_target != inventory_entry.symlink_target:
                raise ImporterError("SYMLINK_CHANGED", "symlink chain target changed")
            remaining = pending[index + 1 :]
            pending = [
                *_normalize_symlink_target(relative_path, current_target),
                *remaining,
            ]
            index = 0
            continue
        if index < len(pending) - 1 and inventory_entry.kind != "directory":
            raise ImporterError("SYMLINK_DANGLING", "symlink chain crosses a non-directory")
        index += 1


def _copy_symlink(
    snapshot_fd: int,
    staging_fd: int,
    payload: _Payload,
    relative_path: str,
    entry: InventoryEntry,
    destination_parts: Sequence[str],
    observer: Callable[[InventoryEntry], None] | None,
) -> None:
    source_path = _repo_path(payload.representative.candidate.root, relative_path)
    source_parent, source_name = _source_parent_fd(snapshot_fd, source_path)
    destination_parent = -1
    try:
        before = os.stat(source_name, dir_fd=source_parent, follow_symlinks=False)
        if not stat.S_ISLNK(before.st_mode):
            raise ImporterError("SYMLINK_CHANGED", "symlink changed to another entry kind")
        _observe(observer, entry)
        target = os.readlink(source_name, dir_fd=source_parent)
        after = os.stat(source_name, dir_fd=source_parent, follow_symlinks=False)
        if (before.st_dev, before.st_ino, before.st_mode) != (
            after.st_dev,
            after.st_ino,
            after.st_mode,
        ):
            raise ImporterError("SYMLINK_CHANGED", "symlink changed while being copied")
        if target != entry.symlink_target:
            raise ImporterError("SYMLINK_CHANGED", "symlink target changed during import")
        _normalize_symlink_target(relative_path, target)
        _validate_symlink_chain(snapshot_fd, payload, relative_path)
        destination_parent, destination_name = _destination_parent_fd(staging_fd, destination_parts)
        os.symlink(target, destination_name, dir_fd=destination_parent)
        if os.readlink(destination_name, dir_fd=destination_parent) != target:
            raise ImporterError("COPY_FAILED", "destination symlink verification failed")
    except ImporterError:
        raise
    except OSError as exc:
        raise ImporterError("COPY_FAILED", "symlink copy failed safely") from exc
    finally:
        if destination_parent >= 0:
            with suppress(OSError):
                os.close(destination_parent)
        os.close(source_parent)


def _validate_source_directory(snapshot_fd: int, repository_path: str) -> None:
    current = _lstat_repository_path(snapshot_fd, repository_path)
    if not stat.S_ISDIR(current.st_mode):
        raise ImporterError("SOURCE_CHANGED", "source directory changed during import")


def _create_destination_directory(staging_fd: int, parts: Sequence[str]) -> None:
    parent_fd, name = _destination_parent_fd(staging_fd, parts)
    child_fd = -1
    try:
        os.mkdir(name, 0o700, dir_fd=parent_fd)
        child_fd = _open_directory_chain(parent_fd, (name,))
        os.fchmod(child_fd, 0o700)
    except ImporterError:
        raise
    except OSError as exc:
        raise ImporterError("COPY_FAILED", "destination directory could not be created") from exc
    finally:
        if child_fd >= 0:
            with suppress(OSError):
                os.close(child_fd)
        os.close(parent_fd)


def _copy_payloads(
    operation: ScanOperation,
    payloads: Sequence[_Payload],
    staging_fd: int,
    limits: Limits,
    observer: Callable[[InventoryEntry], None] | None,
) -> tuple[tuple[str, ...], ...]:
    snapshot_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        snapshot_fd = os.open(operation.resolved.snapshot_root, snapshot_flags)
    except OSError as exc:
        raise ImporterError("SOURCE_CHANGED", "source snapshot is unavailable for import") from exc
    created_directories: list[tuple[str, ...]] = []
    try:
        for payload in payloads:
            root_parts = (
                ()
                if payload.representative.candidate.root == "."
                else PurePosixPath(payload.representative.candidate.root).parts
            )
            root_fd = _open_directory_chain(snapshot_fd, root_parts)
            os.close(root_fd)
            _create_destination_directory(staging_fd, (payload.record.destination,))
            created_directories.append((payload.record.destination,))
            for relative_path, entry in payload.entries:
                destination_parts = (
                    payload.record.destination,
                    *PurePosixPath(relative_path).parts,
                )
                source_path = _repo_path(payload.representative.candidate.root, relative_path)
                if entry.kind == "directory":
                    _validate_source_directory(snapshot_fd, source_path)
                    _create_destination_directory(staging_fd, destination_parts)
                    created_directories.append(tuple(destination_parts))
                elif entry.kind == "file":
                    _copy_regular_file(
                        snapshot_fd,
                        staging_fd,
                        source_path,
                        destination_parts,
                        entry,
                        limits,
                        observer,
                    )
                elif entry.kind == "symlink":
                    _copy_symlink(
                        snapshot_fd,
                        staging_fd,
                        payload,
                        relative_path,
                        entry,
                        destination_parts,
                        observer,
                    )
                else:  # pragma: no cover - validated before destination writes
                    raise ImporterError("UNSUPPORTED_ENTRY", "unsupported selected payload entry")
    except OSError as exc:
        raise ImporterError("COPY_FAILED", "payload copy failed safely") from exc
    finally:
        with suppress(OSError):
            os.close(snapshot_fd)
    return tuple(created_directories)


def _write_manifest(staging_fd: int, manifest_bytes: bytes) -> None:
    file_fd = -1
    try:
        file_fd = os.open(
            "import-manifest.json",
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600,
            dir_fd=staging_fd,
        )
        os.fchmod(file_fd, 0o600)
        _write_all(file_fd, manifest_bytes)
        _fsync_file(file_fd)
    except ImporterError:
        raise
    except OSError as exc:
        raise ImporterError(
            "MANIFEST_WRITE_FAILED", "import manifest could not be written"
        ) from exc
    finally:
        if file_fd >= 0:
            with suppress(OSError):
                os.close(file_fd)


def _fsync_created_directories(staging_fd: int, directories: Sequence[tuple[str, ...]]) -> None:
    for parts in sorted(set(directories), key=lambda item: (-len(item), item)):
        try:
            directory_fd = _open_directory_chain(staging_fd, parts)
        except OSError as exc:
            raise ImporterError("FSYNC_FAILED", "output directory changed before fsync") from exc
        try:
            _fsync_directory(directory_fd)
        finally:
            os.close(directory_fd)
    _fsync_directory(staging_fd)


def _manifest_bytes(plan: ImportPlan) -> bytes:
    def allowlisted_json(value: object) -> object:
        if isinstance(value, Mapping):
            return {key: allowlisted_json(item) for key, item in value.items()}
        if isinstance(value, tuple):
            return [allowlisted_json(item) for item in value]
        return value

    try:
        encoded = json.dumps(
            allowlisted_json(plan.manifest_payload),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ImporterError("INVALID_IMPORT_PLAN", "import manifest is not canonical JSON") from exc
    return encoded + b"\n"


def _remove_directory_contents(directory_fd: int) -> None:
    with os.scandir(directory_fd) as iterator:
        names = sorted(entry.name for entry in iterator)
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    for name in names:
        try:
            current = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        except FileNotFoundError:
            continue
        if stat.S_ISDIR(current.st_mode):
            child_fd = os.open(name, flags, dir_fd=directory_fd)
            try:
                _remove_directory_contents(child_fd)
            finally:
                os.close(child_fd)
            os.rmdir(name, dir_fd=directory_fd)
        else:
            os.unlink(name, dir_fd=directory_fd)


def _cleanup_staging(
    parent_fd: int,
    staging_name: str,
    expected_device: int,
    expected_inode: int,
) -> None:
    current = _lstat_at(parent_fd, staging_name)
    if current is None:
        return
    if (
        not stat.S_ISDIR(current.st_mode)
        or current.st_dev != expected_device
        or current.st_ino != expected_inode
    ):
        return
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    staging_fd = os.open(staging_name, flags, dir_fd=parent_fd)
    try:
        opened = os.fstat(staging_fd)
        if opened.st_dev != expected_device or opened.st_ino != expected_inode:
            return
        _remove_directory_contents(staging_fd)
    finally:
        os.close(staging_fd)
    final = _lstat_at(parent_fd, staging_name)
    if (
        final is not None
        and stat.S_ISDIR(final.st_mode)
        and final.st_dev == expected_device
        and final.st_ino == expected_inode
    ):
        os.rmdir(staging_name, dir_fd=parent_fd)


def _safe_cleanup_staging(output: _OutputHandle, staging: _StagingHandle) -> None:
    with suppress(BaseException):
        _cleanup_staging(
            output.parent_fd,
            staging.name,
            staging.device,
            staging.inode,
        )


def _verify_parent(output: _OutputHandle) -> None:
    try:
        current = os.stat(output.parent_path, follow_symlinks=False)
    except OSError as exc:
        raise ImporterError("OUTPUT_PARENT_CHANGED", "output parent path changed") from exc
    if (
        not stat.S_ISDIR(current.st_mode)
        or current.st_dev != output.parent_device
        or current.st_ino != output.parent_inode
    ):
        raise ImporterError("OUTPUT_PARENT_CHANGED", "output parent path changed")


def _verify_staging(output: _OutputHandle, staging: _StagingHandle) -> None:
    current = _lstat_at(output.parent_fd, staging.name)
    if (
        current is None
        or not stat.S_ISDIR(current.st_mode)
        or current.st_dev != staging.device
        or current.st_ino != staging.inode
    ):
        raise ImporterError("STAGING_CHANGED", "staging directory identity changed")


class SkillImporter:
    """Build, copy, fsync, and atomically publish portable skill payloads."""

    def __init__(
        self,
        pipeline: SkillImporterPipeline | None = None,
        *,
        publisher: AtomicPublisher | None = None,
        copy_observer: Callable[[InventoryEntry], None] | None = None,
        before_publish: Callable[[Path], None] | None = None,
    ) -> None:
        self.pipeline = pipeline or SkillImporterPipeline()
        self.publisher = publisher or NativeAtomicPublisher()
        self.copy_observer = copy_observer
        self.before_publish = before_publish

    def import_source(
        self,
        spec: SourceSpec,
        out: Path,
        options: ScanOptions | None = None,
    ) -> ImportResult:
        """Run a fresh scan and publish a new output directory or nothing."""
        output: _OutputHandle | None = None
        staging: _StagingHandle | None = None
        staging_fd_open = False
        published = False
        result: ImportResult | None = None
        try:
            with self.pipeline.scan_operation(spec, options) as operation:
                try:
                    plan = build_import_plan(operation.report)
                except ValueError as exc:
                    raise ImporterError(
                        "INVALID_IMPORT_PLAN", "scan produced an invalid import plan"
                    ) from exc
                manifest_bytes = _manifest_bytes(plan)
                payloads = _validate_copy_plan(operation, plan, self.pipeline.limits)
                output = _prepare_output(out)
                _validate_output_relationships(spec, operation, output.output_path)
                staging = _create_staging(output)
                staging_fd_open = True
                created_directories = _copy_payloads(
                    operation,
                    payloads,
                    staging.file_fd,
                    self.pipeline.limits,
                    self.copy_observer,
                )
                _write_manifest(staging.file_fd, manifest_bytes)
                _fsync_created_directories(staging.file_fd, created_directories)
                result = ImportResult(
                    output_path=output.output_path,
                    imported=plan.records,
                    skipped=plan.rejected,
                )
                with suppress(OSError):
                    os.close(staging.file_fd)
                staging_fd_open = False

            if output is None or staging is None or result is None:  # pragma: no cover
                raise ImporterError("IMPORT_FAILED", "import operation produced no result")
            if self.before_publish is not None:
                self.before_publish(staging.path)
            _verify_parent(output)
            _verify_staging(output, staging)
            self.publisher.publish(output.parent_fd, staging.name, output.output_name)
            published = True
            with suppress(OSError):
                os.fsync(output.parent_fd)
            return result
        except OSError as exc:
            raise ImporterError(
                "IMPORT_FAILED", "filesystem import operation failed safely"
            ) from exc
        finally:
            if staging_fd_open and staging is not None:
                with suppress(OSError):
                    os.close(staging.file_fd)
            if not published and output is not None and staging is not None:
                _safe_cleanup_staging(output, staging)
            if output is not None:
                with suppress(OSError):
                    os.close(output.parent_fd)
