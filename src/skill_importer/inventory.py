"""Bounded, no-follow inventory construction for immutable snapshots."""

import hashlib
import os
import re
import stat
import unicodedata
from pathlib import PurePosixPath

from .errors import ImporterError
from .limits import Limits
from .models import Inventory, InventoryEntry, ResolvedSource

_VCS_DIRECTORIES = frozenset({".git", ".hg", ".svn"})
_READ_CHUNK_SIZE = 64 * 1024
_WINDOWS_DRIVE_RE = re.compile(r"[A-Za-z]:")


def _collision_key(path: str) -> str:
    return unicodedata.normalize("NFC", path).casefold()


def _bounded_sorted_children(directory_fd: int, remaining_entries: int) -> list[os.DirEntry[str]]:
    children: list[os.DirEntry[str]] = []
    with os.scandir(directory_fd) as iterator:
        for child in iterator:
            if child.name in _VCS_DIRECTORIES:
                continue
            if len(children) >= remaining_entries:
                raise ImporterError("SCAN_LIMIT_EXCEEDED", "source exceeds the entry count limit")
            children.append(child)
    children.sort(key=lambda item: item.name)
    return children


def _check_path_limits(path: str, limits: Limits, seen: dict[str, str]) -> None:
    normalized = PurePosixPath(path)
    if (
        not path
        or "\x00" in path
        or "\\" in path
        or normalized.is_absolute()
        or _WINDOWS_DRIVE_RE.match(path) is not None
        or ".." in normalized.parts
        or normalized.as_posix() != path
    ):
        raise ImporterError("PATH_TRAVERSAL", "source contains an unsafe source path")
    if len(PurePosixPath(path).parts) > limits.max_depth:
        raise ImporterError("SCAN_LIMIT_EXCEEDED", "source exceeds the path depth limit")
    key = _collision_key(path)
    previous = seen.get(key)
    if previous is not None and previous != path:
        raise ImporterError("PATH_COLLISION", "source contains a Unicode or case path collision")
    seen[key] = path


def _read_regular_file(directory_fd: int, name: str, limits: Limits) -> tuple[bytes, int]:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    file_fd = os.open(name, flags, dir_fd=directory_fd)
    try:
        file_stat = os.fstat(file_fd)
        if not stat.S_ISREG(file_stat.st_mode):
            raise ImporterError("UNSUPPORTED_ENTRY", "source entry changed to an unsafe type")
        if file_stat.st_size > limits.max_file_bytes:
            raise ImporterError("FILE_TOO_LARGE", "source file exceeds the file size limit")

        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(file_fd, min(_READ_CHUNK_SIZE, limits.max_file_bytes + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > limits.max_file_bytes:
                raise ImporterError("FILE_TOO_LARGE", "source file exceeds the file size limit")
        return b"".join(chunks), file_stat.st_mode
    finally:
        os.close(file_fd)


def _decode_text(content: bytes) -> str | None:
    if b"\x00" in content:
        return None
    try:
        return content.decode("utf-8")
    except UnicodeDecodeError:
        return None


def build_inventory(resolved: ResolvedSource, limits: Limits) -> Inventory:
    """Inventory a snapshot without following symlinks or reading special files."""
    root = resolved.snapshot_root
    root_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        root_fd = os.open(root, root_flags)
    except OSError as exc:
        raise ImporterError(
            "SOURCE_UNAVAILABLE", "source snapshot is not a readable directory"
        ) from exc

    entries: list[InventoryEntry] = []
    seen: dict[str, str] = {}
    total_bytes = 0
    entry_count = 0

    def visit(directory_fd: int, parent_parts: tuple[str, ...]) -> None:
        nonlocal entry_count, total_bytes
        children = _bounded_sorted_children(directory_fd, limits.max_entries - entry_count)
        entry_count += len(children)
        for child in children:
            parts = (*parent_parts, child.name)
            relative_path = PurePosixPath(*parts).as_posix()
            _check_path_limits(relative_path, limits, seen)

            entry_stat = child.stat(follow_symlinks=False)
            mode = entry_stat.st_mode
            if stat.S_ISLNK(mode):
                target = os.readlink(child.name, dir_fd=directory_fd)
                entries.append(
                    InventoryEntry(
                        path=relative_path,
                        kind="symlink",
                        size=len(os.fsencode(target)),
                        symlink_target=target,
                    )
                )
            elif stat.S_ISDIR(mode):
                entries.append(InventoryEntry(path=relative_path, kind="directory", size=0))
                flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
                child_fd = os.open(child.name, flags, dir_fd=directory_fd)
                try:
                    visit(child_fd, parts)
                finally:
                    os.close(child_fd)
            elif stat.S_ISREG(mode):
                content, current_mode = _read_regular_file(directory_fd, child.name, limits)
                total_bytes += len(content)
                if total_bytes > limits.max_scan_bytes:
                    raise ImporterError("SCAN_LIMIT_EXCEEDED", "source exceeds the scan byte limit")
                entries.append(
                    InventoryEntry(
                        path=relative_path,
                        kind="file",
                        size=len(content),
                        executable=bool(current_mode & 0o111),
                        sha256=hashlib.sha256(content).hexdigest(),
                        content=_decode_text(content),
                    )
                )
            else:
                raise ImporterError(
                    "UNSUPPORTED_ENTRY", "source contains an unsupported entry type"
                )

    try:
        visit(root_fd, ())
    except OSError as exc:
        raise ImporterError("SOURCE_CHANGED", "source snapshot changed during inventory") from exc
    finally:
        os.close(root_fd)

    return Inventory(entries=tuple(sorted(entries, key=lambda entry: entry.path)))
