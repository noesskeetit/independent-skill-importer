"""Safe parsing and immutable snapshot resolution for importer sources."""

import hashlib
import json
import os
import re
import selectors
import stat
import subprocess
import tarfile
import tempfile
import time
import unicodedata
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Protocol
from urllib.parse import urlsplit

from .errors import ImporterError
from .inventory import _bounded_sorted_children, build_inventory
from .limits import Limits
from .models import ResolvedSource, SourceKind, SourceSpec

_GIT_SCHEMES = frozenset({"https", "ssh", "git"})
_GIT_SCP_RE = re.compile(r"(?P<user>[A-Za-z0-9._-]+)@(?P<host>[A-Za-z0-9.-]+):(?P<path>[^\s]+)")
_VCS_DIRECTORIES = frozenset({".git", ".hg", ".svn"})
_READ_CHUNK_SIZE = 64 * 1024
_MAX_GIT_CAPTURE_BYTES = 1024 * 1024
_GIT_SHA_RE = re.compile(r"[0-9a-f]{40}")
_WINDOWS_DRIVE_RE = re.compile(r"[A-Za-z]:")


def _unsafe_git_url() -> ImporterError:
    return ImporterError("UNSAFE_GIT_URL", "unsafe Git URL")


def _validate_remote_url(value: str, *, allow_file_transport: bool = False) -> SourceKind:
    if "\x00" in value or value.startswith(("ext::", "file::")) or "::" in value:
        raise _unsafe_git_url()
    scp_match = _GIT_SCP_RE.fullmatch(value)
    if scp_match is not None:
        host = scp_match.group("host")
        path = scp_match.group("path")
        if any(part.startswith("-") for part in (*host.split("."), *path.split("/"))):
            raise _unsafe_git_url()
        return SourceKind.GITHUB if host.casefold() == "github.com" else SourceKind.GIT

    try:
        parsed = urlsplit(value)
        hostname = parsed.hostname
        password = parsed.password
        username = parsed.username
    except ValueError as exc:
        raise _unsafe_git_url() from exc
    if parsed.scheme == "file":
        if allow_file_transport and parsed.netloc in {"", "localhost"} and parsed.path:
            return SourceKind.GIT
        raise _unsafe_git_url()
    if parsed.scheme not in _GIT_SCHEMES:
        raise _unsafe_git_url()
    if not hostname or password is not None or parsed.query or parsed.fragment:
        raise _unsafe_git_url()
    if parsed.scheme in {"https", "git"} and username is not None:
        raise _unsafe_git_url()
    if (
        not parsed.path
        or "\\" in parsed.path
        or any(part.startswith("-") for part in (*hostname.split("."), *parsed.path.split("/")))
    ):
        raise _unsafe_git_url()
    return SourceKind.GITHUB if hostname.casefold() == "github.com" else SourceKind.GIT


def parse_source_spec(value: str, ref: str | None, subpath: str | None) -> SourceSpec:
    """Normalize a user source string without invoking Git or touching source files."""
    if not value or "\x00" in value:
        raise ImporterError("INVALID_SOURCE", "source input must not be empty")
    looks_remote = (
        "://" in value
        or "::" in value
        or _GIT_SCP_RE.fullmatch(value) is not None
        or value.startswith("file:")
    )
    if looks_remote:
        kind = _validate_remote_url(value)
        try:
            return SourceSpec(kind=kind, value=value, ref=ref, subpath=subpath)
        except ValueError as exc:
            raise ImporterError("INVALID_SOURCE", "source ref or subpath is invalid") from exc
    if ref is not None:
        raise ImporterError("INVALID_SOURCE", "local source does not accept a Git ref")
    try:
        return SourceSpec.local(value, subpath=subpath)
    except (OSError, ValueError) as exc:
        raise ImporterError("INVALID_SOURCE", "local source path is invalid") from exc


class GitRunner(Protocol):
    """Injected boundary for Git process and network operations."""

    allow_file_transport: bool

    def run_capture(
        self,
        arguments: Sequence[str],
        *,
        timeout: int,
        cwd: Path | None = None,
    ) -> bytes: ...

    def run_archive(
        self,
        arguments: Sequence[str],
        destination: Path,
        *,
        max_bytes: int,
        timeout: int,
    ) -> None: ...


class SubprocessGitRunner:
    """Run Git with argv-only subprocesses and isolated configuration."""

    def __init__(
        self,
        *,
        allow_file_transport: bool = False,
        max_capture_bytes: int = _MAX_GIT_CAPTURE_BYTES,
    ) -> None:
        if max_capture_bytes <= 0:
            raise ValueError("Git capture byte limit must be positive")
        self.allow_file_transport = allow_file_transport
        self.max_capture_bytes = max_capture_bytes

    def run_capture(
        self,
        arguments: Sequence[str],
        *,
        timeout: int,
        cwd: Path | None = None,
    ) -> bytes:
        with tempfile.TemporaryDirectory(prefix="skill-importer-git-home-") as home:
            try:
                process = subprocess.Popen(
                    ["git", *arguments],
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    cwd=cwd,
                    env=self._environment(Path(home)),
                    shell=False,
                )
            except OSError as exc:
                raise ImporterError("GIT_COMMAND_FAILED", "Git command failed safely") from exc

            try:
                return self._capture_process(
                    process,
                    max_bytes=self.max_capture_bytes,
                    timeout=timeout,
                )
            except BaseException:
                self._terminate(process)
                raise

    @staticmethod
    def _capture_process(
        process: subprocess.Popen[bytes],
        *,
        max_bytes: int,
        timeout: int,
    ) -> bytes:
        if process.stdout is None or process.stderr is None:  # pragma: no cover - fixed by Popen
            raise ImporterError("GIT_COMMAND_FAILED", "Git command output streams are unavailable")
        selector = selectors.DefaultSelector()
        selector.register(process.stdout, selectors.EVENT_READ, "stdout")
        selector.register(process.stderr, selectors.EVENT_READ, "stderr")
        deadline = time.monotonic() + timeout
        total = 0
        stdout_chunks: list[bytes] = []
        try:
            while selector.get_map():
                remaining = deadline - time.monotonic()
                events = selector.select(remaining) if remaining > 0 else []
                if not events:
                    raise ImporterError("GIT_TIMEOUT", "Git command timed out")
                for key, _ in events:
                    chunk = os.read(key.fd, min(_READ_CHUNK_SIZE, max_bytes - total + 1))
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    total += len(chunk)
                    if total > max_bytes:
                        raise ImporterError(
                            "GIT_OUTPUT_LIMIT",
                            "Git command output exceeds the byte limit",
                        )
                    if key.data == "stdout":
                        stdout_chunks.append(chunk)
            remaining = max(0.001, deadline - time.monotonic())
            try:
                return_code = process.wait(timeout=remaining)
            except subprocess.TimeoutExpired as exc:
                raise ImporterError("GIT_TIMEOUT", "Git command timed out") from exc
            if return_code != 0:
                raise ImporterError("GIT_COMMAND_FAILED", "Git command failed safely")
            return b"".join(stdout_chunks)
        finally:
            selector.close()
            process.stdout.close()
            process.stderr.close()

    def run_archive(
        self,
        arguments: Sequence[str],
        destination: Path,
        *,
        max_bytes: int,
        timeout: int,
    ) -> None:
        """Stream Git stdout to a bounded file and stop the process on overflow."""
        with tempfile.TemporaryDirectory(prefix="skill-importer-git-home-") as home:
            try:
                process = subprocess.Popen(
                    ["git", *arguments],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,
                    env=self._environment(Path(home)),
                    shell=False,
                )
            except OSError as exc:
                raise ImporterError(
                    "GIT_COMMAND_FAILED", "Git archive command failed safely"
                ) from exc

            try:
                self._stream_process(process, destination, max_bytes=max_bytes, timeout=timeout)
            except BaseException:
                self._terminate(process)
                destination.unlink(missing_ok=True)
                raise

    @staticmethod
    def _stream_process(
        process: subprocess.Popen[bytes],
        destination: Path,
        *,
        max_bytes: int,
        timeout: int,
    ) -> None:
        if process.stdout is None:  # pragma: no cover - fixed by Popen construction
            raise ImporterError("GIT_COMMAND_FAILED", "Git archive stream is unavailable")
        selector = selectors.DefaultSelector()
        selector.register(process.stdout, selectors.EVENT_READ)
        deadline = time.monotonic() + timeout
        total = 0
        try:
            with destination.open("xb") as output:
                while True:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise ImporterError("GIT_TIMEOUT", "Git archive command timed out")
                    if not selector.select(remaining):
                        raise ImporterError("GIT_TIMEOUT", "Git archive command timed out")
                    chunk = os.read(process.stdout.fileno(), _READ_CHUNK_SIZE)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > max_bytes:
                        raise ImporterError(
                            "SCAN_LIMIT_EXCEEDED", "Git archive exceeds the archive byte limit"
                        )
                    output.write(chunk)
            remaining = max(0.001, deadline - time.monotonic())
            try:
                return_code = process.wait(timeout=remaining)
            except subprocess.TimeoutExpired as exc:
                raise ImporterError("GIT_TIMEOUT", "Git archive command timed out") from exc
            if return_code != 0:
                raise ImporterError("GIT_COMMAND_FAILED", "Git archive command failed safely")
        finally:
            selector.close()
            process.stdout.close()

    @staticmethod
    def _terminate(process: subprocess.Popen[bytes]) -> None:
        if process.poll() is not None:
            return
        process.terminate()
        try:
            process.wait(timeout=1)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()

    def _environment(self, home: Path) -> dict[str, str]:
        protocols = ["https", "ssh", "git"]
        if self.allow_file_transport:
            protocols.append("file")
        config: list[tuple[str, str]] = [
            ("protocol.allow", "never"),
            ("core.hooksPath", os.devnull),
            *((f"protocol.{protocol}.allow", "always") for protocol in protocols),
        ]
        environment = {
            **{
                key: value
                for key, value in os.environ.items()
                if not key.startswith("GIT_")
                and key not in {"HOME", "SSH_ASKPASS", "SSH_ASKPASS_REQUIRE", "XDG_CONFIG_HOME"}
            },
            "HOME": str(home),
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_CONFIG_COUNT": str(len(config)),
        }
        for index, (key, value) in enumerate(config):
            environment[f"GIT_CONFIG_KEY_{index}"] = key
            environment[f"GIT_CONFIG_VALUE_{index}"] = value
        return environment


def _copy_local_tree(source: Path, destination: Path, limits: Limits) -> None:
    root_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        root_fd = os.open(source, root_flags)
    except OSError as exc:
        raise ImporterError("SOURCE_UNAVAILABLE", "local source directory is not readable") from exc
    entry_count = 0
    total_bytes = 0

    def copy_directory(source_fd: int, target: Path, parent_parts: tuple[str, ...]) -> None:
        nonlocal entry_count, total_bytes
        children = _bounded_sorted_children(source_fd, limits.max_entries - entry_count)
        entry_count += len(children)
        for child in children:
            parts = (*parent_parts, child.name)
            relative_path = PurePosixPath(*parts).as_posix()
            if (
                "\\" in relative_path
                or _WINDOWS_DRIVE_RE.match(relative_path) is not None
                or ".." in PurePosixPath(relative_path).parts
            ):
                raise ImporterError("PATH_TRAVERSAL", "source contains an unsafe source path")
            if len(parts) > limits.max_depth:
                raise ImporterError("SCAN_LIMIT_EXCEEDED", "source exceeds the path depth limit")
            child_stat = child.stat(follow_symlinks=False)
            child_target = target / child.name
            if stat.S_ISLNK(child_stat.st_mode):
                os.symlink(os.readlink(child.name, dir_fd=source_fd), child_target)
            elif stat.S_ISDIR(child_stat.st_mode):
                child_target.mkdir(mode=0o700)
                flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
                child_fd = os.open(child.name, flags, dir_fd=source_fd)
                try:
                    copy_directory(child_fd, child_target, parts)
                finally:
                    os.close(child_fd)
            elif stat.S_ISREG(child_stat.st_mode):
                if child_stat.st_size > limits.max_file_bytes:
                    raise ImporterError("FILE_TOO_LARGE", "source file exceeds the file size limit")
                flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
                file_fd = os.open(child.name, flags, dir_fd=source_fd)
                try:
                    current_stat = os.fstat(file_fd)
                    if not stat.S_ISREG(current_stat.st_mode):
                        raise ImporterError(
                            "UNSUPPORTED_ENTRY", "source entry changed to an unsafe type"
                        )
                    copied = 0
                    with child_target.open("xb") as output:
                        while True:
                            chunk = os.read(file_fd, _READ_CHUNK_SIZE)
                            if not chunk:
                                break
                            copied += len(chunk)
                            total_bytes += len(chunk)
                            if copied > limits.max_file_bytes:
                                raise ImporterError(
                                    "FILE_TOO_LARGE", "source file exceeds the file size limit"
                                )
                            if total_bytes > limits.max_scan_bytes:
                                raise ImporterError(
                                    "SCAN_LIMIT_EXCEEDED", "source exceeds the scan byte limit"
                                )
                            output.write(chunk)
                    os.chmod(child_target, 0o700 if current_stat.st_mode & 0o111 else 0o600)
                finally:
                    os.close(file_fd)
            else:
                raise ImporterError(
                    "UNSUPPORTED_ENTRY", "source contains an unsupported entry type"
                )

    try:
        copy_directory(root_fd, destination, ())
    except OSError as exc:
        raise ImporterError("SOURCE_CHANGED", "local source changed during snapshot") from exc
    finally:
        os.close(root_fd)


def _snapshot_hash(root: Path, limits: Limits) -> str:
    placeholder = ResolvedSource(
        spec=SourceSpec.local(root),
        canonical_url=root.as_uri(),
        snapshot_root=root,
        snapshot_sha256="0" * 64,
        discovery_scope=".",
    )
    inventory = build_inventory(placeholder, limits)
    payload = [
        {
            "path": entry.path,
            "kind": entry.kind,
            "size": entry.size,
            "executable": entry.executable,
            "symlink_target": entry.symlink_target,
            "sha256": entry.sha256,
        }
        for entry in inventory.entries
    ]
    encoded = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _local_git_head(source: Path, runner: GitRunner, timeout: int) -> str | None:
    try:
        output = runner.run_capture(
            ["-C", str(source), "rev-parse", "--verify", "HEAD^{commit}"],
            timeout=timeout,
        )
    except ImporterError:
        return None
    candidate = output.decode("ascii", errors="ignore").strip()
    return candidate if _GIT_SHA_RE.fullmatch(candidate) else None


def _validate_discovery_scope(root: Path, scope: str) -> None:
    if scope == ".":
        return
    current = root
    for part in PurePosixPath(scope).parts:
        current = current / part
        try:
            current_stat = current.lstat()
        except OSError as exc:
            raise ImporterError("INVALID_SUBPATH", "source subpath does not exist") from exc
        if stat.S_ISLNK(current_stat.st_mode):
            raise ImporterError("INVALID_SUBPATH", "source subpath cannot cross a symlink")
    if not stat.S_ISDIR(current_stat.st_mode):
        raise ImporterError("INVALID_SUBPATH", "source subpath must select a directory")


def _create_temporary_root(workspace: Path, prefix: str) -> Path:
    try:
        workspace.mkdir(parents=True, exist_ok=True)
        return Path(tempfile.mkdtemp(prefix=prefix, dir=workspace)).resolve()
    except (OSError, ValueError) as exc:
        raise ImporterError("SOURCE_SETUP_FAILED", "source workspace could not be created") from exc


def snapshot_local(
    source: Path,
    workspace: Path,
    limits: Limits,
    *,
    spec: SourceSpec | None = None,
    git_runner: GitRunner | None = None,
) -> ResolvedSource:
    """Copy a local directory into a bounded immutable working snapshot."""
    try:
        canonical_source = source.expanduser().resolve(strict=True)
    except (OSError, RuntimeError, ValueError) as exc:
        raise ImporterError("SOURCE_UNAVAILABLE", "local source directory is unavailable") from exc
    if not canonical_source.is_dir():
        raise ImporterError("SOURCE_UNAVAILABLE", "local source must be a directory")
    if spec is None:
        spec = SourceSpec.local(canonical_source)
    if spec.kind is not SourceKind.LOCAL:
        raise ImporterError("INVALID_SOURCE", "local snapshot requires a local source")

    snapshot_root = _create_temporary_root(workspace, "snapshot-")
    _copy_local_tree(canonical_source, snapshot_root, limits)
    discovery_scope = spec.subpath or "."
    _validate_discovery_scope(snapshot_root, discovery_scope)
    snapshot_sha256 = _snapshot_hash(snapshot_root, limits)
    runner = git_runner or SubprocessGitRunner()
    resolved_commit_sha = _local_git_head(canonical_source, runner, limits.git_timeout_seconds)
    return ResolvedSource(
        spec=spec,
        canonical_url=canonical_source.as_uri(),
        snapshot_root=snapshot_root,
        snapshot_sha256=snapshot_sha256,
        discovery_scope=discovery_scope,
        resolved_commit_sha=resolved_commit_sha,
    )


@dataclass(frozen=True, slots=True)
class _GitHubLocation:
    canonical_url: str
    route_kind: str | None
    route_tail: tuple[str, ...]


def _github_location(value: str) -> _GitHubLocation:
    scp_match = _GIT_SCP_RE.fullmatch(value)
    if scp_match is not None:
        path_parts = tuple(part for part in scp_match.group("path").split("/") if part)
    else:
        try:
            parsed = urlsplit(value)
        except ValueError as exc:
            raise _unsafe_git_url() from exc
        path_parts = tuple(part for part in parsed.path.split("/") if part)
    if len(path_parts) < 2 or any(part in {".", ".."} for part in path_parts):
        raise _unsafe_git_url()

    owner = path_parts[0]
    repository = path_parts[1].removesuffix(".git")
    if not owner or not repository or owner.startswith("-") or repository.startswith("-"):
        raise _unsafe_git_url()

    route_kind: str | None = None
    route_tail: tuple[str, ...] = ()
    if len(path_parts) > 2:
        if path_parts[2] not in {"tree", "blob"} or len(path_parts) < 4:
            raise _unsafe_git_url()
        route_kind = path_parts[2]
        route_tail = path_parts[3:]
    return _GitHubLocation(
        canonical_url=f"https://github.com/{owner}/{repository}.git",
        route_kind=route_kind,
        route_tail=route_tail,
    )


def _remote_ref_names(output: bytes) -> tuple[str, ...]:
    names: set[str] = set()
    try:
        decoded = output.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ImporterError("GIT_COMMAND_FAILED", "Git returned invalid reference data") from exc
    for line in decoded.splitlines():
        fields = line.split()
        if len(fields) != 2 or _GIT_SHA_RE.fullmatch(fields[0]) is None:
            continue
        reference = fields[1]
        for prefix in ("refs/heads/", "refs/tags/"):
            if reference.startswith(prefix) and not reference.endswith("^{}"):
                names.add(reference.removeprefix(prefix))
    return tuple(sorted(names))


def _github_ref_and_scope(
    spec: SourceSpec,
    location: _GitHubLocation,
    runner: GitRunner,
    timeout: int,
) -> tuple[str | None, str]:
    if location.route_kind is None:
        return spec.ref, spec.subpath or "."

    remote_output = runner.run_capture(
        ["ls-remote", "--heads", "--tags", "--", location.canonical_url],
        timeout=timeout,
    )
    route_text = "/".join(location.route_tail)
    matches = [
        name
        for name in _remote_ref_names(remote_output)
        if route_text == name or route_text.startswith(f"{name}/")
    ]
    matched_url_ref = max(matches, key=len) if matches else None
    if matched_url_ref is None and spec.ref is None:
        raise ImporterError(
            "AMBIGUOUS_GITHUB_REF",
            "GitHub tree or blob URL has an ambiguous ref; pass --ref",
        )

    url_ref_parts = 1 if matched_url_ref is None else len(PurePosixPath(matched_url_ref).parts)
    routed_path = location.route_tail[url_ref_parts:]
    requested_ref = spec.ref or matched_url_ref

    if spec.subpath is not None:
        return requested_ref, spec.subpath
    if location.route_kind == "blob":
        if not routed_path:
            raise ImporterError("INVALID_SOURCE", "GitHub blob URL must select a file")
        routed_path = routed_path[:-1]
    scope = PurePosixPath(*routed_path).as_posix() if routed_path else "."
    return requested_ref, scope


def _normalize_archive_path(name: str) -> tuple[str, tuple[str, ...]]:
    candidate = name.removesuffix("/")
    if (
        not candidate
        or candidate == "."
        or "\x00" in candidate
        or "\\" in candidate
        or candidate.startswith("/")
        or _WINDOWS_DRIVE_RE.match(candidate) is not None
    ):
        raise ImporterError("PATH_TRAVERSAL", "Git archive contains archive path traversal")
    path = PurePosixPath(candidate)
    if ".." in path.parts or "." in path.parts or path.as_posix() != candidate:
        raise ImporterError("PATH_TRAVERSAL", "Git archive contains archive path traversal")
    return candidate, path.parts


def _archive_collision_key(path: str) -> str:
    return unicodedata.normalize("NFC", path).casefold()


def _extract_git_archive(archive: Path, snapshot_root: Path, limits: Limits) -> None:
    try:
        archive_stat = archive.lstat()
    except OSError as exc:
        raise ImporterError("GIT_COMMAND_FAILED", "Git archive output is unavailable") from exc
    if not stat.S_ISREG(archive_stat.st_mode):
        raise ImporterError("GIT_COMMAND_FAILED", "Git archive output is not a regular file")
    if archive_stat.st_size > limits.max_archive_bytes:
        raise ImporterError("SCAN_LIMIT_EXCEEDED", "Git archive exceeds the archive byte limit")

    normalized_paths: dict[str, str] = {}
    materialized: dict[str, str] = {}
    archive_members = 0
    total_bytes = 0

    def register(path: str, kind: str) -> bool:
        if len(PurePosixPath(path).parts) > limits.max_depth:
            raise ImporterError("SCAN_LIMIT_EXCEEDED", "source exceeds the path depth limit")
        key = _archive_collision_key(path)
        previous = normalized_paths.get(key)
        if previous is not None and previous != path:
            raise ImporterError(
                "PATH_COLLISION", "source contains a Unicode or case path collision"
            )
        existing_kind = materialized.get(path)
        if existing_kind is not None:
            if existing_kind == kind == "directory":
                return False
            raise ImporterError("PATH_COLLISION", "source contains a duplicate path collision")
        if len(materialized) >= limits.max_entries:
            raise ImporterError("SCAN_LIMIT_EXCEEDED", "source exceeds the entry count limit")
        normalized_paths[key] = path
        materialized[path] = kind
        return True

    def ensure_parents(parts: tuple[str, ...]) -> None:
        for index in range(1, len(parts)):
            parent = PurePosixPath(*parts[:index]).as_posix()
            kind = materialized.get(parent)
            if kind == "symlink":
                raise ImporterError("PATH_TRAVERSAL", "Git archive path has a symlink ancestor")
            if kind not in {None, "directory"}:
                raise ImporterError("PATH_COLLISION", "source contains a parent path collision")
            if kind is None:
                register(parent, "directory")
                (snapshot_root / parent).mkdir(mode=0o700)

    try:
        with tarfile.open(archive, mode="r:*") as tar:
            for member in tar:
                archive_members += 1
                if archive_members > limits.max_entries:
                    raise ImporterError(
                        "SCAN_LIMIT_EXCEEDED", "source exceeds the entry count limit"
                    )
                path, parts = _normalize_archive_path(member.name)
                if _VCS_DIRECTORIES.intersection(parts):
                    continue
                if not (member.isdir() or member.isreg() or member.issym()):
                    raise ImporterError(
                        "UNSUPPORTED_ENTRY", "Git archive has an unsupported archive entry type"
                    )

                ensure_parents(parts)
                destination = snapshot_root.joinpath(*parts)
                if member.isdir():
                    if register(path, "directory"):
                        destination.mkdir(mode=0o700)
                    continue
                if member.issym():
                    register(path, "symlink")
                    if "\x00" in member.linkname:
                        raise ImporterError(
                            "UNSUPPORTED_ENTRY", "Git archive has an invalid symlink target"
                        )
                    os.symlink(member.linkname, destination)
                    continue

                register(path, "file")
                if member.size < 0 or member.size > limits.max_file_bytes:
                    raise ImporterError("FILE_TOO_LARGE", "source file exceeds the file size limit")
                total_bytes += member.size
                if total_bytes > limits.max_scan_bytes:
                    raise ImporterError("SCAN_LIMIT_EXCEEDED", "source exceeds the scan byte limit")
                extracted = tar.extractfile(member)
                if extracted is None:
                    raise ImporterError("UNSUPPORTED_ENTRY", "Git archive file data is unavailable")
                copied = 0
                with extracted, destination.open("xb") as output:
                    while True:
                        chunk = extracted.read(_READ_CHUNK_SIZE)
                        if not chunk:
                            break
                        copied += len(chunk)
                        if copied > member.size or copied > limits.max_file_bytes:
                            raise ImporterError(
                                "FILE_TOO_LARGE", "source file exceeds the file size limit"
                            )
                        output.write(chunk)
                if copied != member.size:
                    raise ImporterError(
                        "INVALID_ARCHIVE", "Git archive contains truncated file data"
                    )
                os.chmod(destination, 0o700 if member.mode & 0o111 else 0o600)
    except (OSError, tarfile.TarError) as exc:
        raise ImporterError("INVALID_ARCHIVE", "Git archive is invalid or changed") from exc


class SourceResolver:
    """Resolve local and remote specifications into bounded immutable snapshots."""

    def __init__(self, *, limits: Limits, git_runner: GitRunner | None = None) -> None:
        self.limits = limits
        self.git_runner = git_runner or SubprocessGitRunner()

    def resolve(self, spec: SourceSpec, workspace: Path) -> ResolvedSource:
        """Resolve ``spec`` without executing repository-controlled content."""
        if spec.kind is SourceKind.LOCAL:
            return snapshot_local(
                Path(spec.value),
                workspace,
                self.limits,
                spec=spec,
                git_runner=self.git_runner,
            )
        return self._resolve_git(spec, workspace)

    def _resolve_git(self, spec: SourceSpec, workspace: Path) -> ResolvedSource:
        parsed_kind = _validate_remote_url(
            spec.value,
            allow_file_transport=self.git_runner.allow_file_transport,
        )
        if spec.kind is SourceKind.GITHUB or parsed_kind is SourceKind.GITHUB:
            location = _github_location(spec.value)
            canonical_url = location.canonical_url
            requested_ref, discovery_scope = _github_ref_and_scope(
                spec,
                location,
                self.git_runner,
                self.limits.git_timeout_seconds,
            )
        else:
            canonical_url = spec.value
            requested_ref = spec.ref
            discovery_scope = spec.subpath or "."

        operation_root = _create_temporary_root(workspace, "git-source-")
        bare_repository = operation_root / "repository.git"
        snapshot_root = operation_root / "snapshot"
        try:
            bare_repository.mkdir(mode=0o700)
            snapshot_root.mkdir(mode=0o700)
        except OSError as exc:
            raise ImporterError(
                "SOURCE_SETUP_FAILED", "source workspace could not be created"
            ) from exc
        archive = operation_root / "source.tar"

        timeout = self.limits.git_timeout_seconds
        self.git_runner.run_capture(
            ["init", "--bare", str(bare_repository)],
            timeout=timeout,
        )
        fetch_ref = requested_ref or "HEAD"
        self.git_runner.run_capture(
            [
                "--git-dir",
                str(bare_repository),
                "fetch",
                "--depth=1",
                "--no-tags",
                "--no-recurse-submodules",
                "--",
                canonical_url,
                fetch_ref,
            ],
            timeout=timeout,
        )
        commit_output = self.git_runner.run_capture(
            [
                "--git-dir",
                str(bare_repository),
                "rev-parse",
                "--verify",
                "FETCH_HEAD^{commit}",
            ],
            timeout=timeout,
        )
        resolved_commit_sha = commit_output.decode("ascii", errors="ignore").strip()
        if _GIT_SHA_RE.fullmatch(resolved_commit_sha) is None:
            raise ImporterError("GIT_COMMAND_FAILED", "Git did not resolve a full commit SHA")

        self.git_runner.run_archive(
            [
                "--git-dir",
                str(bare_repository),
                "archive",
                "--format=tar",
                resolved_commit_sha,
            ],
            archive,
            max_bytes=self.limits.max_archive_bytes,
            timeout=timeout,
        )
        _extract_git_archive(archive, snapshot_root, self.limits)
        _validate_discovery_scope(snapshot_root, discovery_scope)
        snapshot_sha256 = _snapshot_hash(snapshot_root, self.limits)
        return ResolvedSource(
            spec=spec,
            canonical_url=canonical_url,
            snapshot_root=snapshot_root,
            snapshot_sha256=snapshot_sha256,
            discovery_scope=discovery_scope,
            resolved_commit_sha=resolved_commit_sha,
        )
