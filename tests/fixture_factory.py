"""Real filesystem and Git fixtures for source resolver tests."""

import os
import subprocess
import tarfile
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from io import BytesIO
from pathlib import Path
from typing import Any

from skill_importer.source import SubprocessGitRunner

SKILL_TEXT = "---\nname: x\ndescription: x\n---\n"


class ScandirLimiter:
    """Count real DirEntry reads and fail if enumeration crosses a test ceiling."""

    def __init__(self, max_yields: int) -> None:
        self.max_yields = max_yields
        self.yielded = 0
        self._real_scandir = os.scandir

    def __call__(self, path: Any) -> "ScandirLimiter._Iterator":
        return self._Iterator(self, self._real_scandir(path))

    class _Iterator:
        def __init__(self, owner: "ScandirLimiter", inner: Any) -> None:
            self.owner = owner
            self.inner = inner

        def __enter__(self) -> "ScandirLimiter._Iterator":
            return self

        def __exit__(self, *args: object) -> None:
            self.inner.close()

        def __iter__(self) -> "ScandirLimiter._Iterator":
            return self

        def __next__(self) -> os.DirEntry[str]:
            entry = next(self.inner)
            self.owner.yielded += 1
            if self.owner.yielded > self.owner.max_yields:
                raise AssertionError("scandir consumed beyond the bounded entry window")
            return entry


def write_tree(root: Path, files: Mapping[str, str | bytes]) -> None:
    """Create a small source tree without hiding filesystem behavior."""
    for relative_path, content in files.items():
        destination = root / relative_path
        destination.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, bytes):
            destination.write_bytes(content)
        else:
            destination.write_text(content, encoding="utf-8")


def run_git(repository: Path, args: Sequence[str]) -> str:
    """Run real Git with deterministic identity and no ambient user config."""
    environment = {
        **os.environ,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_TERMINAL_PROMPT": "0",
    }
    completed = subprocess.run(
        [
            "git",
            "-c",
            "user.name=Skill Importer Test",
            "-c",
            "user.email=skill-importer@example.invalid",
            "-C",
            str(repository),
            *args,
        ],
        check=True,
        capture_output=True,
        env=environment,
        shell=False,
        text=True,
    )
    return completed.stdout.strip()


def create_git_repository(root: Path, files: Mapping[str, str | bytes]) -> str:
    """Create and commit a real repository, returning its full HEAD SHA."""
    root.mkdir()
    run_git(root, ["init", "--initial-branch=main"])
    write_tree(root, files)
    run_git(root, ["add", "--all"])
    run_git(root, ["commit", "-m", "fixture"])
    return run_git(root, ["rev-parse", "HEAD"])


def create_bare_repository(source: Path, destination: Path) -> Path:
    """Clone a known test repository as a real bare remote without using ambient config."""
    environment = {
        **os.environ,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_TERMINAL_PROMPT": "0",
    }
    subprocess.run(
        ["git", "clone", "--bare", "--no-local", str(source), str(destination)],
        check=True,
        capture_output=True,
        env=environment,
        shell=False,
        text=True,
    )
    return destination


@dataclass(frozen=True, slots=True)
class TarEntry:
    """One explicit tar member, including hostile types Git cannot create."""

    name: str
    kind: str = "file"
    content: bytes = b""
    linkname: str = ""
    mode: int = 0o644


def create_tar(archive: Path, entries: Sequence[TarEntry]) -> None:
    """Write a real tar stream with exactly the requested member types."""
    type_by_kind = {
        "file": tarfile.REGTYPE,
        "directory": tarfile.DIRTYPE,
        "symlink": tarfile.SYMTYPE,
        "hardlink": tarfile.LNKTYPE,
        "fifo": tarfile.FIFOTYPE,
        "character": tarfile.CHRTYPE,
    }
    with tarfile.open(archive, "w") as output:
        for entry in entries:
            member = tarfile.TarInfo(entry.name)
            member.type = type_by_kind[entry.kind]
            member.mode = entry.mode
            member.linkname = entry.linkname
            member.size = len(entry.content) if entry.kind == "file" else 0
            output.addfile(member, BytesIO(entry.content) if entry.kind == "file" else None)


class StaticArchiveGitRunner:
    """Replace only the external Git boundary while exercising real tar extraction."""

    allow_file_transport = False

    def __init__(self, archive: Path, commit_sha: str = "a" * 40) -> None:
        self.archive = archive
        self.commit_sha = commit_sha
        self.commands: list[tuple[str, ...]] = []

    def run_capture(
        self,
        arguments: Sequence[str],
        *,
        timeout: int,
        cwd: Path | None = None,
    ) -> bytes:
        del timeout, cwd
        command = tuple(arguments)
        self.commands.append(command)
        if "rev-parse" in command:
            return f"{self.commit_sha}\n".encode("ascii")
        return b""

    def run_archive(
        self,
        arguments: Sequence[str],
        destination: Path,
        *,
        max_bytes: int,
        timeout: int,
    ) -> None:
        del max_bytes, timeout
        self.commands.append(tuple(arguments))
        destination.write_bytes(self.archive.read_bytes())


class LocalMirrorGitRunner(SubprocessGitRunner):
    """Map one fake HTTPS remote to a real local repository for deterministic tests."""

    def __init__(self, remote_url: str, repository: Path) -> None:
        super().__init__(allow_file_transport=True)
        self.remote_url = remote_url
        self.repository_url = repository.resolve().as_uri()

    def _rewrite(self, arguments: Sequence[str]) -> list[str]:
        return [self.repository_url if item == self.remote_url else item for item in arguments]

    def run_capture(
        self,
        arguments: Sequence[str],
        *,
        timeout: int,
        cwd: Path | None = None,
    ) -> bytes:
        return super().run_capture(self._rewrite(arguments), timeout=timeout, cwd=cwd)

    def run_archive(
        self,
        arguments: Sequence[str],
        destination: Path,
        *,
        max_bytes: int,
        timeout: int,
    ) -> None:
        super().run_archive(
            self._rewrite(arguments),
            destination,
            max_bytes=max_bytes,
            timeout=timeout,
        )
