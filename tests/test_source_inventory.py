import os
from dataclasses import replace
from pathlib import Path

import pytest
from fixture_factory import (
    SKILL_TEXT,
    LocalMirrorGitRunner,
    ScandirLimiter,
    StaticArchiveGitRunner,
    TarEntry,
    create_git_repository,
    create_tar,
    run_git,
    write_tree,
)

import skill_importer.inventory as inventory_module
import skill_importer.source as source_module
from skill_importer.errors import ImporterError
from skill_importer.inventory import build_inventory
from skill_importer.limits import Limits
from skill_importer.models import SourceKind, SourceSpec
from skill_importer.source import (
    SourceResolver,
    SubprocessGitRunner,
    parse_source_spec,
    snapshot_local,
)


@pytest.mark.parametrize(
    "value",
    [
        "ext::sh -c id",
        "file:///tmp/repo",
        "https://u:p@example/a.git",
        "git@example.com:-oProxyCommand=id",
        "https://example.com/acme/-upload-pack=x",
        "https://-evil.example/acme/repo.git",
    ],
)
def test_production_git_parser_rejects_unsafe_remote(value: str) -> None:
    with pytest.raises(ImporterError, match="unsafe Git URL"):
        parse_source_spec(value, ref=None, subpath=None)


def test_parser_maps_malformed_url_to_bounded_error() -> None:
    with pytest.raises(ImporterError, match="unsafe Git URL"):
        parse_source_spec("https://[invalid/repo.git", ref=None, subpath=None)


def test_inventory_never_follows_symlink(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "SKILL.md").write_text(
        "---\nname: x\ndescription: x\n---\n",
        encoding="utf-8",
    )
    (source / "escape").symlink_to(tmp_path / "secret.txt")

    resolved = snapshot_local(source, tmp_path / "workspace", Limits())
    inventory = build_inventory(resolved, Limits())

    entry = inventory.by_path["escape"]
    assert entry.kind == "symlink"
    assert entry.symlink_target == str(tmp_path / "secret.txt")
    assert entry.content is None


def test_local_snapshot_rejects_hardlink_to_file_outside_source(tmp_path: Path) -> None:
    outside = tmp_path / "outside-secret.txt"
    outside.write_text("must remain outside", encoding="utf-8")
    source = tmp_path / "source"
    source.mkdir()
    write_tree(source, {"SKILL.md": SKILL_TEXT})
    os.link(outside, source / "linked-secret.txt")
    workspace = tmp_path / "workspace"

    with pytest.raises(ImporterError) as captured:
        snapshot_local(source, workspace, Limits())

    assert captured.value.code == "PATH_TRAVERSAL"
    assert outside.read_text(encoding="utf-8") == "must remain outside"
    snapshots = list(workspace.glob("snapshot-*"))
    assert len(snapshots) == 1
    assert not (snapshots[0] / "linked-secret.txt").exists()


def test_local_snapshot_conservatively_rejects_any_hardlinked_regular_file(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    write_tree(source, {"SKILL.md": SKILL_TEXT, "asset.txt": "shared"})
    os.link(source / "asset.txt", source / "asset-alias.txt")

    with pytest.raises(ImporterError) as captured:
        snapshot_local(source, tmp_path / "workspace", Limits())

    assert captured.value.code == "PATH_TRAVERSAL"
    assert "hardlink" in captured.value.message


def test_local_snapshot_excludes_vcs_metadata(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    write_tree(
        source,
        {
            "SKILL.md": SKILL_TEXT,
            ".git/config": "secret",
            "nested/.svn/entries": "secret",
            "nested/asset.txt": "kept",
        },
    )

    resolved = snapshot_local(source, tmp_path / "workspace", Limits())
    inventory = build_inventory(resolved, Limits())

    assert "nested/asset.txt" in inventory.by_path
    assert all(
        not {".git", ".hg", ".svn"}.intersection(Path(entry.path).parts)
        for entry in inventory.entries
    )


def test_inventory_keeps_only_bounded_utf8_content(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    write_tree(source, {"SKILL.md": SKILL_TEXT, "binary.bin": b"\xff\x00"})

    resolved = snapshot_local(source, tmp_path / "workspace", Limits())
    inventory = build_inventory(resolved, Limits())

    assert inventory.by_path["SKILL.md"].content == SKILL_TEXT
    assert inventory.by_path["binary.bin"].content is None


def test_snapshot_rejects_file_over_limit(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "large.txt").write_bytes(b"1234")
    limits = replace(Limits(), max_file_bytes=3)

    with pytest.raises(ImporterError, match="file size limit"):
        snapshot_local(source, tmp_path / "workspace", limits)


def test_snapshot_rejects_entry_count_over_limit(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    write_tree(source, {"one": "1", "two": "2"})
    limits = replace(Limits(), max_entries=1)

    with pytest.raises(ImporterError, match="entry count limit"):
        snapshot_local(source, tmp_path / "workspace", limits)


def test_local_snapshot_bounds_directory_enumeration_before_sorting(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    write_tree(source, {f"file-{index}": "x" for index in range(20)})
    limits = replace(Limits(), max_entries=2)
    scandir = ScandirLimiter(max_yields=limits.max_entries + 1)
    monkeypatch.setattr(source_module.os, "scandir", scandir)

    with pytest.raises(ImporterError, match="entry count limit"):
        snapshot_local(source, tmp_path / "workspace", limits)

    assert scandir.yielded == limits.max_entries + 1


def test_inventory_bounds_directory_enumeration_before_sorting(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    write_tree(source, {f"file-{index}": "x" for index in range(20)})
    resolved = snapshot_local(source, tmp_path / "workspace", Limits())
    limits = replace(Limits(), max_entries=2)
    scandir = ScandirLimiter(max_yields=limits.max_entries + 1)
    monkeypatch.setattr(inventory_module.os, "scandir", scandir)

    with pytest.raises(ImporterError, match="entry count limit"):
        build_inventory(resolved, limits)

    assert scandir.yielded == limits.max_entries + 1


def test_snapshot_rejects_path_over_depth_limit(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    write_tree(source, {"one/two": "deep"})
    limits = replace(Limits(), max_depth=1)

    with pytest.raises(ImporterError, match="path depth limit"):
        snapshot_local(source, tmp_path / "workspace", limits)


def test_snapshot_rejects_total_bytes_over_limit(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    write_tree(source, {"one": "12", "two": "34"})
    limits = replace(Limits(), max_scan_bytes=3)

    with pytest.raises(ImporterError, match="scan byte limit"):
        snapshot_local(source, tmp_path / "workspace", limits)


def test_local_snapshot_reports_unsafe_platform_path_as_bounded_error(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "bad\\name").write_text("unsafe", encoding="utf-8")

    with pytest.raises(ImporterError, match="unsafe source path"):
        snapshot_local(source, tmp_path / "workspace", Limits())


def test_local_snapshot_maps_root_open_failure_to_bounded_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    real_open = source_module.os.open

    def deny_source_open(
        path: object,
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        if path == source.resolve() and dir_fd is None:
            raise PermissionError("denied by test")
        return real_open(path, flags, mode, dir_fd=dir_fd)  # type: ignore[call-overload]

    monkeypatch.setattr(source_module.os, "open", deny_source_open)

    with pytest.raises(ImporterError, match="local source directory is not readable"):
        snapshot_local(source, tmp_path / "workspace", Limits())


def test_local_snapshot_maps_workspace_setup_failure_to_bounded_error(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    workspace = tmp_path / "workspace"
    workspace.write_text("not a directory", encoding="utf-8")

    with pytest.raises(ImporterError, match="source workspace could not be created"):
        snapshot_local(source, workspace, Limits())


def test_git_resolver_maps_workspace_setup_failure_to_bounded_error(tmp_path: Path) -> None:
    archive = tmp_path / "archive.tar"
    create_tar(archive, [TarEntry("SKILL.md", content=SKILL_TEXT.encode())])
    workspace = tmp_path / "workspace"
    workspace.write_text("not a directory", encoding="utf-8")
    resolver = SourceResolver(limits=Limits(), git_runner=StaticArchiveGitRunner(archive))
    spec = SourceSpec(kind=SourceKind.GIT, value="https://example.com/acme/repo.git")

    with pytest.raises(ImporterError, match="source workspace could not be created"):
        resolver.resolve(spec, workspace)


def test_dirty_local_repository_changes_snapshot_revision(tmp_path: Path) -> None:
    source = tmp_path / "source"
    head = create_git_repository(source, {"SKILL.md": SKILL_TEXT})

    clean = snapshot_local(source, tmp_path / "workspace-clean", Limits())
    (source / "SKILL.md").write_text(f"{SKILL_TEXT}dirty\n", encoding="utf-8")
    dirty = snapshot_local(source, tmp_path / "workspace-dirty", Limits())

    assert clean.resolved_commit_sha == head
    assert dirty.resolved_commit_sha == head
    assert dirty.revision == dirty.snapshot_sha256
    assert clean.snapshot_sha256 != dirty.snapshot_sha256


def test_local_subpath_only_changes_discovery_scope(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    write_tree(source, {"skills/x/SKILL.md": SKILL_TEXT, "plugin.json": "{}"})
    spec = parse_source_spec(str(source), ref=None, subpath="skills/x")

    resolved = snapshot_local(
        Path(spec.value),
        tmp_path / "workspace",
        Limits(),
        spec=spec,
    )
    inventory = build_inventory(resolved, Limits())

    assert resolved.discovery_scope == "skills/x"
    assert "plugin.json" in inventory.by_path


@pytest.mark.parametrize(
    ("value", "kind"),
    [
        ("https://example.com/acme/repo.git", SourceKind.GIT),
        ("ssh://git@example.com/acme/repo.git", SourceKind.GIT),
        ("git://example.com/acme/repo.git", SourceKind.GIT),
        ("git@example.com:acme/repo.git", SourceKind.GIT),
        ("https://github.com/acme/repo", SourceKind.GITHUB),
        ("git@github.com:acme/repo.git", SourceKind.GITHUB),
    ],
)
def test_parser_classifies_allowed_git_urls(value: str, kind: SourceKind) -> None:
    assert parse_source_spec(value, ref=None, subpath=None).kind is kind


def test_production_runner_rejects_file_transport_even_for_direct_spec(tmp_path: Path) -> None:
    source = tmp_path / "repository"
    create_git_repository(source, {"SKILL.md": SKILL_TEXT})
    spec = SourceSpec(kind=SourceKind.GIT, value=source.resolve().as_uri())
    resolver = SourceResolver(limits=Limits(), git_runner=SubprocessGitRunner())

    with pytest.raises(ImporterError, match="unsafe Git URL"):
        resolver.resolve(spec, tmp_path / "workspace")


def test_git_runner_ignores_hostile_ambient_git_config(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("GIT_CONFIG_PARAMETERS", "'protocol.allow=always'")
    runner = SubprocessGitRunner()

    configured = runner.run_capture(
        ["config", "--get", "protocol.allow"],
        timeout=5,
    )

    assert configured == b"never\n"


def test_git_runner_bounds_large_capture_output_during_execution(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    create_git_repository(repository, {"SKILL.md": SKILL_TEXT})
    for index in range(5):
        run_git(repository, ["branch", f"remote-like-{index}"])
    runner = SubprocessGitRunner(allow_file_transport=True, max_capture_bytes=128)

    with pytest.raises(ImporterError, match="Git command output exceeds the byte limit"):
        runner.run_capture(
            ["ls-remote", "--heads", "--", repository.resolve().as_uri()],
            timeout=5,
        )


def test_real_local_git_fixture_resolves_full_sha_and_whole_inventory(tmp_path: Path) -> None:
    source = tmp_path / "repository"
    head = create_git_repository(
        source,
        {"skills/x/SKILL.md": SKILL_TEXT, "plugin.json": "{}"},
    )
    spec = SourceSpec(
        kind=SourceKind.GIT,
        value=source.resolve().as_uri(),
        ref="main",
        subpath="skills/x",
    )
    resolver = SourceResolver(
        limits=Limits(),
        git_runner=SubprocessGitRunner(allow_file_transport=True),
    )

    resolved = resolver.resolve(spec, tmp_path / "workspace")
    inventory = build_inventory(resolved, Limits())

    assert resolved.resolved_commit_sha == head
    assert len(resolved.resolved_commit_sha) == 40
    assert resolved.discovery_scope == "skills/x"
    assert "plugin.json" in inventory.by_path
    assert all(".git" not in Path(entry.path).parts for entry in inventory.entries)


@pytest.mark.parametrize(
    ("url", "expected_scope"),
    [
        ("https://github.com/acme/repo", "."),
        ("https://github.com/acme/repo/tree/feature/nested/tools/example", "tools/example"),
        ("https://github.com/acme/repo/blob/main/tools/example/SKILL.md", "tools/example"),
    ],
)
def test_github_urls_normalize_repository_ref_and_scope(
    url: str,
    expected_scope: str,
    tmp_path: Path,
) -> None:
    repository = tmp_path / "repository"
    create_git_repository(
        repository,
        {"tools/example/SKILL.md": SKILL_TEXT, "plugin.json": "{}"},
    )
    run_git(repository, ["checkout", "-b", "feature/nested"])
    (repository / "branch-marker").write_text("feature", encoding="utf-8")
    run_git(repository, ["add", "branch-marker"])
    run_git(repository, ["commit", "-m", "feature"])
    run_git(repository, ["checkout", "main"])
    expected_ref = "feature/nested" if "/tree/" in url else "main"
    expected_sha = run_git(repository, ["rev-parse", expected_ref])
    canonical_url = "https://github.com/acme/repo.git"
    resolver = SourceResolver(
        limits=Limits(),
        git_runner=LocalMirrorGitRunner(canonical_url, repository),
    )

    resolved = resolver.resolve(
        parse_source_spec(url, ref=None, subpath=None),
        tmp_path / "workspace",
    )
    inventory = build_inventory(resolved, Limits())

    assert resolved.canonical_url == canonical_url
    assert resolved.resolved_commit_sha == expected_sha
    assert resolved.discovery_scope == expected_scope
    assert "plugin.json" in inventory.by_path


@pytest.mark.parametrize("route_kind", ["tree", "blob"])
def test_github_url_with_full_commit_sha_is_immutable_without_explicit_ref(
    route_kind: str,
    tmp_path: Path,
) -> None:
    repository = tmp_path / "repository"
    head = create_git_repository(
        repository,
        {"tools/example/SKILL.md": SKILL_TEXT, "tools/example/assets/data.txt": "data"},
    )
    canonical_url = "https://github.com/acme/repo.git"
    suffix = "tools/example" if route_kind == "tree" else "tools/example/SKILL.md"
    resolver = SourceResolver(
        limits=Limits(),
        git_runner=LocalMirrorGitRunner(canonical_url, repository),
    )

    resolved = resolver.resolve(
        parse_source_spec(
            f"https://github.com/acme/repo/{route_kind}/{head}/{suffix}",
            ref=None,
            subpath=None,
        ),
        tmp_path / "workspace",
    )

    assert resolved.resolved_commit_sha == head
    assert resolved.discovery_scope == "tools/example"


@pytest.mark.parametrize("explicit_ref", [False, True])
def test_github_url_disambiguates_slash_ref_starting_with_full_sha_shape(
    explicit_ref: bool,
    tmp_path: Path,
) -> None:
    repository = tmp_path / "repository"
    create_git_repository(
        repository,
        {"tools/example/SKILL.md": SKILL_TEXT, "plugin.json": "{}"},
    )
    branch = f"{'a' * 40}/feature"
    run_git(repository, ["checkout", "-b", branch])
    (repository / "branch-marker").write_text("feature", encoding="utf-8")
    run_git(repository, ["add", "branch-marker"])
    run_git(repository, ["commit", "-m", "feature"])
    expected_sha = run_git(repository, ["rev-parse", branch])
    canonical_url = "https://github.com/acme/repo.git"
    resolver = SourceResolver(
        limits=Limits(),
        git_runner=LocalMirrorGitRunner(canonical_url, repository),
    )

    resolved = resolver.resolve(
        parse_source_spec(
            f"https://github.com/acme/repo/tree/{branch}/tools/example",
            ref=branch if explicit_ref else None,
            subpath=None,
        ),
        tmp_path / "workspace",
    )

    assert resolved.resolved_commit_sha == expected_sha
    assert resolved.discovery_scope == "tools/example"


@pytest.mark.parametrize(
    "blob_target",
    ["tools/example/MISSING.md", "tools/example"],
)
def test_github_blob_url_rejects_missing_or_non_file_target(
    blob_target: str,
    tmp_path: Path,
) -> None:
    repository = tmp_path / "repository"
    create_git_repository(
        repository,
        {"tools/example/SKILL.md": SKILL_TEXT, "tools/sibling/SKILL.md": SKILL_TEXT},
    )
    canonical_url = "https://github.com/acme/repo.git"
    resolver = SourceResolver(
        limits=Limits(),
        git_runner=LocalMirrorGitRunner(canonical_url, repository),
    )

    with pytest.raises(ImporterError) as captured:
        resolver.resolve(
            parse_source_spec(
                f"https://github.com/acme/repo/blob/main/{blob_target}",
                ref=None,
                subpath=None,
            ),
            tmp_path / "workspace",
        )

    assert captured.value.code == "INVALID_SOURCE"
    assert "regular file" in captured.value.message


def test_github_blob_url_rejects_symlink_target_without_following_it(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    create_git_repository(repository, {"tools/example/SKILL.md": SKILL_TEXT})
    (repository / "tools/link.md").symlink_to("example/SKILL.md")
    run_git(repository, ["add", "tools/link.md"])
    run_git(repository, ["commit", "-m", "symlink"])
    canonical_url = "https://github.com/acme/repo.git"
    resolver = SourceResolver(
        limits=Limits(),
        git_runner=LocalMirrorGitRunner(canonical_url, repository),
    )

    with pytest.raises(ImporterError) as captured:
        resolver.resolve(
            parse_source_spec(
                "https://github.com/acme/repo/blob/main/tools/link.md",
                ref=None,
                subpath=None,
            ),
            tmp_path / "workspace",
        )

    assert captured.value.code == "INVALID_SOURCE"
    assert "regular file" in captured.value.message


def test_github_url_rejects_unproven_slash_ref_boundary_during_ref_override(
    tmp_path: Path,
) -> None:
    repository = tmp_path / "repository"
    create_git_repository(
        repository,
        {
            "feature/path/SKILL.md": SKILL_TEXT,
            "path/SKILL.md": SKILL_TEXT,
        },
    )
    canonical_url = "https://github.com/acme/repo.git"
    resolver = SourceResolver(
        limits=Limits(),
        git_runner=LocalMirrorGitRunner(canonical_url, repository),
    )

    with pytest.raises(ImporterError) as captured:
        resolver.resolve(
            parse_source_spec(
                "https://github.com/acme/repo/tree/deleted/feature/path",
                ref="main",
                subpath=None,
            ),
            tmp_path / "workspace",
        )

    assert captured.value.code == "AMBIGUOUS_GITHUB_REF"
    assert "--subpath" in captured.value.message


def test_explicit_subpath_makes_unadvertised_url_ref_boundary_irrelevant(
    tmp_path: Path,
) -> None:
    repository = tmp_path / "repository"
    head = create_git_repository(repository, {"path/SKILL.md": SKILL_TEXT})
    canonical_url = "https://github.com/acme/repo.git"
    resolver = SourceResolver(
        limits=Limits(),
        git_runner=LocalMirrorGitRunner(canonical_url, repository),
    )

    resolved = resolver.resolve(
        parse_source_spec(
            "https://github.com/acme/repo/tree/deleted/feature/path",
            ref="main",
            subpath="path",
        ),
        tmp_path / "workspace",
    )

    assert resolved.resolved_commit_sha == head
    assert resolved.discovery_scope == "path"


def test_explicit_subpath_overrides_github_url_scope(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    head = create_git_repository(
        repository,
        {"tools/example/SKILL.md": SKILL_TEXT, "other/SKILL.md": SKILL_TEXT},
    )
    canonical_url = "https://github.com/acme/repo.git"
    resolver = SourceResolver(
        limits=Limits(),
        git_runner=LocalMirrorGitRunner(canonical_url, repository),
    )
    spec = parse_source_spec(
        "https://github.com/acme/repo/blob/main/tools/example/SKILL.md",
        ref="main",
        subpath="other",
    )

    resolved = resolver.resolve(spec, tmp_path / "workspace")

    assert resolved.resolved_commit_sha == head
    assert resolved.discovery_scope == "other"


@pytest.mark.parametrize("member_name", ["../escape", "/absolute", "a/../../escape"])
def test_git_archive_rejects_traversal_member(member_name: str, tmp_path: Path) -> None:
    archive = tmp_path / "hostile.tar"
    create_tar(archive, [TarEntry(member_name, content=b"escape")])
    resolver = SourceResolver(limits=Limits(), git_runner=StaticArchiveGitRunner(archive))
    spec = SourceSpec(kind=SourceKind.GIT, value="https://example.com/acme/repo.git")

    with pytest.raises(ImporterError, match="archive path traversal"):
        resolver.resolve(spec, tmp_path / "workspace")


@pytest.mark.parametrize("kind", ["hardlink", "fifo", "character"])
def test_git_archive_rejects_special_member_types(kind: str, tmp_path: Path) -> None:
    archive = tmp_path / "hostile.tar"
    create_tar(archive, [TarEntry("unsafe", kind=kind, linkname="target")])
    resolver = SourceResolver(limits=Limits(), git_runner=StaticArchiveGitRunner(archive))
    spec = SourceSpec(kind=SourceKind.GIT, value="https://example.com/acme/repo.git")

    with pytest.raises(ImporterError, match="unsupported archive entry type"):
        resolver.resolve(spec, tmp_path / "workspace")


@pytest.mark.parametrize(
    "names",
    [
        ("Skill.md", "skill.md"),
        ("\N{LATIN SMALL LETTER E WITH ACUTE}.txt", "e\N{COMBINING ACUTE ACCENT}.txt"),
    ],
)
def test_git_archive_rejects_unicode_or_case_collision(
    names: tuple[str, str],
    tmp_path: Path,
) -> None:
    archive = tmp_path / "collision.tar"
    create_tar(archive, [TarEntry(name, content=b"x") for name in names])
    resolver = SourceResolver(limits=Limits(), git_runner=StaticArchiveGitRunner(archive))
    spec = SourceSpec(kind=SourceKind.GIT, value="https://example.com/acme/repo.git")

    with pytest.raises(ImporterError, match="path collision"):
        resolver.resolve(spec, tmp_path / "workspace")


def test_git_archive_cannot_write_through_symlink_ancestor(tmp_path: Path) -> None:
    archive = tmp_path / "hostile.tar"
    create_tar(
        archive,
        [
            TarEntry("redirect", kind="symlink", linkname="../outside"),
            TarEntry("redirect/payload", content=b"escape"),
        ],
    )
    resolver = SourceResolver(limits=Limits(), git_runner=StaticArchiveGitRunner(archive))
    spec = SourceSpec(kind=SourceKind.GIT, value="https://example.com/acme/repo.git")

    with pytest.raises(ImporterError, match="symlink ancestor"):
        resolver.resolve(spec, tmp_path / "workspace")


def test_git_archive_is_bounded_before_extraction(tmp_path: Path) -> None:
    archive = tmp_path / "archive.tar"
    create_tar(archive, [TarEntry("SKILL.md", content=SKILL_TEXT.encode())])
    limits = replace(Limits(), max_archive_bytes=100)
    resolver = SourceResolver(limits=limits, git_runner=StaticArchiveGitRunner(archive))
    spec = SourceSpec(kind=SourceKind.GIT, value="https://example.com/acme/repo.git")

    with pytest.raises(ImporterError, match="archive byte limit"):
        resolver.resolve(spec, tmp_path / "workspace")


def test_git_resolver_never_requests_checkout_or_submodules(tmp_path: Path) -> None:
    archive = tmp_path / "archive.tar"
    create_tar(archive, [TarEntry("SKILL.md", content=SKILL_TEXT.encode())])
    runner = StaticArchiveGitRunner(archive)
    resolver = SourceResolver(limits=Limits(), git_runner=runner)
    spec = SourceSpec(kind=SourceKind.GIT, value="https://example.com/acme/repo.git")

    resolver.resolve(spec, tmp_path / "workspace")

    flattened = {argument for command in runner.commands for argument in command}
    assert "checkout" not in flattened
    assert "submodule" not in flattened
    assert "--no-recurse-submodules" in flattened
