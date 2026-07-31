"""The small public API for creating, checking, and restoring backups."""

from __future__ import annotations

import os
import shutil
import tempfile
from collections.abc import Iterable, Mapping, Sequence
from pathlib import Path

from ._archive import build_manifest, extract_verified, write_archive
from ._filesystem import (
    copy_directory,
    copy_file,
    fsync_directory,
    reject_links,
    require_posix,
    snapshot_sqlite,
)
from .errors import ConfigurationError, LimitError, RestoreError, SourceError
from .keys import SigningKey, VerificationKey
from .models import (
    BackupReport,
    Limits,
    RestoreReport,
    Source,
    SourceKind,
    VerificationReport,
)


def _resolved_output(path: str | Path) -> Path:
    requested = Path(path).expanduser()
    if requested.name in {"", ".", ".."}:
        raise ConfigurationError("backup output must be a file path")
    if requested.is_symlink():
        raise ConfigurationError(f"backup output must not be a symlink: {requested}")
    requested.parent.mkdir(parents=True, exist_ok=True)
    output = requested.parent.resolve() / requested.name
    if output.exists() and output.is_dir():
        raise ConfigurationError(f"backup output must not be a directory: {output}")
    return output


def _resolved_destination(path: str | Path) -> Path:
    requested = Path(path).expanduser()
    if requested.name in {"", ".", ".."}:
        raise ConfigurationError("restore destination must be a directory path")
    if requested.is_symlink():
        raise ConfigurationError(
            f"restore destination must not be a symlink: {requested}"
        )
    requested.parent.mkdir(parents=True, exist_ok=True)
    destination = requested.parent.resolve() / requested.name
    if destination.exists() and not destination.is_dir():
        raise ConfigurationError(
            f"restore destination must not be a file: {destination}"
        )
    return destination


def _check_source_layout(sources: Sequence[Source]) -> None:
    if not sources:
        raise ConfigurationError("at least one backup source is required")
    for source in sources:
        if not isinstance(source, Source):
            raise ConfigurationError("sources must be Source values")
    for index, source in enumerate(sources):
        for other in sources[index + 1 :]:
            left = source.archive_path
            right = other.archive_path
            if left == right or left in right.parents or right in left.parents:
                raise ConfigurationError(
                    f"backup sources have overlapping archive paths: {left} and {right}"
                )


def _path_size(path: Path) -> int:
    if path.is_file():
        return path.stat().st_size
    return sum(
        candidate.stat().st_size for candidate in path.rglob("*") if candidate.is_file()
    )


def _require_staging_space(directory: Path, size: int, limits: Limits) -> None:
    if size > limits.max_expanded_bytes:
        raise LimitError("backup source exceeds the expanded byte limit")
    if shutil.disk_usage(directory).free < size + limits.min_free_bytes:
        raise LimitError("insufficient free space for backup staging")


def _reject_output_overlap(output: Path, source: Path) -> None:
    resolved = source.resolve()
    if output == resolved or (source.is_dir() and output.is_relative_to(resolved)):
        raise ConfigurationError(f"backup output overlaps a source: {source}")


def _stage_sources(
    payload: Path,
    output: Path,
    sources: Sequence[Source],
    limits: Limits,
) -> tuple[set[str], dict[str, int], tuple[str, ...]]:
    sqlite_paths: set[str] = set()
    mode_overrides: dict[str, int] = {}
    missing_optional: list[str] = []
    staged_bytes = 0
    for source in sources:
        path = source.path
        if path.is_symlink():
            raise SourceError(f"backup source must not be a symlink: {path}")
        if not path.exists():
            if source.required:
                raise SourceError(f"required backup source does not exist: {path}")
            missing_optional.append(source.archive_path.as_posix())
            continue
        reject_links(path, label="backup source")
        _reject_output_overlap(output, path)
        target = payload.joinpath(*source.archive_path.parts)

        if source.kind is SourceKind.DIRECTORY:
            if not path.is_dir():
                raise SourceError(f"directory backup source is not a directory: {path}")
            estimated = _path_size(path)
            if staged_bytes + estimated > limits.max_expanded_bytes:
                raise LimitError("backup sources exceed the expanded byte limit")
            _require_staging_space(payload, estimated, limits)
            copy_directory(path, target)
            copied = _path_size(target)
        elif source.kind is SourceKind.FILE:
            if not path.is_file():
                raise SourceError(f"file backup source is not a regular file: {path}")
            estimated = path.stat().st_size
            if staged_bytes + estimated > limits.max_expanded_bytes:
                raise LimitError("backup sources exceed the expanded byte limit")
            _require_staging_space(payload, estimated, limits)
            copy_file(path, target)
            copied = target.stat().st_size
        else:
            if not path.is_file():
                raise SourceError(f"SQLite backup source is not a file: {path}")
            remaining = limits.max_expanded_bytes - staged_bytes
            copied = snapshot_sqlite(
                path,
                target,
                max_bytes=remaining,
                min_free_bytes=limits.min_free_bytes,
            )
            sqlite_paths.add(source.archive_path.as_posix())

        if source.mode is not None:
            mode_overrides[source.archive_path.as_posix()] = source.mode
        staged_bytes += copied
        if staged_bytes > limits.max_expanded_bytes:
            raise LimitError("backup sources exceed the expanded byte limit")
    return sqlite_paths, mode_overrides, tuple(missing_optional)


def backup(
    output: str | Path,
    sources: Sequence[Source],
    *,
    signing_key: SigningKey,
    limits: Limits | None = None,
    metadata: Mapping[str, object] | None = None,
    overwrite: bool = False,
) -> BackupReport:
    """Create and self-verify a signed StateCrate archive.

    The candidate archive is promoted only after the same verification used by
    :func:`verify` and :func:`restore` succeeds.
    """

    require_posix()
    if not isinstance(signing_key, SigningKey):
        raise ConfigurationError("signing_key must be a SigningKey")
    effective_limits = limits or Limits()
    _check_source_layout(sources)
    archive_path = _resolved_output(output)
    if archive_path.exists() and not overwrite:
        raise ConfigurationError(f"backup output already exists: {archive_path}")

    temporary_archive: Path | None = None
    with tempfile.TemporaryDirectory(
        prefix=".statecrate-backup-", dir=archive_path.parent
    ) as temporary:
        temporary_root = Path(temporary)
        payload = temporary_root / "payload"
        payload.mkdir(mode=0o700)
        sqlite_paths, mode_overrides, missing_optional = _stage_sources(
            payload, archive_path, sources, effective_limits
        )
        manifest = build_manifest(
            payload,
            sqlite_paths=sqlite_paths,
            mode_overrides=mode_overrides,
            missing_optional_sources=missing_optional,
            metadata=metadata,
            limits=effective_limits,
        )
        expanded_bytes = sum(int(entry["size"]) for entry in manifest["entries"])
        _require_staging_space(archive_path.parent, expanded_bytes, effective_limits)
        try:
            with tempfile.NamedTemporaryFile(
                prefix=f".{archive_path.name}.",
                suffix=".tmp",
                dir=archive_path.parent,
                mode="w+b",
                delete=False,
            ) as handle:
                temporary_archive = Path(handle.name)
                write_archive(handle, payload, manifest, signing_key)
                handle.flush()
                os.fsync(handle.fileno())
            temporary_archive.chmod(0o600)
            verification = verify(
                temporary_archive,
                trusted_keys=signing_key.verification_key,
                limits=effective_limits,
            )
            if overwrite:
                os.replace(temporary_archive, archive_path)
            else:
                try:
                    os.link(temporary_archive, archive_path)
                except FileExistsError as error:
                    raise ConfigurationError(
                        f"backup output already exists: {archive_path}"
                    ) from error
                temporary_archive.unlink()
            fsync_directory(archive_path.parent)
        finally:
            if temporary_archive is not None:
                temporary_archive.unlink(missing_ok=True)

    return BackupReport(
        archive=archive_path,
        signer_key_id=verification.signer_key_id,
        created_at=verification.created_at,
        entries=verification.entries_checked,
        expanded_bytes=verification.expanded_bytes,
        missing_optional_sources=verification.missing_optional_sources,
    )


def verify(
    archive: str | Path,
    *,
    trusted_keys: VerificationKey | Iterable[VerificationKey],
    limits: Limits | None = None,
) -> VerificationReport:
    """Verify a manifest signature, every payload hash, and every SQLite file."""

    require_posix()
    archive_path = Path(archive).expanduser().resolve()
    if not archive_path.is_file():
        raise ConfigurationError(f"backup archive does not exist: {archive_path}")
    with tempfile.TemporaryDirectory(prefix="statecrate-verify-") as temporary:
        report, _ = extract_verified(
            archive_path,
            Path(temporary),
            trusted_keys=trusted_keys,
            limits=limits or Limits(),
        )
        return report


def restore(
    archive: str | Path,
    destination: str | Path,
    *,
    trusted_keys: VerificationKey | Iterable[VerificationKey],
    limits: Limits | None = None,
    replace: bool = False,
) -> RestoreReport:
    """Verify an archive and install its complete payload as one state tree.

    An existing destination is replaced only when ``replace=True``. The prior
    tree is retained until the verified replacement has been installed, so an
    in-process installation failure can roll back.
    """

    require_posix()
    archive_path = Path(archive).expanduser().resolve()
    if not archive_path.is_file():
        raise ConfigurationError(f"backup archive does not exist: {archive_path}")
    target = _resolved_destination(destination)
    if target.exists() and not replace:
        raise RestoreError(f"restore destination already exists: {target}")
    if archive_path.is_relative_to(target):
        raise RestoreError("backup archive must not be inside the restore destination")

    with tempfile.TemporaryDirectory(
        prefix=f".{target.name}-statecrate-", dir=target.parent
    ) as temporary:
        staging = Path(temporary)
        report, payload = extract_verified(
            archive_path,
            staging,
            trusted_keys=trusted_keys,
            limits=limits or Limits(),
            durable=True,
        )
        previous = staging / "previous"
        if target.exists():
            if not replace:
                raise RestoreError(f"restore destination already exists: {target}")
            os.replace(target, previous)
            fsync_directory(target.parent)
        try:
            os.replace(payload, target)
            fsync_directory(target.parent)
        except BaseException:
            if previous.exists() and not target.exists():
                os.replace(previous, target)
                fsync_directory(target.parent)
            raise
        if previous.exists():
            shutil.rmtree(previous)
            fsync_directory(staging)

    return RestoreReport(
        archive=archive_path,
        destination=target,
        signer_key_id=report.signer_key_id,
        restored_entries=report.entries_checked,
        expanded_bytes=report.expanded_bytes,
    )
