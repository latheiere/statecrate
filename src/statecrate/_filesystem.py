"""POSIX filesystem and SQLite primitives used by the archive engine."""

from __future__ import annotations

import hashlib
import os
import shutil
import sqlite3
from contextlib import closing
from pathlib import Path, PurePosixPath

from .errors import IntegrityError, LimitError, SourceError, UnsupportedPlatformError


def require_posix() -> None:
    if os.name != "posix":
        raise UnsupportedPlatformError("StateCrate supports POSIX systems only")


def validate_relative_path(path: PurePosixPath, *, label: str) -> None:
    if (
        path.is_absolute()
        or not path.parts
        or path.as_posix() in {"", "."}
        or ".." in path.parts
    ):
        raise SourceError(f"unsafe {label}: {path}")


def reject_links(path: Path, *, label: str) -> None:
    if path.is_symlink():
        raise SourceError(f"{label} must not be a symbolic link: {path}")
    if path.is_dir():
        for candidate in path.rglob("*"):
            if candidate.is_symlink():
                raise SourceError(f"{label} contains a symbolic link: {candidate}")
            if not (candidate.is_file() or candidate.is_dir()):
                raise SourceError(f"{label} contains a special file: {candidate}")
    elif not path.is_file():
        raise SourceError(f"{label} must be a regular file or directory: {path}")


def copy_file(source: Path, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    shutil.copy2(source, destination, follow_symlinks=False)
    reject_links(destination, label="staged backup source")


def copy_directory(source: Path, destination: Path) -> None:
    shutil.copytree(source, destination, symlinks=True)
    reject_links(destination, label="staged backup source")


def snapshot_sqlite(
    source: Path,
    destination: Path,
    *,
    max_bytes: int,
    min_free_bytes: int,
) -> int:
    destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    source_uri = f"{source.resolve().as_uri()}?mode=ro"
    try:
        with closing(sqlite3.connect(source_uri, uri=True)) as source_connection:
            page_count = int(
                source_connection.execute("PRAGMA page_count").fetchone()[0]
            )
            page_size = int(source_connection.execute("PRAGMA page_size").fetchone()[0])
            estimated_bytes = page_count * page_size
            if estimated_bytes > max_bytes:
                raise LimitError("SQLite snapshot exceeds the expanded byte limit")
            available = shutil.disk_usage(destination.parent).free
            if available < estimated_bytes + min_free_bytes:
                raise LimitError("insufficient free space for SQLite snapshot staging")
            with closing(sqlite3.connect(destination)) as destination_connection:
                source_connection.backup(destination_connection)
    except sqlite3.Error as error:
        raise SourceError(f"could not snapshot SQLite database: {source}") from error
    actual_bytes = destination.stat().st_size
    if actual_bytes > max_bytes:
        raise LimitError("SQLite snapshot exceeds the expanded byte limit")
    check_sqlite(destination)
    return actual_bytes


def check_sqlite(path: Path) -> None:
    uri = f"{path.resolve().as_uri()}?mode=ro&immutable=1"
    try:
        with closing(sqlite3.connect(uri, uri=True)) as connection:
            result = connection.execute("PRAGMA quick_check").fetchone()
    except sqlite3.Error as error:
        raise IntegrityError(f"SQLite integrity check failed: {path.name}") from error
    if not result or result[0] != "ok":
        raise IntegrityError(f"SQLite integrity check failed: {path.name}")


def sha256_file(path: Path) -> str:
    with path.open("rb") as handle:
        return hashlib.file_digest(handle, "sha256").hexdigest()


def fsync_file(path: Path) -> None:
    with path.open("rb") as handle:
        os.fsync(handle.fileno())


def fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def fsync_tree(root: Path) -> None:
    files = sorted(candidate for candidate in root.rglob("*") if candidate.is_file())
    for path in files:
        fsync_file(path)
    directories = [root, *(path for path in root.rglob("*") if path.is_dir())]
    for path in sorted(directories, key=lambda item: len(item.parts), reverse=True):
        fsync_directory(path)
