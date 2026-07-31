"""Public values used to describe backups and their results."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path, PurePosixPath
from typing import Any

from .errors import ConfigurationError


class SourceKind(StrEnum):
    """The way a source is captured and checked."""

    FILE = "file"
    DIRECTORY = "directory"
    SQLITE = "sqlite"


def _archive_path(value: str | PurePosixPath | None, source: Path) -> PurePosixPath:
    candidate = (
        PurePosixPath(value) if value is not None else PurePosixPath(source.name)
    )
    if (
        candidate.is_absolute()
        or not candidate.parts
        or candidate.as_posix() in {"", "."}
        or ".." in candidate.parts
    ):
        raise ConfigurationError(f"unsafe archive path: {candidate}")
    return candidate


@dataclass(frozen=True, slots=True)
class Source:
    """A file, directory, or SQLite database included in a backup."""

    path: Path
    archive_path: PurePosixPath
    kind: SourceKind
    required: bool = True
    mode: int | None = None

    def __post_init__(self) -> None:
        if self.mode is not None and (
            type(self.mode) is not int or not 0 <= self.mode <= 0o777
        ):
            raise ConfigurationError("source mode must be between 0o000 and 0o777")

    @classmethod
    def file(
        cls,
        path: str | Path,
        *,
        at: str | PurePosixPath | None = None,
        required: bool = True,
        mode: int | None = None,
    ) -> Source:
        source = Path(path).expanduser()
        return cls(source, _archive_path(at, source), SourceKind.FILE, required, mode)

    @classmethod
    def directory(
        cls,
        path: str | Path,
        *,
        at: str | PurePosixPath | None = None,
        required: bool = True,
        mode: int | None = None,
    ) -> Source:
        source = Path(path).expanduser()
        return cls(
            source,
            _archive_path(at, source),
            SourceKind.DIRECTORY,
            required,
            mode,
        )

    @classmethod
    def sqlite(
        cls,
        path: str | Path,
        *,
        at: str | PurePosixPath | None = None,
        required: bool = True,
        mode: int | None = None,
    ) -> Source:
        source = Path(path).expanduser()
        return cls(source, _archive_path(at, source), SourceKind.SQLITE, required, mode)


@dataclass(frozen=True, slots=True)
class Limits:
    """Resource limits applied during creation, verification, and restoration."""

    max_members: int = 10_000
    max_expanded_bytes: int = 1024 * 1024 * 1024
    max_manifest_bytes: int = 8 * 1024 * 1024
    max_signature_bytes: int = 16 * 1024
    max_member_name_length: int = 240
    min_free_bytes: int = 128 * 1024 * 1024

    def __post_init__(self) -> None:
        for name, value in (
            ("max_members", self.max_members),
            ("max_expanded_bytes", self.max_expanded_bytes),
            ("max_manifest_bytes", self.max_manifest_bytes),
            ("max_signature_bytes", self.max_signature_bytes),
            ("max_member_name_length", self.max_member_name_length),
        ):
            if type(value) is not int or value <= 0:
                raise ConfigurationError(f"{name} must be greater than zero")
        if type(self.min_free_bytes) is not int or self.min_free_bytes < 0:
            raise ConfigurationError("min_free_bytes must not be negative")


@dataclass(frozen=True, slots=True)
class VerificationReport:
    """Information obtained after complete signature and content verification."""

    archive: Path
    signer_key_id: str
    created_at: str
    entries_checked: int
    expanded_bytes: int
    missing_optional_sources: tuple[str, ...] = ()
    metadata: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class BackupReport:
    """Information about a created and self-verified archive."""

    archive: Path
    signer_key_id: str
    created_at: str
    entries: int
    expanded_bytes: int
    missing_optional_sources: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class RestoreReport:
    """Information about a verified archive installed at a destination."""

    archive: Path
    destination: Path
    signer_key_id: str
    restored_entries: int
    expanded_bytes: int
