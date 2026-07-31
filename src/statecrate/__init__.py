"""Signed backups for application files, directories, and SQLite databases."""

from importlib.metadata import PackageNotFoundError, version

from .api import backup, restore, verify
from .errors import (
    ArchiveError,
    ConfigurationError,
    IntegrityError,
    LimitError,
    RestoreError,
    SignatureError,
    SourceError,
    StateCrateError,
    UnsupportedPlatformError,
)
from .keys import SigningKey, VerificationKey
from .models import BackupReport, Limits, RestoreReport, Source, VerificationReport

try:
    __version__ = version("statecrate")
except PackageNotFoundError:  # pragma: no cover - source trees without installation
    __version__ = "0.0.0"

__all__ = [
    "ArchiveError",
    "BackupReport",
    "ConfigurationError",
    "IntegrityError",
    "LimitError",
    "Limits",
    "RestoreError",
    "RestoreReport",
    "SignatureError",
    "SigningKey",
    "Source",
    "SourceError",
    "StateCrateError",
    "UnsupportedPlatformError",
    "VerificationKey",
    "VerificationReport",
    "__version__",
    "backup",
    "restore",
    "verify",
]
