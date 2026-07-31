"""StateCrate's public exception hierarchy."""


class StateCrateError(Exception):
    """Base class for all expected StateCrate failures."""


class UnsupportedPlatformError(StateCrateError):
    """The current operating system cannot provide the required guarantees."""


class ConfigurationError(StateCrateError):
    """A caller supplied an invalid source, path, key, or limit."""


class SourceError(StateCrateError):
    """A backup source is missing, unsafe, or has an unexpected type."""


class ArchiveError(StateCrateError):
    """An archive is malformed or contains unsafe members."""


class LimitError(ArchiveError):
    """An operation would exceed a configured resource limit."""


class SignatureError(ArchiveError):
    """A manifest signature is invalid or has no trusted verification key."""


class IntegrityError(ArchiveError):
    """Archived content does not match its signed manifest."""


class RestoreError(StateCrateError):
    """Verified content could not be installed at the destination."""
