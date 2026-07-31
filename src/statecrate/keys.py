"""Ed25519 key handling for manifest signatures."""

from __future__ import annotations

import hashlib
import os
import tempfile
from dataclasses import dataclass
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .errors import ConfigurationError, SignatureError


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _key_id(key: Ed25519PublicKey) -> str:
    raw = key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return f"sha256:{hashlib.sha256(raw).hexdigest()}"


def _write_private_file(
    path: Path,
    data: bytes,
    *,
    mode: int,
    overwrite: bool,
) -> None:
    path = path.expanduser()
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink():
        raise ConfigurationError(f"key path must not be a symlink: {path}")
    if not overwrite:
        try:
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
        except FileExistsError as error:
            raise ConfigurationError(f"key path already exists: {path}") from error
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        _fsync_directory(path.parent)
        return

    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            dir=path.parent,
            prefix=f".{path.name}.",
            delete=False,
        ) as handle:
            temporary = Path(handle.name)
            os.chmod(temporary, mode)
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        _fsync_directory(path.parent)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


@dataclass(frozen=True, slots=True)
class VerificationKey:
    """A trusted public key used to verify StateCrate manifests."""

    _key: Ed25519PublicKey

    @property
    def key_id(self) -> str:
        return _key_id(self._key)

    @classmethod
    def from_pem(cls, data: bytes) -> VerificationKey:
        try:
            key = serialization.load_pem_public_key(data)
        except (TypeError, ValueError) as error:
            raise ConfigurationError("invalid public verification key") from error
        if not isinstance(key, Ed25519PublicKey):
            raise ConfigurationError("verification key must use Ed25519")
        return cls(key)

    @classmethod
    def load(cls, path: str | Path) -> VerificationKey:
        key_path = Path(path).expanduser()
        if key_path.is_symlink() or not key_path.is_file():
            raise ConfigurationError(f"public key must be a regular file: {key_path}")
        return cls.from_pem(key_path.read_bytes())

    def to_pem(self) -> bytes:
        return self._key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    def save(self, path: str | Path, *, overwrite: bool = False) -> None:
        _write_private_file(Path(path), self.to_pem(), mode=0o644, overwrite=overwrite)

    def verify(self, signature: bytes, data: bytes) -> None:
        try:
            self._key.verify(signature, data)
        except InvalidSignature as error:
            raise SignatureError("manifest signature is invalid") from error


@dataclass(frozen=True, slots=True)
class SigningKey:
    """A private Ed25519 key used to sign StateCrate manifests."""

    _key: Ed25519PrivateKey

    @property
    def key_id(self) -> str:
        return _key_id(self._key.public_key())

    @property
    def verification_key(self) -> VerificationKey:
        return VerificationKey(self._key.public_key())

    @classmethod
    def generate(cls) -> SigningKey:
        return cls(Ed25519PrivateKey.generate())

    @classmethod
    def from_pem(
        cls,
        data: bytes,
        *,
        password: bytes | None = None,
    ) -> SigningKey:
        try:
            key = serialization.load_pem_private_key(data, password=password)
        except (TypeError, ValueError) as error:
            raise ConfigurationError(
                "invalid private signing key or password"
            ) from error
        if not isinstance(key, Ed25519PrivateKey):
            raise ConfigurationError("signing key must use Ed25519")
        return cls(key)

    @classmethod
    def load(
        cls,
        path: str | Path,
        *,
        password: bytes | None = None,
    ) -> SigningKey:
        key_path = Path(path).expanduser()
        if key_path.is_symlink() or not key_path.is_file():
            raise ConfigurationError(f"private key must be a regular file: {key_path}")
        return cls.from_pem(key_path.read_bytes(), password=password)

    def to_pem(self, *, password: bytes | None = None) -> bytes:
        encryption: serialization.KeySerializationEncryption
        if password is None:
            encryption = serialization.NoEncryption()
        else:
            encryption = serialization.BestAvailableEncryption(password)
        return self._key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption,
        )

    def save(
        self,
        path: str | Path,
        *,
        password: bytes | None = None,
        overwrite: bool = False,
    ) -> None:
        _write_private_file(
            Path(path),
            self.to_pem(password=password),
            mode=0o600,
            overwrite=overwrite,
        )

    def sign(self, data: bytes) -> bytes:
        return self._key.sign(data)
