from __future__ import annotations

import json
import os
from collections.abc import Callable
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

import statecrate._filesystem as filesystem
from statecrate import (
    ArchiveError,
    ConfigurationError,
    LimitError,
    Limits,
    RestoreError,
    SignatureError,
    SigningKey,
    Source,
    SourceError,
    UnsupportedPlatformError,
    VerificationKey,
    backup,
    restore,
    verify,
)
from statecrate._archive import (
    canonical_json,
    signature_document,
    validate_manifest,
    verify_manifest_signature,
)


def _manifest() -> dict[str, object]:
    return {
        "created_at": "2026-01-01T00:00:00+00:00",
        "entries": [
            {
                "kind": "file",
                "mode": 0o600,
                "path": "data.txt",
                "sha256": "0" * 64,
                "size": 0,
            }
        ],
        "format": "statecrate",
        "format_version": 1,
        "metadata": {},
        "missing_optional_sources": [],
    }


ManifestMutation = Callable[[dict[str, object]], None]


def _remove_format(manifest: dict[str, object]) -> None:
    del manifest["format"]


def _bad_entry(manifest: dict[str, object]) -> None:
    manifest["entries"] = [{}]


def _entry_value(field: str, value: object) -> ManifestMutation:
    def mutate(manifest: dict[str, object]) -> None:
        entries = manifest["entries"]
        assert isinstance(entries, list)
        entry = entries[0]
        assert isinstance(entry, dict)
        entry[field] = value

    return mutate


def _duplicate(manifest: dict[str, object]) -> None:
    entries = manifest["entries"]
    assert isinstance(entries, list)
    entries.append(dict(entries[0]))


def _nested_below_file(manifest: dict[str, object]) -> None:
    entries = manifest["entries"]
    assert isinstance(entries, list)
    first = entries[0]
    assert isinstance(first, dict)
    first["path"] = "parent"
    entries.append({**first, "path": "parent/child"})


def _file_above_entry(manifest: dict[str, object]) -> None:
    entries = manifest["entries"]
    assert isinstance(entries, list)
    first = entries[0]
    assert isinstance(first, dict)
    first["path"] = "parent/child"
    entries.append({**first, "path": "parent"})


@pytest.mark.parametrize(
    "mutation",
    [
        _remove_format,
        lambda value: value.__setitem__("format_version", 2),
        lambda value: value.__setitem__("format_version", True),
        lambda value: value.__setitem__("created_at", 1),
        lambda value: value.__setitem__("created_at", "invalid"),
        lambda value: value.__setitem__("created_at", "2026-01-01T00:00:00"),
        lambda value: value.__setitem__("metadata", []),
        lambda value: value.__setitem__("missing_optional_sources", [1]),
        lambda value: value.__setitem__("missing_optional_sources", ["../unsafe"]),
        lambda value: value.__setitem__("entries", []),
        _bad_entry,
        _entry_value("path", 1),
        _entry_value("path", "../unsafe"),
        _entry_value("kind", "unknown"),
        _entry_value("mode", True),
        _entry_value("size", -1),
        _entry_value("sha256", "invalid"),
        _duplicate,
        _nested_below_file,
        _file_above_entry,
    ],
)
def test_manifest_rejects_invalid_contracts(mutation: ManifestMutation) -> None:
    manifest = _manifest()
    mutation(manifest)
    with pytest.raises(ArchiveError):
        validate_manifest(canonical_json(manifest))


def test_manifest_rejects_invalid_and_noncanonical_json() -> None:
    with pytest.raises(ArchiveError, match="valid UTF-8 JSON"):
        validate_manifest(b"not json")
    readable = json.dumps(_manifest()).encode()
    with pytest.raises(ArchiveError, match="canonical"):
        validate_manifest(readable)
    with pytest.raises(ArchiveError, match="JSON values"):
        canonical_json({"not-json": object()})


def test_directory_manifest_entry_cannot_have_content() -> None:
    manifest = _manifest()
    entries = manifest["entries"]
    assert isinstance(entries, list)
    entry = entries[0]
    assert isinstance(entry, dict)
    entry.update(kind="directory", size=1, sha256=None)
    with pytest.raises(ArchiveError, match="file content"):
        validate_manifest(canonical_json(manifest))


def test_signature_document_validation() -> None:
    key = SigningKey.generate()
    manifest = canonical_json(_manifest())
    valid = json.loads(signature_document(key, manifest))

    with pytest.raises(SignatureError, match="invalid"):
        verify_manifest_signature(manifest, b"not json", key.verification_key)
    with pytest.raises(SignatureError, match="invalid shape"):
        verify_manifest_signature(manifest, canonical_json({}), key.verification_key)

    changed = dict(valid)
    changed["algorithm"] = "unknown"
    with pytest.raises(SignatureError, match="algorithm"):
        verify_manifest_signature(
            manifest, canonical_json(changed), key.verification_key
        )

    changed = dict(valid)
    changed["key_id"] = 1
    with pytest.raises(SignatureError, match="invalid values"):
        verify_manifest_signature(
            manifest, canonical_json(changed), key.verification_key
        )

    changed = dict(valid)
    changed["signature"] = "not base64!"
    with pytest.raises(SignatureError, match="encoding"):
        verify_manifest_signature(
            manifest, canonical_json(changed), key.verification_key
        )

    with pytest.raises(SignatureError, match="at least one"):
        verify_manifest_signature(manifest, canonical_json(valid), [])
    with pytest.raises(SignatureError, match="VerificationKey"):
        verify_manifest_signature(
            manifest,
            canonical_json(valid),
            [object()],  # type: ignore[list-item]
        )
    with pytest.raises(SignatureError, match="canonical"):
        verify_manifest_signature(
            manifest, json.dumps(valid).encode(), key.verification_key
        )


def test_key_loaders_reject_missing_invalid_and_non_ed25519_keys(
    tmp_path: Path,
) -> None:
    missing = tmp_path / "missing.pem"
    with pytest.raises(ConfigurationError, match="regular file"):
        SigningKey.load(missing)
    with pytest.raises(ConfigurationError, match="regular file"):
        VerificationKey.load(missing)
    with pytest.raises(ConfigurationError, match="invalid private"):
        SigningKey.from_pem(b"invalid")
    with pytest.raises(ConfigurationError, match="invalid public"):
        VerificationKey.from_pem(b"invalid")

    private = ec.generate_private_key(ec.SECP256R1())
    private_pem = private.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    public_pem = private.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    with pytest.raises(ConfigurationError, match="must use Ed25519"):
        SigningKey.from_pem(private_pem)
    with pytest.raises(ConfigurationError, match="must use Ed25519"):
        VerificationKey.from_pem(public_pem)


def test_public_api_rejects_invalid_configuration(tmp_path: Path) -> None:
    key = SigningKey.generate()
    source = tmp_path / "source"
    source.write_text("content", encoding="utf-8")
    archive = tmp_path / "backup.tar.gz"

    with pytest.raises(ConfigurationError, match="at least one"):
        backup(archive, [], signing_key=key)
    with pytest.raises(ConfigurationError, match="SigningKey"):
        backup(archive, [Source.file(source)], signing_key=object())  # type: ignore[arg-type]
    with pytest.raises(ConfigurationError, match="Source values"):
        backup(archive, [object()], signing_key=key)  # type: ignore[list-item]
    with pytest.raises(ConfigurationError, match="file path"):
        backup(Path("/"), [Source.file(source)], signing_key=key)

    output_directory = tmp_path / "output"
    output_directory.mkdir()
    with pytest.raises(ConfigurationError, match="directory"):
        backup(output_directory, [Source.file(source)], signing_key=key)

    backup(archive, [Source.file(source)], signing_key=key)
    with pytest.raises(ConfigurationError, match="already exists"):
        backup(archive, [Source.file(source)], signing_key=key)
    with pytest.raises(ConfigurationError, match="does not exist"):
        verify(tmp_path / "missing.tar.gz", trusted_keys=key.verification_key)
    with pytest.raises(ConfigurationError, match="does not exist"):
        restore(
            tmp_path / "missing.tar.gz",
            tmp_path / "restore",
            trusted_keys=key.verification_key,
        )

    destination_file = tmp_path / "destination-file"
    destination_file.write_text("content", encoding="utf-8")
    with pytest.raises(ConfigurationError, match="must not be a file"):
        restore(archive, destination_file, trusted_keys=key.verification_key)


def test_source_kind_and_size_validation(tmp_path: Path) -> None:
    key = SigningKey.generate()
    file_path = tmp_path / "file"
    file_path.write_bytes(b"content")
    directory = tmp_path / "directory"
    directory.mkdir()

    with pytest.raises(SourceError, match="not a directory"):
        backup(
            tmp_path / "directory.tar.gz",
            [Source.directory(file_path)],
            signing_key=key,
        )
    with pytest.raises(SourceError, match="not a regular file"):
        backup(
            tmp_path / "file.tar.gz",
            [Source.file(directory)],
            signing_key=key,
        )
    with pytest.raises(SourceError, match="SQLite backup source"):
        backup(
            tmp_path / "sqlite.tar.gz",
            [Source.sqlite(directory)],
            signing_key=key,
        )
    with pytest.raises(LimitError, match="expanded byte limit"):
        backup(
            tmp_path / "small.tar.gz",
            [Source.file(file_path)],
            signing_key=key,
            limits=Limits(max_expanded_bytes=1, min_free_bytes=0),
        )

    fifo = tmp_path / "fifo"
    os.mkfifo(fifo)
    with pytest.raises(SourceError, match="regular file or directory"):
        backup(tmp_path / "fifo.tar.gz", [Source.file(fifo)], signing_key=key)


def test_posix_requirement_is_explicit(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(filesystem.os, "name", "nt")
    with pytest.raises(UnsupportedPlatformError, match="POSIX"):
        filesystem.require_posix()


def test_restore_rejects_archive_inside_destination(tmp_path: Path) -> None:
    key = SigningKey.generate()
    source = tmp_path / "source"
    source.write_text("content", encoding="utf-8")
    destination = tmp_path / "state"
    destination.mkdir()
    archive = destination / "backup.tar.gz"
    backup(archive, [Source.file(source)], signing_key=key)
    with pytest.raises(RestoreError, match="inside"):
        restore(
            archive,
            destination,
            trusted_keys=key.verification_key,
            replace=True,
        )
