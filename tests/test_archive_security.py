from __future__ import annotations

import hashlib
import io
import json
import tarfile
from collections.abc import Callable
from contextlib import closing
from pathlib import Path

import pytest

from statecrate import (
    ArchiveError,
    IntegrityError,
    LimitError,
    Limits,
    SignatureError,
    SigningKey,
    Source,
    backup,
    verify,
)
from statecrate._archive import canonical_json, signature_document

Transform = Callable[[str, bytes | None, tarfile.TarInfo], tuple[str, bytes | None]]


def _rewrite_archive(source: Path, destination: Path, transform: Transform) -> None:
    members: list[tuple[tarfile.TarInfo, bytes | None]] = []
    with tarfile.open(source, "r:gz") as archive:
        for original in archive:
            data = archive.extractfile(original).read() if original.isfile() else None
            name, data = transform(original.name, data, original)
            info = tarfile.TarInfo(name)
            info.type = original.type
            info.mode = original.mode
            info.size = len(data) if data is not None else 0
            members.append((info, data))
    with tarfile.open(destination, "w:gz") as archive:
        for info, data in members:
            archive.addfile(info, io.BytesIO(data) if data is not None else None)


@pytest.fixture
def signed_archive(tmp_path: Path) -> tuple[Path, SigningKey]:
    source = tmp_path / "source.txt"
    source.write_text("original content", encoding="utf-8")
    key = SigningKey.generate()
    archive = tmp_path / "backup.tar.gz"
    backup(archive, [Source.file(source)], signing_key=key)
    return archive, key


def test_wrong_trusted_key_is_rejected(
    signed_archive: tuple[Path, SigningKey],
) -> None:
    archive, _ = signed_archive
    with pytest.raises(SignatureError, match="not trusted"):
        verify(archive, trusted_keys=SigningKey.generate().verification_key)


def test_changed_manifest_is_rejected_before_content_is_trusted(
    tmp_path: Path,
    signed_archive: tuple[Path, SigningKey],
) -> None:
    archive, key = signed_archive
    changed = tmp_path / "changed-manifest.tar.gz"

    def transform(
        name: str, data: bytes | None, _info: tarfile.TarInfo
    ) -> tuple[str, bytes | None]:
        if name == "statecrate/manifest.json" and data is not None:
            manifest = json.loads(data)
            manifest["metadata"] = {"changed": True}
            return name, canonical_json(manifest)
        return name, data

    _rewrite_archive(archive, changed, transform)
    with pytest.raises(SignatureError, match="invalid"):
        verify(changed, trusted_keys=key.verification_key)


def test_changed_payload_is_rejected_by_signed_checksum(
    tmp_path: Path,
    signed_archive: tuple[Path, SigningKey],
) -> None:
    archive, key = signed_archive
    changed = tmp_path / "changed-payload.tar.gz"

    def transform(
        name: str, data: bytes | None, _info: tarfile.TarInfo
    ) -> tuple[str, bytes | None]:
        if name == "statecrate/payload/source.txt":
            return name, b"modified content"
        return name, data

    _rewrite_archive(archive, changed, transform)
    with pytest.raises(IntegrityError, match="checksum mismatch"):
        verify(changed, trusted_keys=key.verification_key)


def test_unlisted_and_unsafe_members_are_rejected(
    tmp_path: Path,
    signed_archive: tuple[Path, SigningKey],
) -> None:
    archive, key = signed_archive
    extra = tmp_path / "extra.tar.gz"
    with (
        tarfile.open(archive, "r:gz") as original,
        tarfile.open(extra, "w:gz") as output,
    ):
        for member in original:
            data = original.extractfile(member).read() if member.isfile() else None
            output.addfile(member, io.BytesIO(data) if data is not None else None)
        payload = b"extra"
        info = tarfile.TarInfo("statecrate/payload/extra.txt")
        info.size = len(payload)
        output.addfile(info, io.BytesIO(payload))
    with pytest.raises(IntegrityError, match="does not match"):
        verify(extra, trusted_keys=key.verification_key)

    unsafe = tmp_path / "unsafe.tar.gz"
    with tarfile.open(unsafe, "w:gz") as output:
        info = tarfile.TarInfo("statecrate/../escape")
        info.size = 1
        output.addfile(info, io.BytesIO(b"x"))
    with pytest.raises(ArchiveError, match="unsafe archive member"):
        verify(unsafe, trusted_keys=key.verification_key)


def test_unexpected_duplicate_and_missing_members_are_rejected(
    tmp_path: Path,
    signed_archive: tuple[Path, SigningKey],
) -> None:
    archive, key = signed_archive
    unexpected = tmp_path / "unexpected.tar.gz"
    with (
        tarfile.open(archive, "r:gz") as original,
        tarfile.open(unexpected, "w:gz") as output,
    ):
        for member in original:
            data = original.extractfile(member).read() if member.isfile() else None
            output.addfile(member, io.BytesIO(data) if data is not None else None)
        info = tarfile.TarInfo("statecrate/unexpected.txt")
        info.size = 1
        output.addfile(info, io.BytesIO(b"x"))
    with pytest.raises(ArchiveError, match="unexpected archive member"):
        verify(unexpected, trusted_keys=key.verification_key)

    duplicate = tmp_path / "duplicate.tar.gz"
    with (
        tarfile.open(archive, "r:gz") as original,
        tarfile.open(duplicate, "w:gz") as output,
    ):
        root: tarfile.TarInfo | None = None
        for member in original:
            data = original.extractfile(member).read() if member.isfile() else None
            output.addfile(member, io.BytesIO(data) if data is not None else None)
            if member.name == "statecrate":
                root = member
        assert root is not None
        output.addfile(root)
    with pytest.raises(ArchiveError, match="duplicate member"):
        verify(duplicate, trusted_keys=key.verification_key)

    missing = tmp_path / "missing.tar.gz"
    with tarfile.open(missing, "w:gz") as output:
        output.addfile(tarfile.TarInfo("statecrate"))
    with pytest.raises(ArchiveError, match="missing required member"):
        verify(missing, trusted_keys=key.verification_key)


def test_metadata_member_and_name_limits_are_enforced(
    signed_archive: tuple[Path, SigningKey],
) -> None:
    archive, key = signed_archive
    with pytest.raises(LimitError, match="name is too long"):
        verify(
            archive,
            trusted_keys=key.verification_key,
            limits=Limits(max_member_name_length=12, min_free_bytes=0),
        )
    with pytest.raises(LimitError, match="manifest exceeds"):
        verify(
            archive,
            trusted_keys=key.verification_key,
            limits=Limits(max_manifest_bytes=1, min_free_bytes=0),
        )
    with pytest.raises(LimitError, match="signature exceeds"):
        verify(
            archive,
            trusted_keys=key.verification_key,
            limits=Limits(max_signature_bytes=1, min_free_bytes=0),
        )


def test_non_archive_file_has_a_domain_error(tmp_path: Path) -> None:
    path = tmp_path / "not-an-archive"
    path.write_bytes(b"not an archive")
    with pytest.raises(ArchiveError, match="could not open"):
        verify(path, trusted_keys=SigningKey.generate().verification_key)


def test_link_member_is_rejected(
    tmp_path: Path,
    signed_archive: tuple[Path, SigningKey],
) -> None:
    archive, key = signed_archive
    changed = tmp_path / "link.tar.gz"

    def transform(
        name: str, data: bytes | None, info: tarfile.TarInfo
    ) -> tuple[str, bytes | None]:
        if name == "statecrate/payload/source.txt":
            info.type = tarfile.SYMTYPE
            info.linkname = "/etc/passwd"
            return name, None
        return name, data

    _rewrite_archive(archive, changed, transform)
    with pytest.raises(ArchiveError, match="unsafe archive member"):
        verify(changed, trusted_keys=key.verification_key)


def test_expanded_size_and_member_limits_are_enforced(
    signed_archive: tuple[Path, SigningKey],
) -> None:
    archive, key = signed_archive
    with pytest.raises(LimitError, match="expanded byte limit"):
        verify(
            archive,
            trusted_keys=key.verification_key,
            limits=Limits(max_expanded_bytes=1, min_free_bytes=0),
        )
    with pytest.raises(LimitError, match="member limit"):
        verify(
            archive,
            trusted_keys=key.verification_key,
            limits=Limits(max_members=1, min_free_bytes=0),
        )


def test_invalid_sqlite_payload_is_rejected_after_valid_signature(
    tmp_path: Path,
) -> None:
    import sqlite3

    database = tmp_path / "database.db"
    with closing(sqlite3.connect(database)) as connection:
        connection.execute("CREATE TABLE records (value TEXT)")
        connection.commit()
    key = SigningKey.generate()
    archive = tmp_path / "backup.tar.gz"
    backup(archive, [Source.sqlite(database)], signing_key=key)
    invalid = b"not a sqlite database"
    changed_manifest: bytes | None = None

    with tarfile.open(archive, "r:gz") as original:
        manifest_member = original.getmember("statecrate/manifest.json")
        manifest = json.loads(original.extractfile(manifest_member).read())
    entry = next(item for item in manifest["entries"] if item["kind"] == "sqlite")
    entry["size"] = len(invalid)
    entry["sha256"] = hashlib.sha256(invalid).hexdigest()
    changed_manifest = canonical_json(manifest)
    changed_signature = signature_document(key, changed_manifest)
    changed = tmp_path / "invalid-sqlite.tar.gz"

    def transform(
        name: str, data: bytes | None, _info: tarfile.TarInfo
    ) -> tuple[str, bytes | None]:
        if name == "statecrate/manifest.json":
            return name, changed_manifest
        if name == "statecrate/manifest.sig":
            return name, changed_signature
        if name == "statecrate/payload/database.db":
            return name, invalid
        return name, data

    _rewrite_archive(archive, changed, transform)
    with pytest.raises(IntegrityError, match="SQLite integrity"):
        verify(changed, trusted_keys=key.verification_key)
