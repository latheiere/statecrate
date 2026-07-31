from __future__ import annotations

import os
import sqlite3
from contextlib import closing
from pathlib import Path

import pytest

import statecrate.api as statecrate_api
from statecrate import (
    ConfigurationError,
    RestoreError,
    SigningKey,
    Source,
    SourceError,
    VerificationKey,
    backup,
    restore,
    verify,
)


def _database(path: Path) -> sqlite3.Connection:
    connection = sqlite3.connect(path)
    connection.execute("PRAGMA journal_mode=WAL")
    connection.execute("CREATE TABLE records (value TEXT NOT NULL)")
    connection.execute("INSERT INTO records VALUES ('stored value')")
    connection.commit()
    return connection


def test_backup_verify_and_restore_all_source_kinds(tmp_path: Path) -> None:
    config = tmp_path / "config.json"
    config.write_text('{"enabled": true}\n', encoding="utf-8")
    config.chmod(0o640)
    uploads = tmp_path / "uploads"
    (uploads / "empty").mkdir(parents=True)
    (uploads / "document.txt").write_text("content\n", encoding="utf-8")
    database = tmp_path / "application.db"
    connection = _database(database)
    key = SigningKey.generate()
    archive = tmp_path / "backup.tar.gz"

    try:
        result = backup(
            archive,
            [
                Source.file(config, at="configuration/config.json"),
                Source.directory(uploads, at="uploads"),
                Source.sqlite(database, at="data/application.db"),
                Source.file(
                    tmp_path / "optional.cache",
                    at="cache/optional.cache",
                    required=False,
                ),
            ],
            signing_key=key,
            metadata={"application": "example"},
        )
    finally:
        connection.close()

    assert result.archive == archive
    assert result.signer_key_id == key.key_id
    assert result.missing_optional_sources == ("cache/optional.cache",)
    assert archive.stat().st_mode & 0o777 == 0o600

    report = verify(archive, trusted_keys=key.verification_key)
    assert report.metadata == {"application": "example"}
    assert report.entries_checked == 7

    destination = tmp_path / "restored"
    restored = restore(archive, destination, trusted_keys=key.verification_key)
    assert restored.destination == destination
    assert (destination / "configuration/config.json").read_text() == config.read_text()
    assert (destination / "configuration/config.json").stat().st_mode & 0o777 == 0o640
    assert (destination / "uploads/document.txt").read_text() == "content\n"
    assert (destination / "uploads/empty").is_dir()
    with closing(
        sqlite3.connect(destination / "data/application.db")
    ) as restored_database:
        assert restored_database.execute("SELECT value FROM records").fetchone() == (
            "stored value",
        )


def test_restore_replaces_the_complete_destination_tree(tmp_path: Path) -> None:
    source = tmp_path / "source.txt"
    source.write_text("new", encoding="utf-8")
    key = SigningKey.generate()
    archive = tmp_path / "backup.tar.gz"
    backup(archive, [Source.file(source)], signing_key=key)
    destination = tmp_path / "state"
    destination.mkdir()
    (destination / "unrelated.txt").write_text("old", encoding="utf-8")

    with pytest.raises(RestoreError, match="already exists"):
        restore(archive, destination, trusted_keys=key.verification_key)
    assert (destination / "unrelated.txt").read_text() == "old"

    restore(
        archive,
        destination,
        trusted_keys=key.verification_key,
        replace=True,
    )
    assert not (destination / "unrelated.txt").exists()
    assert (destination / "source.txt").read_text() == "new"


def test_key_round_trip_and_file_permissions(tmp_path: Path) -> None:
    signing = SigningKey.generate()
    private_path = tmp_path / "private.pem"
    public_path = tmp_path / "public.pem"
    signing.save(private_path, password=b"long-enough-example-password")
    signing.verification_key.save(public_path)

    loaded_signing = SigningKey.load(
        private_path, password=b"long-enough-example-password"
    )
    loaded_public = VerificationKey.load(public_path)
    assert loaded_signing.key_id == signing.key_id == loaded_public.key_id
    assert private_path.stat().st_mode & 0o777 == 0o600
    assert public_path.stat().st_mode & 0o777 == 0o644

    with pytest.raises(ConfigurationError, match="already exists"):
        signing.save(private_path)


def test_required_missing_source_fails_but_optional_source_is_recorded(
    tmp_path: Path,
) -> None:
    key = SigningKey.generate()
    with pytest.raises(SourceError, match="required backup source"):
        backup(
            tmp_path / "backup.tar.gz",
            [Source.file(tmp_path / "missing")],
            signing_key=key,
        )

    existing = tmp_path / "existing"
    existing.write_text("content", encoding="utf-8")
    result = backup(
        tmp_path / "backup.tar.gz",
        [
            Source.file(existing),
            Source.file(tmp_path / "missing", required=False),
        ],
        signing_key=key,
    )
    assert result.missing_optional_sources == ("missing",)


def test_source_and_output_safety_checks(tmp_path: Path) -> None:
    key = SigningKey.generate()
    source_directory = tmp_path / "state"
    source_directory.mkdir()
    source = source_directory / "source.txt"
    source.write_text("content", encoding="utf-8")
    link = tmp_path / "link"
    link.symlink_to(source)

    with pytest.raises(SourceError, match="symlink"):
        backup(tmp_path / "link.tar.gz", [Source.file(link)], signing_key=key)
    with pytest.raises(ConfigurationError, match="overlaps"):
        backup(
            source_directory / "backup.tar.gz",
            [Source.directory(source_directory)],
            signing_key=key,
        )
    with pytest.raises(ConfigurationError, match="overlapping archive paths"):
        backup(
            tmp_path / "overlap.tar.gz",
            [Source.file(source, at="data"), Source.file(source, at="data/file")],
            signing_key=key,
        )


def test_failed_overwrite_preserves_existing_archive(tmp_path: Path) -> None:
    archive = tmp_path / "backup.tar.gz"
    archive.write_bytes(b"known good bytes")
    key = SigningKey.generate()
    with pytest.raises(SourceError):
        backup(
            archive,
            [Source.file(tmp_path / "missing")],
            signing_key=key,
            overwrite=True,
        )
    assert archive.read_bytes() == b"known good bytes"


def test_version_comes_from_installed_metadata() -> None:
    from importlib.metadata import version

    import statecrate

    assert statecrate.__version__ == version("statecrate")


def test_private_key_overwrite_is_atomic(tmp_path: Path) -> None:
    path = tmp_path / "key.pem"
    first = SigningKey.generate()
    second = SigningKey.generate()
    first.save(path)
    second.save(path, overwrite=True)
    assert SigningKey.load(path).key_id == second.key_id
    assert os.stat(path).st_mode & 0o777 == 0o600


def test_failed_replacement_rolls_back_the_previous_tree(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "source"
    source.write_text("new", encoding="utf-8")
    key = SigningKey.generate()
    archive = tmp_path / "backup.tar.gz"
    backup(archive, [Source.file(source)], signing_key=key)
    destination = tmp_path / "state"
    destination.mkdir()
    previous = destination / "previous"
    previous.write_text("old", encoding="utf-8")
    real_replace = os.replace

    def fail_payload_install(
        source_path: os.PathLike[str], target_path: os.PathLike[str]
    ) -> None:
        if Path(source_path).name == "payload" and Path(target_path) == destination:
            raise OSError("simulated installation failure")
        real_replace(source_path, target_path)

    monkeypatch.setattr(statecrate_api.os, "replace", fail_payload_install)
    with pytest.raises(OSError, match="simulated"):
        restore(
            archive,
            destination,
            trusted_keys=key.verification_key,
            replace=True,
        )
    assert previous.read_text() == "old"


def test_restrictive_restore_modes_are_applied_after_content_is_verified(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    source.write_text("private", encoding="utf-8")
    directory = tmp_path / "directory"
    directory.mkdir()
    (directory / "nested").write_text("content", encoding="utf-8")
    key = SigningKey.generate()
    archive = tmp_path / "backup.tar.gz"
    backup(
        archive,
        [
            Source.file(source, at="private", mode=0o000),
            Source.directory(directory, at="locked", mode=0o000),
        ],
        signing_key=key,
    )
    destination = tmp_path / "restored"
    restore(archive, destination, trusted_keys=key.verification_key)
    private = destination / "private"
    locked = destination / "locked"
    assert private.stat().st_mode & 0o777 == 0o000
    assert locked.stat().st_mode & 0o777 == 0o000
    private.chmod(0o600)
    locked.chmod(0o700)
