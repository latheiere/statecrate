"""Signed archive creation, inspection, extraction, and verification."""

from __future__ import annotations

import base64
import binascii
import hashlib
import io
import json
import os
import re
import shutil
import tarfile
from collections.abc import Iterable, Mapping, Sequence
from contextlib import ExitStack
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any

from ._filesystem import check_sqlite, sha256_file, validate_relative_path
from .errors import (
    ArchiveError,
    IntegrityError,
    LimitError,
    SignatureError,
    SourceError,
)
from .keys import SigningKey, VerificationKey
from .models import Limits, VerificationReport

ARCHIVE_ROOT = "statecrate"
PAYLOAD_ROOT = f"{ARCHIVE_ROOT}/payload"
MANIFEST_NAME = f"{ARCHIVE_ROOT}/manifest.json"
SIGNATURE_NAME = f"{ARCHIVE_ROOT}/manifest.sig"
FORMAT_NAME = "statecrate"
FORMAT_VERSION = 1
SIGNATURE_ALGORITHM = "ed25519"
_SHA256 = re.compile(r"[0-9a-f]{64}")


def canonical_json(value: object) -> bytes:
    try:
        return (
            json.dumps(
                value,
                ensure_ascii=False,
                allow_nan=False,
                separators=(",", ":"),
                sort_keys=True,
            )
            + "\n"
        ).encode("utf-8")
    except (TypeError, ValueError) as error:
        raise ArchiveError("manifest metadata must contain JSON values") from error


def signature_document(signing_key: SigningKey, manifest_bytes: bytes) -> bytes:
    return canonical_json(
        {
            "algorithm": SIGNATURE_ALGORITHM,
            "key_id": signing_key.key_id,
            "signature": base64.b64encode(signing_key.sign(manifest_bytes)).decode(
                "ascii"
            ),
        }
    )


def _trusted_key_map(
    trusted_keys: VerificationKey | Iterable[VerificationKey],
) -> dict[str, VerificationKey]:
    values = (
        [trusted_keys]
        if isinstance(trusted_keys, VerificationKey)
        else list(trusted_keys)
    )
    if not values:
        raise SignatureError("at least one trusted verification key is required")
    result: dict[str, VerificationKey] = {}
    for key in values:
        if not isinstance(key, VerificationKey):
            raise SignatureError("trusted keys must be VerificationKey values")
        result[key.key_id] = key
    return result


def verify_manifest_signature(
    manifest_bytes: bytes,
    signature_bytes: bytes,
    trusted_keys: VerificationKey | Iterable[VerificationKey],
) -> str:
    try:
        document = json.loads(signature_bytes)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise SignatureError("manifest signature document is invalid") from error
    if not isinstance(document, dict) or set(document) != {
        "algorithm",
        "key_id",
        "signature",
    }:
        raise SignatureError("manifest signature document has an invalid shape")
    if canonical_json(document) != signature_bytes:
        raise SignatureError("manifest signature document is not canonical JSON")
    if document["algorithm"] != SIGNATURE_ALGORITHM:
        raise SignatureError("manifest signature algorithm is not supported")
    key_id = document["key_id"]
    encoded = document["signature"]
    if not isinstance(key_id, str) or not isinstance(encoded, str):
        raise SignatureError("manifest signature document has invalid values")
    key = _trusted_key_map(trusted_keys).get(key_id)
    if key is None:
        raise SignatureError(f"manifest signer is not trusted: {key_id}")
    try:
        signature = base64.b64decode(encoded, validate=True)
    except (ValueError, binascii.Error) as error:
        raise SignatureError("manifest signature encoding is invalid") from error
    key.verify(signature, manifest_bytes)
    return key_id


def _safe_manifest_path(value: object, *, label: str) -> PurePosixPath:
    if not isinstance(value, str):
        raise ArchiveError(f"{label} must be a string")
    path = PurePosixPath(value)
    try:
        validate_relative_path(path, label=label)
    except SourceError as error:
        raise ArchiveError(str(error)) from error
    return path


def validate_manifest(data: bytes) -> dict[str, Any]:
    try:
        manifest = json.loads(data)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ArchiveError("manifest is not valid UTF-8 JSON") from error
    if not isinstance(manifest, dict) or set(manifest) != {
        "created_at",
        "entries",
        "format",
        "format_version",
        "metadata",
        "missing_optional_sources",
    }:
        raise ArchiveError("manifest has an invalid shape")
    if canonical_json(manifest) != data:
        raise ArchiveError("manifest is not canonical JSON")
    if (
        manifest["format"] != FORMAT_NAME
        or type(manifest["format_version"]) is not int
        or manifest["format_version"] != FORMAT_VERSION
    ):
        raise ArchiveError("archive format is not supported")
    created_at = manifest["created_at"]
    if not isinstance(created_at, str):
        raise ArchiveError("manifest creation time must be a string")
    try:
        parsed_time = datetime.fromisoformat(created_at)
    except ValueError as error:
        raise ArchiveError("manifest creation time is invalid") from error
    if parsed_time.tzinfo is None:
        raise ArchiveError("manifest creation time must include a UTC offset")
    if not isinstance(manifest["metadata"], dict):
        raise ArchiveError("manifest metadata must be an object")
    missing = manifest["missing_optional_sources"]
    if not isinstance(missing, list) or any(
        not isinstance(item, str) for item in missing
    ):
        raise ArchiveError("missing optional sources must be a list of paths")
    for item in missing:
        _safe_manifest_path(item, label="missing optional source path")

    entries = manifest["entries"]
    if not isinstance(entries, list) or not entries:
        raise ArchiveError("manifest must contain at least one entry")
    seen: dict[PurePosixPath, str] = {}
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != {
            "kind",
            "mode",
            "path",
            "sha256",
            "size",
        }:
            raise ArchiveError("manifest contains an invalid entry")
        path = _safe_manifest_path(entry["path"], label="manifest entry path")
        kind = entry["kind"]
        if kind not in {"file", "directory", "sqlite"}:
            raise ArchiveError(f"manifest entry has an invalid kind: {path}")
        if type(entry["mode"]) is not int or not 0 <= entry["mode"] <= 0o777:
            raise ArchiveError(f"manifest entry has an invalid mode: {path}")
        if type(entry["size"]) is not int or entry["size"] < 0:
            raise ArchiveError(f"manifest entry has an invalid size: {path}")
        digest = entry["sha256"]
        if kind == "directory":
            if entry["size"] != 0 or digest is not None:
                raise ArchiveError(f"directory manifest entry has file content: {path}")
        elif not isinstance(digest, str) or _SHA256.fullmatch(digest) is None:
            raise ArchiveError(f"manifest entry has an invalid checksum: {path}")
        if path in seen:
            raise ArchiveError(f"manifest contains a duplicate path: {path}")
        for parent in path.parents:
            if parent == PurePosixPath("."):
                continue
            if seen.get(parent) in {"file", "sqlite"}:
                raise ArchiveError(f"manifest path is nested below a file: {path}")
        if kind in {"file", "sqlite"}:
            prefix = path.as_posix() + "/"
            if any(existing.as_posix().startswith(prefix) for existing in seen):
                raise ArchiveError(f"manifest file path contains another entry: {path}")
        seen[path] = kind
    return manifest


def _normalized_member_name(member: tarfile.TarInfo, limits: Limits) -> str:
    name = member.name.rstrip("/")
    path = PurePosixPath(name)
    if (
        not name
        or path.is_absolute()
        or ".." in path.parts
        or path.as_posix() != name
        or path.parts[0] != ARCHIVE_ROOT
        or not (member.isfile() or member.isdir())
    ):
        raise ArchiveError(f"unsafe archive member: {member.name}")
    if len(name) > limits.max_member_name_length:
        raise LimitError(f"archive member name is too long: {name[:80]}")
    if member.size < 0:
        raise ArchiveError(f"archive member has an invalid size: {name}")
    return name


def inspect_members(
    archive: tarfile.TarFile,
    limits: Limits,
) -> tuple[dict[str, tarfile.TarInfo], int]:
    members: dict[str, tarfile.TarInfo] = {}
    payload_bytes = 0
    for count, member in enumerate(archive, start=1):
        if count > limits.max_members:
            raise LimitError("archive exceeds the member limit")
        name = _normalized_member_name(member, limits)
        if name in members:
            raise ArchiveError(f"archive contains a duplicate member: {name}")
        if name not in {
            ARCHIVE_ROOT,
            PAYLOAD_ROOT,
            MANIFEST_NAME,
            SIGNATURE_NAME,
        } and not name.startswith(PAYLOAD_ROOT + "/"):
            raise ArchiveError(f"unexpected archive member: {name}")
        members[name] = member
        if member.isfile():
            if name == MANIFEST_NAME and member.size > limits.max_manifest_bytes:
                raise LimitError("manifest exceeds the size limit")
            if name == SIGNATURE_NAME and member.size > limits.max_signature_bytes:
                raise LimitError("manifest signature exceeds the size limit")
            if name.startswith(PAYLOAD_ROOT + "/"):
                payload_bytes += member.size
                if payload_bytes > limits.max_expanded_bytes:
                    raise LimitError("archive exceeds the expanded byte limit")
    for required, directory in (
        (ARCHIVE_ROOT, True),
        (PAYLOAD_ROOT, True),
        (MANIFEST_NAME, False),
        (SIGNATURE_NAME, False),
    ):
        required_member = members.get(required)
        if required_member is None or required_member.isdir() != directory:
            raise ArchiveError(f"archive is missing required member: {required}")
    return members, payload_bytes


def _member_bytes(archive: tarfile.TarFile, member: tarfile.TarInfo) -> bytes:
    handle = archive.extractfile(member)
    if handle is None:
        raise ArchiveError(f"archive member cannot be read: {member.name}")
    data = handle.read(member.size + 1)
    if len(data) != member.size:
        raise ArchiveError(f"archive member is truncated: {member.name}")
    return data


def _entry_map(manifest: Mapping[str, Any]) -> dict[str, Mapping[str, Any]]:
    return {entry["path"]: entry for entry in manifest["entries"]}


def _compare_manifest_to_members(
    manifest: Mapping[str, Any],
    members: Mapping[str, tarfile.TarInfo],
) -> None:
    entries = _entry_map(manifest)
    actual: dict[str, tarfile.TarInfo] = {
        name.removeprefix(PAYLOAD_ROOT + "/"): member
        for name, member in members.items()
        if name.startswith(PAYLOAD_ROOT + "/")
    }
    if set(actual) != set(entries):
        raise IntegrityError("archive payload does not match the signed manifest")
    for path, entry in entries.items():
        member = actual[path]
        expected_directory = entry["kind"] == "directory"
        if member.isdir() != expected_directory or member.size != entry["size"]:
            raise IntegrityError(f"archive member does not match its manifest: {path}")


def extract_verified(
    archive_path: Path,
    destination: Path,
    *,
    trusted_keys: VerificationKey | Iterable[VerificationKey],
    limits: Limits,
    durable: bool = False,
) -> tuple[VerificationReport, Path]:
    with ExitStack() as stack:
        try:
            archive = stack.enter_context(tarfile.open(archive_path, "r:gz"))
        except (OSError, tarfile.TarError) as error:
            raise ArchiveError(
                f"could not open StateCrate archive: {archive_path}"
            ) from error
        members, payload_bytes = inspect_members(archive, limits)
        manifest_bytes = _member_bytes(archive, members[MANIFEST_NAME])
        signature_bytes = _member_bytes(archive, members[SIGNATURE_NAME])
        signer_key_id = verify_manifest_signature(
            manifest_bytes, signature_bytes, trusted_keys
        )
        manifest = validate_manifest(manifest_bytes)
        _compare_manifest_to_members(manifest, members)
        available = shutil.disk_usage(destination).free
        if available < payload_bytes + limits.min_free_bytes:
            raise LimitError("insufficient free space to extract archive")

        payload = destination / "payload"
        payload.mkdir(mode=0o700)
        entries = _entry_map(manifest)
        directory_modes: list[tuple[Path, int]] = []
        for path_text in sorted(entries, key=lambda item: (item.count("/"), item)):
            entry = entries[path_text]
            relative = PurePosixPath(path_text)
            target = payload.joinpath(*relative.parts)
            member = members[f"{PAYLOAD_ROOT}/{path_text}"]
            if entry["kind"] == "directory":
                target.mkdir(parents=True, exist_ok=True, mode=0o700)
                directory_modes.append((target, entry["mode"]))
                continue
            target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            source = archive.extractfile(member)
            if source is None:
                raise ArchiveError(f"archive member cannot be read: {path_text}")
            digest = hashlib.sha256()
            written = 0
            with target.open("xb") as output:
                while chunk := source.read(1024 * 1024):
                    written += len(chunk)
                    if written > entry["size"]:
                        raise IntegrityError(
                            f"archive member exceeds its size: {path_text}"
                        )
                    digest.update(chunk)
                    output.write(chunk)
            if written != entry["size"] or digest.hexdigest() != entry["sha256"]:
                raise IntegrityError(f"archive checksum mismatch: {path_text}")
            if entry["kind"] == "sqlite":
                check_sqlite(target)
            descriptor = os.open(target, os.O_RDONLY)
            try:
                os.fchmod(descriptor, entry["mode"])
                if durable:
                    os.fsync(descriptor)
            finally:
                os.close(descriptor)

        for directory, mode in sorted(
            directory_modes,
            key=lambda item: len(item[0].parts),
            reverse=True,
        ):
            descriptor = os.open(directory, os.O_RDONLY)
            try:
                os.fchmod(descriptor, mode)
                if durable:
                    os.fsync(descriptor)
            finally:
                os.close(descriptor)
        if durable:
            descriptor = os.open(payload, os.O_RDONLY)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)

    report = VerificationReport(
        archive=archive_path,
        signer_key_id=signer_key_id,
        created_at=manifest["created_at"],
        entries_checked=len(manifest["entries"]),
        expanded_bytes=payload_bytes,
        missing_optional_sources=tuple(manifest["missing_optional_sources"]),
        metadata=dict(manifest["metadata"]),
    )
    return report, payload


def _tar_info(
    name: str, *, mode: int, size: int = 0, directory: bool = False
) -> tarfile.TarInfo:
    info = tarfile.TarInfo(name)
    info.type = tarfile.DIRTYPE if directory else tarfile.REGTYPE
    info.mode = mode
    info.size = 0 if directory else size
    info.mtime = 0
    info.uid = 0
    info.gid = 0
    info.uname = ""
    info.gname = ""
    return info


def write_archive(
    handle: Any,
    payload: Path,
    manifest: Mapping[str, Any],
    signing_key: SigningKey,
) -> None:
    manifest_bytes = canonical_json(manifest)
    signature_bytes = signature_document(signing_key, manifest_bytes)
    with tarfile.open(
        fileobj=handle, mode="w:gz", format=tarfile.PAX_FORMAT
    ) as archive:
        archive.addfile(_tar_info(ARCHIVE_ROOT, mode=0o700, directory=True))
        archive.addfile(
            _tar_info(MANIFEST_NAME, mode=0o600, size=len(manifest_bytes)),
            io.BytesIO(manifest_bytes),
        )
        archive.addfile(
            _tar_info(SIGNATURE_NAME, mode=0o600, size=len(signature_bytes)),
            io.BytesIO(signature_bytes),
        )
        archive.addfile(_tar_info(PAYLOAD_ROOT, mode=0o700, directory=True))
        for entry in manifest["entries"]:
            path = entry["path"]
            candidate = payload.joinpath(*PurePosixPath(path).parts)
            name = f"{PAYLOAD_ROOT}/{path}"
            if entry["kind"] == "directory":
                archive.addfile(_tar_info(name, mode=entry["mode"], directory=True))
            else:
                with candidate.open("rb") as source:
                    archive.addfile(
                        _tar_info(name, mode=entry["mode"], size=entry["size"]),
                        source,
                    )


def build_manifest(
    payload: Path,
    *,
    sqlite_paths: set[str],
    mode_overrides: Mapping[str, int],
    missing_optional_sources: Sequence[str],
    metadata: Mapping[str, object] | None,
    limits: Limits,
) -> dict[str, Any]:
    entries: list[dict[str, object]] = []
    candidates = sorted(
        payload.rglob("*"),
        key=lambda item: item.relative_to(payload).as_posix(),
    )
    for candidate in candidates:
        relative = candidate.relative_to(payload).as_posix()
        if len(f"{PAYLOAD_ROOT}/{relative}") > limits.max_member_name_length:
            raise LimitError(f"archive member name is too long: {relative[:80]}")
        mode = mode_overrides.get(
            relative, candidate.stat(follow_symlinks=False).st_mode & 0o777
        )
        if candidate.is_dir():
            entries.append(
                {
                    "kind": "directory",
                    "mode": mode,
                    "path": relative,
                    "sha256": None,
                    "size": 0,
                }
            )
        elif candidate.is_file():
            entries.append(
                {
                    "kind": "sqlite" if relative in sqlite_paths else "file",
                    "mode": mode,
                    "path": relative,
                    "sha256": sha256_file(candidate),
                    "size": candidate.stat().st_size,
                }
            )
        else:
            raise ArchiveError(f"staged source contains a special file: {relative}")
    if not entries:
        raise ArchiveError("backup must contain at least one file or directory")
    if len(entries) + 4 > limits.max_members:
        raise LimitError("backup exceeds the member limit")
    expanded_bytes = sum(
        candidate.stat().st_size for candidate in candidates if candidate.is_file()
    )
    if expanded_bytes > limits.max_expanded_bytes:
        raise LimitError("backup exceeds the expanded byte limit")
    manifest: dict[str, Any] = {
        "created_at": datetime.now(UTC).isoformat(),
        "entries": entries,
        "format": FORMAT_NAME,
        "format_version": FORMAT_VERSION,
        "metadata": dict(metadata or {}),
        "missing_optional_sources": list(missing_optional_sources),
    }
    manifest_bytes = canonical_json(manifest)
    if len(manifest_bytes) > limits.max_manifest_bytes:
        raise LimitError("manifest exceeds the size limit")
    validate_manifest(manifest_bytes)
    return manifest
