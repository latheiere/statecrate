# Coding Agent Guide

StateCrate is a POSIX-only Python library for signed backup archives containing
application files, directories, and online SQLite snapshots. Keep the public
API small, keep the archive format strict, and preserve recovery safety over
convenience shortcuts.

## Product boundary

- StateCrate owns local snapshot staging, signed archive creation, validation,
  extraction safety, and restoration of one complete destination tree.
- Callers own source discovery, application quiescing beyond SQLite, backup
  schedules, retention, remote storage, and encryption.
- Archives are authenticated but not confidential. Never describe signing as
  encryption.
- Support POSIX behavior only. Do not add conditional Windows behavior without
  a separately reviewed filesystem and durability contract.
- Do not add project-specific path discovery, secret filtering, metadata, or
  operational policy to the shared package.

## Archive invariants

- Every writer emits the documented `statecrate` format and current version.
- Every archive contains exactly one canonical UTF-8 JSON manifest and one
  Ed25519 signature document.
- The signature covers the exact manifest bytes. Verification and restoration
  require an explicitly trusted public key; an embedded key is never trusted.
- The signed manifest names every payload file and directory. Extra, missing,
  duplicate, nested-below-file, or type-mismatched members are rejected.
- Files carry a SHA-256 digest and expanded size. SQLite entries additionally
  pass `PRAGMA quick_check` after the online snapshot and after extraction.
- Reject absolute paths, parent traversal, symbolic links, hard links, special
  files, excessive member counts, long names, large manifests, and expanded
  payloads before installation.
- Preserve only relative paths and permission bits. Never restore ownership,
  setuid/setgid bits, timestamps, ACLs, extended attributes, or archive-provided
  extraction paths.
- New writers may change only with a format-version change. Readers must reject
  unsupported versions rather than guessing.

## Filesystem invariants

- Reject a backup output that overlaps a source.
- Copy SQLite through `sqlite3.Connection.backup`; never copy a live database
  file directly.
- Stage archive candidates privately, flush them, self-verify the exact bytes,
  and only then promote them.
- Keep archive permissions at `0600` and private signing-key permissions at
  `0600`.
- Verify and stage a restore beside its destination so installation stays on
  one filesystem.
- Refuse to replace an existing destination unless the caller explicitly sets
  `replace=True`. Retain the old tree until the new tree is installed and roll
  back when installation raises.
- `fsync` files and directories at durability boundaries. Do not remove these
  calls merely to speed up tests.

## Architecture

- `api.py`: the supported `backup`, `verify`, and `restore` workflows.
- `models.py`: public source, limit, and report values.
- `keys.py`: Ed25519 key serialization, identifiers, signing, and verification.
- `_archive.py`: canonical manifest, archive layout, bounded extraction, and
  content verification.
- `_filesystem.py`: POSIX durability, online SQLite snapshots, copying, and
  link rejection.
- `errors.py`: the stable public exception hierarchy.

Keep helpers private unless callers need them to complete a supported workflow.
Do not expose raw extraction as a public API.

## Changes and tests

- Use Semantic Versioning. Before `1.0.0`, minor versions may change the public
  API; archive compatibility changes still require an explicit format version.
- Add adversarial tests for every archive parser or path-validation change.
- Add round-trip tests for source kinds, optional sources, signing-key rotation,
  replacement, resource limits, and SQLite integrity behavior.
- Tests must not weaken durability behavior globally. Patch the narrow syscall
  only when a failure path specifically requires it.
- Run `make check` before handoff. It executes linting, strict type checking,
  tests with coverage, package builds, and package metadata checks.
- Update the README only for human-facing use. Put wire-format details in
  `docs/ARCHIVE_FORMAT.md` and contributor workflow in `CONTRIBUTING.md`.
- Do not create a remote repository, publish a package, push, or make a release
  unless explicitly authorized.

## General, reusable development descriptions

Describe behavior by its reusable system boundary, triggering conditions, and
outcome. Keep meaningful distinctions such as source kind, archive trust,
filesystem scope, and restore mode. Avoid descriptions centered on one observed
file, database, application, or incident when the behavior covers an equivalent
category.
