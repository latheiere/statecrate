# StateCrate

StateCrate adds backup and restore to Python applications. It puts selected
files, directories, and consistent snapshots of live SQLite databases into one
signed archive.

Before restoring anything, StateCrate checks the signer, every file, the
archive layout, and each SQLite database. Unsafe paths, links, oversized
archives, unexpected files, and damaged content are rejected.

StateCrate supports POSIX systems and Python 3.11 or newer.

## Install

```bash
python -m pip install statecrate
```

## Use

Create a signing key once and keep it somewhere separate from the backups:

```python
from statecrate import SigningKey

key = SigningKey.generate()
key.save("backup-signing-key.pem")
key.verification_key.save("backup-public-key.pem")
```

Create a backup:

```python
from statecrate import SigningKey, Source, backup

key = SigningKey.load("backup-signing-key.pem")

result = backup(
    "application-backup.tar.gz",
    [
        Source.file("config.json"),
        Source.directory("uploads"),
        Source.sqlite("application.db"),
    ],
    signing_key=key,
)

print(result.archive)
```

Check a backup without restoring it:

```python
from statecrate import VerificationKey, verify

public_key = VerificationKey.load("backup-public-key.pem")
report = verify("application-backup.tar.gz", trusted_keys=public_key)
print(report.entries_checked)
```

Restore into a new directory:

```python
from statecrate import restore

restore(
    "application-backup.tar.gz",
    "restored-state",
    trusted_keys=public_key,
)
```

Pass `replace=True` only when the destination is an application-state directory
that StateCrate may replace completely. Unrelated files in that directory are
not preserved.

## What it handles

- Live SQLite snapshots made through SQLite's backup API
- Ed25519 manifest signatures and trusted-key selection
- SHA-256 checks for every archived file
- SQLite integrity checks before creation and after extraction
- Safe paths, bounded extraction, and link rejection
- Required and optional sources
- File modes, empty directories, and custom JSON metadata
- Staged creation, self-verification, durable writes, and rollback on a failed
  replacement

## Boundaries

Archives are signed, but they are not encrypted. Anyone who can read an archive
can read its contents. Encrypt the archive separately when confidentiality is
required.

StateCrate creates and restores local archive files. Scheduling, retention,
remote storage, incremental backups, and application-specific consistency are
outside its scope.

Replacing an existing destination is rollback-safe when the process reports an
error. POSIX does not provide a portable atomic exchange for non-empty
directories, so a system failure between the two directory renames can require
operator recovery from the hidden staging directory.

See [the archive format](docs/ARCHIVE_FORMAT.md) for the compatibility and
security contract.

## Development

```bash
make install
make check
```

StateCrate is licensed under Apache License 2.0. Contributions are welcome; see
[CONTRIBUTING.md](CONTRIBUTING.md).
