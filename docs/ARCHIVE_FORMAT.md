# StateCrate archive format

This document defines the compatibility and trust boundary for
`format_version` 1.

## Layout

A StateCrate archive is a gzip-compressed POSIX tar archive:

```text
statecrate/
  manifest.json
  manifest.sig
  payload/
    ...
```

Only regular files and directories are permitted. Every payload member is
listed exactly once in the manifest; the archive cannot contain unlisted
payload members.

## Manifest

`manifest.json` is canonical UTF-8 JSON with sorted object keys, compact
separators, and one trailing newline. It contains:

- `format`: `"statecrate"`
- `format_version`: `1`
- `created_at`: a timezone-aware ISO 8601 timestamp
- `entries`: payload files and directories
- `missing_optional_sources`: requested relative source paths that were absent
- `metadata`: caller-owned JSON metadata

Each entry contains a relative POSIX `path`, `kind`, permission `mode`, expanded
`size`, and `sha256`. Directory entries have size zero and a null checksum.
Kinds are `file`, `directory`, and `sqlite`.

Paths cannot be absolute, contain `..`, overlap files with descendants, or
repeat another entry. Permission modes are limited to `0000` through `0777`.

## Signature and trust

`manifest.sig` is canonical JSON containing the Ed25519 algorithm name, the
signer's public-key identifier, and a base64 signature over the exact
`manifest.json` bytes. The key identifier is `sha256:` followed by the SHA-256
digest of the raw Ed25519 public key.

The archive does not contain a trusted public key. A caller must provide one or
more trusted keys to verification and restoration. This permits signing-key
rotation without trusting data supplied by the archive itself.

The signature authenticates the manifest, and manifest hashes authenticate the
payload. It does not encrypt the payload.

## Verification

A conforming reader performs these checks before installation:

1. Bound member count, names, manifest size, signature size, and expanded size.
2. Reject links, special members, unsafe paths, and duplicate members.
3. Verify the manifest signature with an explicitly trusted key.
4. Validate the complete manifest schema and version.
5. Require an exact match between manifest entries and payload members.
6. Check every file's expanded size and SHA-256 digest while extracting.
7. Run SQLite `PRAGMA quick_check` on every SQLite entry.

Resource limits are caller-configurable, with conservative defaults. A reader
must not treat a higher format version as compatible unless support for that
version is implemented explicitly.

## Restored state

Restoration recreates the payload beneath one caller-selected destination.
StateCrate restores relative paths and ordinary permission bits. It does not
restore ownership, special permission bits, timestamps, links, ACLs, or
extended attributes.
