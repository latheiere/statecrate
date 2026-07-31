# Contributing

Thank you for helping improve StateCrate.

Before opening a change, search the existing issues and describe the reusable
backup or restore behavior being changed. Security-sensitive reports belong in
the private process described in [SECURITY.md](SECURITY.md).

Set up a development environment:

```bash
python3.11 -m venv .venv
.venv/bin/python -m pip install --upgrade pip
.venv/bin/python -m pip install -e '.[dev]'
```

Run all local checks:

```bash
make check
```

Changes to parsing, paths, signing, limits, or restoration need adversarial
tests as well as a normal round trip. Changes to the archive contract must
update `docs/ARCHIVE_FORMAT.md` and use a new format version when an existing
reader cannot interpret the result safely.

By submitting a contribution, you agree that it is licensed under Apache
License 2.0.
