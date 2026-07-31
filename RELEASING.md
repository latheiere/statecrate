# Releasing

StateCrate uses Semantic Versioning for its Python API and an independent
integer version for its archive format.

Before a release:

1. Update `project.version` in `pyproject.toml`.
2. Move the relevant changelog entries from `Unreleased` to the release date.
3. Run `make check` from a clean checkout.
4. Commit the version and changelog together.
5. Create an annotated `vX.Y.Z` tag on that commit and push it.
6. Publish a GitHub release from the immutable tag.

The release workflow builds the source distribution and wheel, checks their
metadata, and publishes through PyPI Trusted Publishing. Configure the GitHub
`pypi` environment and the matching PyPI trusted publisher before the first
release. Do not store a long-lived PyPI token in repository secrets.

Changing the archive layout, signature contract, manifest interpretation, or
restored meaning of existing fields requires a new archive format version.
Readers must continue to reject unsupported versions explicitly.
