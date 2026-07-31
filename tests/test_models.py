from pathlib import Path

import pytest

from statecrate import ConfigurationError, Limits, Source


@pytest.mark.parametrize("path", ["/absolute", "../parent", "."])
def test_source_rejects_unsafe_archive_paths(path: str) -> None:
    with pytest.raises(ConfigurationError, match="unsafe archive path"):
        Source.file("source", at=path)


def test_source_rejects_special_permission_bits() -> None:
    with pytest.raises(ConfigurationError, match="source mode"):
        Source.file(Path("source"), mode=0o4755)
    with pytest.raises(ConfigurationError, match="source mode"):
        Source.file(Path("source"), mode=True)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("max_members", 0),
        ("max_expanded_bytes", 0),
        ("max_manifest_bytes", 0),
        ("max_signature_bytes", 0),
        ("max_member_name_length", 0),
        ("min_free_bytes", -1),
        ("max_members", True),
    ],
)
def test_limits_reject_invalid_values(field: str, value: int) -> None:
    with pytest.raises(ConfigurationError):
        Limits(**{field: value})
