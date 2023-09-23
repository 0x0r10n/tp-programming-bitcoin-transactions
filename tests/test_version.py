from btctoy import (
    __version__,
)


def test_version_string_not_empty() -> None:
    assert __version__ != ""
