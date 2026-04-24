import pgrls


def test_version_string_is_set():
    assert isinstance(pgrls.__version__, str)
    assert len(pgrls.__version__.split(".")) == 3
