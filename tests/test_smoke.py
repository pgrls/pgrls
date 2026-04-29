import pgrls


def test_version_string_is_set():
    assert isinstance(pgrls.__version__, str)
    assert len(pgrls.__version__.split(".")) == 3


def test_public_modules_declare_all() -> None:
    # Pre-1.0 stability: the public surface is the union of every
    # `__all__` set. Modules whose names appear in `pgrls.__init__`'s
    # docstring as importable destinations must declare `__all__`
    # so static linters and IDE autocomplete have an explicit list
    # of public names.
    import pgrls
    import pgrls.fixers
    import pgrls.model
    import pgrls.rules
    import pgrls.testing
    import pgrls.violations

    for module in (
        pgrls,
        pgrls.violations,
        pgrls.model,
        pgrls.fixers,
        pgrls.rules,
        pgrls.testing,
    ):
        assert hasattr(module, "__all__"), (
            f"{module.__name__} must declare __all__ to commit to "
            "its public surface."
        )
        assert isinstance(module.__all__, list)
        assert all(isinstance(name, str) for name in module.__all__)
        # Every name in __all__ must actually exist on the module.
        for name in module.__all__:
            assert hasattr(module, name), (
                f"{module.__name__}.__all__ lists {name!r} but the "
                "attribute does not exist."
            )


def test_pgrls_testing_subpackage_importable() -> None:
    # Round 0 of pgrls test scaffolding — assert the subpackage
    # exists and exposes a stable import surface. Detailed exports
    # are pinned by `test_public_modules_declare_all` once the
    # client/assertions modules land.
    import pgrls.testing  # noqa: F401


def test_pgrls_testing_exports_client_and_protocol_version() -> None:
    import pgrls.testing

    assert "PgrlsTestClient" in pgrls.testing.__all__
    assert "PROTOCOL_VERSION" in pgrls.testing.__all__
    assert pgrls.testing.PROTOCOL_VERSION == 1
