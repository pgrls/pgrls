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
    import pgrls.diff
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
        pgrls.diff,
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
    # Initial pgrls.testing scaffolding — assert the subpackage
    # exists and exposes a stable import surface. Detailed exports
    # are pinned by `test_public_modules_declare_all` once the
    # client/assertions modules land.
    import pgrls.testing  # noqa: F401


def test_pgrls_testing_exports_client_and_protocol_version() -> None:
    import pgrls.testing

    assert "PgrlsTestClient" in pgrls.testing.__all__
    assert "PROTOCOL_VERSION" in pgrls.testing.__all__
    assert pgrls.testing.PROTOCOL_VERSION == 1


def test_pgrls_diff_exports_change_and_diff_schemas() -> None:
    # Pin the v0.2 public surface for the diff machinery. These
    # names are importable from `pgrls.diff` but NOT promoted to
    # the top-level `pgrls` package — promotion to top-level is a
    # v0.3 decision (see README Roadmap).
    import pgrls.diff

    expected = {"Change", "ChangeKind", "Classification", "diff_schemas"}
    assert expected.issubset(set(pgrls.diff.__all__)), (
        f"pgrls.diff.__all__ must include {expected}; got "
        f"{set(pgrls.diff.__all__)}"
    )
    # Each name resolves on the module (the test_public_modules_declare_all
    # generic test also covers this, but pin the four diff names
    # explicitly so a future __all__ refactor surfaces here too).
    for name in expected:
        assert hasattr(pgrls.diff, name), (
            f"pgrls.diff.__all__ lists {name!r} but the attribute "
            "does not exist."
        )
