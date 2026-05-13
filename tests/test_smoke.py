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
    # Pin the v0.2 public surface for the diff machinery. As of
    # v0.5.9 these four names are also re-exported from the
    # top-level `pgrls` package — see
    # `test_top_level_promotes_diff_api` below for that contract.
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


def test_top_level_promotes_diff_api() -> None:
    # v0.5.9 promoted the four diff symbols (Change, ChangeKind,
    # Classification, diff_schemas) from `pgrls.diff` to the
    # top-level `pgrls` package. The re-exports MUST resolve to the
    # exact same objects — `isinstance(c, pgrls.Change)` must work
    # on a Change instance built via either import path, and
    # callers comparing classes (e.g. for routing tests) must not
    # see two separate identities.
    #
    # Pinning identity (`is`) rather than equality so a future
    # refactor that accidentally re-defines the classes inside
    # `pgrls/__init__.py` (instead of re-exporting) fails this test
    # loudly — defining the class twice would silently break every
    # isinstance check across the public surface.
    import pgrls
    import pgrls.diff

    assert pgrls.diff_schemas is pgrls.diff.diff_schemas
    assert pgrls.Change is pgrls.diff.Change
    assert pgrls.ChangeKind is pgrls.diff.ChangeKind
    # `Classification` is a typing.Literal alias; identity still
    # holds because it's a module-level binding, not a class
    # constructor — `is` is the right check here too.
    assert pgrls.Classification is pgrls.diff.Classification

    # The four names + `__version__` are the entire top-level
    # surface as of v0.5.9. Pinning the full set so a future
    # accidental import leak (e.g. `from pgrls.cli import main`
    # at module top) doesn't silently expand the public surface.
    assert set(pgrls.__all__) == {
        "Change",
        "ChangeKind",
        "Classification",
        "__version__",
        "diff_schemas",
    }
