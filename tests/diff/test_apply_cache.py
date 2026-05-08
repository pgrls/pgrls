"""Unit tests for `pgrls.diff._apply_cache` — the v0.5.2 baseline
restore cache for ``pgrls diff --apply migration.sql``.

These tests exercise the pure-function surface: cache key
computation, image-tag formatting, and the disable-env-var
predicate. The Docker-touching paths (`image_exists`,
`commit_baseline`) are exercised end-to-end by the integration
tests in `test_cli_apply.py` rather than re-mocked here.
"""
from __future__ import annotations

import os
from unittest.mock import patch

from pgrls.diff import _apply_cache


# ---------------------------------------------------------------------------
# compute_cache_key
# ---------------------------------------------------------------------------


def test_cache_key_is_deterministic_across_calls():
    """Same inputs → same key, every time. The cache is content-
    addressed; non-determinism would mean every run misses."""
    args = dict(
        pg_image="postgres:17-alpine",
        baseline_sql="CREATE TABLE t (id INT);\n",
        roles=["app_user", "tenant_admin"],
        extensions=["citext"],
    )
    k1 = _apply_cache.compute_cache_key(**args)
    k2 = _apply_cache.compute_cache_key(**args)
    assert k1 == k2
    assert isinstance(k1, str)
    assert len(k1) == 16
    assert all(c in "0123456789abcdef" for c in k1)


def test_cache_key_normalizes_role_order():
    """Role list order shouldn't affect the key — the underlying
    `CREATE ROLE … NOLOGIN` loop sorts roles, so two callers
    passing ['a', 'b'] vs ['b', 'a'] produce identical setup
    and should hit the same cache entry."""
    base = dict(
        pg_image="postgres:17-alpine",
        baseline_sql="-- baseline\n",
        extensions=[],
    )
    k1 = _apply_cache.compute_cache_key(roles=["a", "b"], **base)
    k2 = _apply_cache.compute_cache_key(roles=["b", "a"], **base)
    k3 = _apply_cache.compute_cache_key(roles={"a", "b"}, **base)
    k4 = _apply_cache.compute_cache_key(roles=("b", "a"), **base)
    assert k1 == k2 == k3 == k4


def test_cache_key_normalizes_extension_order():
    """Same as roles — extensions are sorted before pre-install,
    so input order shouldn't change the key."""
    base = dict(
        pg_image="postgres:17-alpine",
        baseline_sql="-- baseline\n",
        roles=[],
    )
    k1 = _apply_cache.compute_cache_key(
        extensions=["citext", "pgcrypto"], **base
    )
    k2 = _apply_cache.compute_cache_key(
        extensions=["pgcrypto", "citext"], **base
    )
    assert k1 == k2


def test_cache_key_changes_with_pg_image():
    """A pg17 baseline shouldn't be reused when the user flips
    PGRLS_DIFF_APPLY_PG_IMAGE to pg16 (different binaries, the
    cached data files might not be readable)."""
    base = dict(
        baseline_sql="CREATE TABLE t (id INT);\n",
        roles=[],
        extensions=[],
    )
    k15 = _apply_cache.compute_cache_key(pg_image="postgres:15-alpine", **base)
    k16 = _apply_cache.compute_cache_key(pg_image="postgres:16-alpine", **base)
    k17 = _apply_cache.compute_cache_key(pg_image="postgres:17-alpine", **base)
    assert len({k15, k16, k17}) == 3


def test_cache_key_changes_with_baseline_sql():
    """Different baseline DDL → different cache entry. The whole
    point of the cache is to map (inputs) → restored state."""
    base = dict(
        pg_image="postgres:17-alpine",
        roles=[],
        extensions=[],
    )
    k1 = _apply_cache.compute_cache_key(
        baseline_sql="CREATE TABLE a (id INT);\n", **base
    )
    k2 = _apply_cache.compute_cache_key(
        baseline_sql="CREATE TABLE b (id INT);\n", **base
    )
    assert k1 != k2


def test_cache_key_changes_with_roles():
    """Adding a role changes the pre-create step, which changes
    the cached state. Ergo — the cache key."""
    base = dict(
        pg_image="postgres:17-alpine",
        baseline_sql="-- empty\n",
        extensions=[],
    )
    k1 = _apply_cache.compute_cache_key(roles=[], **base)
    k2 = _apply_cache.compute_cache_key(roles=["app_user"], **base)
    k3 = _apply_cache.compute_cache_key(
        roles=["app_user", "tenant_admin"], **base
    )
    assert len({k1, k2, k3}) == 3


def test_cache_key_changes_with_extensions():
    """Pre-installed extensions are part of the baseline state."""
    base = dict(
        pg_image="postgres:17-alpine",
        baseline_sql="-- empty\n",
        roles=[],
    )
    k0 = _apply_cache.compute_cache_key(extensions=[], **base)
    k1 = _apply_cache.compute_cache_key(extensions=["citext"], **base)
    k2 = _apply_cache.compute_cache_key(extensions=["pgcrypto"], **base)
    assert len({k0, k1, k2}) == 3


def test_cache_key_separator_prevents_role_extension_collision():
    """Pin the explicit `::` separator between role and extension
    lists. Without it, ``roles=['cite', 'xt'], extensions=[]`` and
    ``roles=[], extensions=['citext']`` would hash identically
    (both → "citextxt" then "" or vice-versa). The separator is
    cheap insurance against this class of collision."""
    base = dict(
        pg_image="postgres:17-alpine",
        baseline_sql="-- empty\n",
    )
    # Construct two configurations that, without the role/ext
    # separator, would hash to the same byte stream. Concretely:
    # if encoding were just "join(roles) + join(exts)" with a
    # uniform NUL separator, ['x'] + [] and [] + ['x'] would
    # produce the same hash. The "::" between sections breaks
    # that collision.
    k1 = _apply_cache.compute_cache_key(
        roles=["x"], extensions=[], **base
    )
    k2 = _apply_cache.compute_cache_key(
        roles=[], extensions=["x"], **base
    )
    assert k1 != k2


# ---------------------------------------------------------------------------
# cached_image_tag
# ---------------------------------------------------------------------------


def test_cached_image_tag_matches_repo_naming_convention():
    """Image tag must be a valid Docker reference. ``pgrls-baseline:``
    + 16 hex chars satisfies repo:tag and stays under the 128-char
    image-name limit."""
    tag = _apply_cache.cached_image_tag("abcdef0123456789")
    assert tag == "pgrls-baseline:abcdef0123456789"


# ---------------------------------------------------------------------------
# cache_disabled
# ---------------------------------------------------------------------------


def test_cache_disabled_default_false():
    """Default state: caching is on. Verify the env var really
    is the only way to turn it off — no implicit gate."""
    with patch.dict(os.environ, {}, clear=False):
        os.environ.pop(_apply_cache.DISABLE_ENV_VAR, None)
        assert _apply_cache.cache_disabled() is False


def test_cache_disabled_recognizes_truthy_values():
    """Accept the standard set so users don't need to remember
    which one. Case-insensitive — common typo-zone."""
    for raw in ("1", "true", "TRUE", "True", "yes", "YES", "Yes"):
        with patch.dict(os.environ, {_apply_cache.DISABLE_ENV_VAR: raw}):
            assert _apply_cache.cache_disabled() is True, raw


def test_cache_disabled_treats_other_values_as_enabled():
    """Anything else — empty, "0", "false", typos — leaves the
    cache active. Avoids accidental disable from leftover env
    vars or shell quirks."""
    for raw in ("", "0", "false", "no", "off", "disabled"):
        with patch.dict(os.environ, {_apply_cache.DISABLE_ENV_VAR: raw}):
            assert _apply_cache.cache_disabled() is False, raw


# ---------------------------------------------------------------------------
# image_exists — daemon-failure paths
# ---------------------------------------------------------------------------


def test_image_exists_returns_false_when_docker_sdk_missing(monkeypatch):
    """If `docker` SDK isn't importable for any reason, treat as
    miss rather than crash. The diff command should still work
    (just slower — every run pays full setup cost)."""
    import builtins

    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "docker" or name.startswith("docker."):
            raise ImportError("docker not available in this test")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    assert _apply_cache.image_exists("pgrls-baseline:abcdef0123456789") is False


def test_image_exists_returns_false_on_docker_error(monkeypatch):
    """Docker daemon errors are best-effort cache-miss signals,
    not failure conditions for the diff command itself."""
    import docker
    from docker.errors import APIError

    class StubClient:
        class images:  # noqa: N801
            @staticmethod
            def get(_tag):
                raise APIError("daemon unhappy")

    def fake_from_env():
        return StubClient()

    monkeypatch.setattr(docker, "from_env", fake_from_env)
    assert _apply_cache.image_exists("pgrls-baseline:abcdef0123456789") is False


def test_image_exists_returns_false_on_image_not_found(monkeypatch):
    """The expected miss path: docker is healthy, image just
    isn't in the local cache yet."""
    import docker
    from docker.errors import ImageNotFound

    class StubClient:
        class images:  # noqa: N801
            @staticmethod
            def get(_tag):
                raise ImageNotFound("no such image")

    def fake_from_env():
        return StubClient()

    monkeypatch.setattr(docker, "from_env", fake_from_env)
    assert _apply_cache.image_exists("pgrls-baseline:nonexistent000000") is False


def test_image_exists_returns_true_when_present(monkeypatch):
    """The expected hit path: docker returns the image object
    successfully — we don't need to inspect it, just confirm
    presence."""
    import docker

    class StubClient:
        class images:  # noqa: N801
            @staticmethod
            def get(_tag):
                # Docker SDK returns an Image object on success;
                # truthy is enough — we don't access fields.
                return object()

    def fake_from_env():
        return StubClient()

    monkeypatch.setattr(docker, "from_env", fake_from_env)
    assert _apply_cache.image_exists("pgrls-baseline:0000000000000000") is True
