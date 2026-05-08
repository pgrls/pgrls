"""Baseline-restore cache for `pgrls diff --apply migration.sql` (v0.5.2).

When the same baseline schema is diffed against multiple
migrations (or the same migration repeatedly during local
iteration), the bulk of the per-invocation cost is the boot +
role + extension + baseline-DDL setup of the ephemeral Postgres
testcontainer. The migration-apply + introspection that follows
is comparatively cheap.

This module short-circuits steps 1-4 by committing the configured
container into a tagged Docker image after the first successful
baseline restore, then booting subsequent runs directly from
that image.

## Cache key

A SHA-256 of (in order, NUL-separated):

* ``pg_image`` — full image reference, e.g. ``postgres:17-alpine``.
  Tying the cache to the source image means a `pg17` baseline
  cache won't be reused when ``PGRLS_DIFF_APPLY_PG_IMAGE`` flips
  to ``postgres:16-alpine`` for a different test matrix row.
* ``baseline_sql`` — verbatim output of `Schema.to_sql()`.
* sorted role names — pre-created via ``CREATE ROLE … NOLOGIN``.
* sorted extension names — pre-installed via
  ``CREATE EXTENSION IF NOT EXISTS``.

Truncated to 16 hex chars for a manageable image-tag length.
SHA-256's collision resistance at 64 bits is far above what the
expected cache cardinality (probably <100 baselines per dev box)
demands, and a collision means the wrong cache hits — surfaces
quickly as a confusing diff result, not a security risk.

## Cache miss flow

1. Boot fresh Postgres testcontainer.
2. Pre-create roles, pre-install extensions, restore baseline.
3. ``CHECKPOINT;`` — flush dirty buffers so the on-disk state is
   consistent at commit time.
4. ``container.commit(tag)`` — captures the data files in a new
   image layer.
5. Continue with migration-apply + introspect.

## Cache hit flow

1. Boot Postgres testcontainer using the cached image as the base.
2. Skip steps 1-3 entirely; postgres comes up with the baseline
   already applied.
3. Apply migration + introspect.

## Storage

Cached images are tagged ``pgrls-baseline:<HASH>`` and labeled
``org.pgrls.cache=baseline``. Users can prune them with
``docker image prune --filter label=org.pgrls.cache=baseline``.

The cache lives in the local Docker daemon — no shared registry
push, no cross-host sharing. Each developer's box / each CI job
warms its own cache. CI runners without persistent volumes will
miss every time, paying only the modest extra cost of one image
commit per run.

## Disabling the cache

Set ``PGRLS_DIFF_APPLY_NO_CACHE=1`` in the environment to skip
both lookup and commit. Useful when debugging cache-related
issues, or when the caller knows the baseline changes every run
and the commit overhead would be pure waste.

## PGDATA override

The official Postgres image declares
``VOLUME /var/lib/postgresql/data`` — data written there ends
up in an anonymous Docker volume, NOT in the container's
filesystem layer, so ``docker commit`` would capture an empty
data directory. We work around this by setting
``PGDATA=/var/lib/postgresql/pgrls-data`` (a path NOT under the
declared volume), which puts data in the container layer where
``commit`` can see it.
"""
from __future__ import annotations

import hashlib
import logging
import os

logger = logging.getLogger(__name__)

# Path inside the container for PGDATA. Must be OUTSIDE the
# postgres image's `VOLUME /var/lib/postgresql/data` declaration
# so `docker commit` captures the data files.
PGDATA_PATH = "/var/lib/postgresql/pgrls-data"

# Image name + label namespace. Centralized so tests and the
# `docker image prune --filter label=...` UX stay aligned.
CACHE_IMAGE_REPO = "pgrls-baseline"
CACHE_LABEL_KEY = "org.pgrls.cache"
CACHE_LABEL_VALUE = "baseline"

# Env var users set to disable caching entirely.
DISABLE_ENV_VAR = "PGRLS_DIFF_APPLY_NO_CACHE"


def cache_disabled() -> bool:
    """Return True iff ``PGRLS_DIFF_APPLY_NO_CACHE`` is set to a
    truthy value (``1``, ``true``, ``yes``, case-insensitive).
    Any other value (or unset) leaves the cache active.
    """
    raw = os.environ.get(DISABLE_ENV_VAR, "")
    return raw.strip().lower() in {"1", "true", "yes"}


def compute_cache_key(
    *,
    pg_image: str,
    baseline_sql: str,
    roles: tuple[str, ...] | list[str] | set[str],
    extensions: tuple[str, ...] | list[str] | set[str],
) -> str:
    """Compute the cache key for a baseline configuration.

    Returns a 16-char hex string suitable for use as a Docker
    image tag suffix. Identical inputs produce identical keys
    across runs and across dev boxes; any change to baseline DDL,
    role list, extension list, or PG image invalidates the cache.

    Role and extension order is normalized (sorted) so the caller
    doesn't have to.
    """
    h = hashlib.sha256()
    h.update(pg_image.encode("utf-8"))
    h.update(b"\0")
    h.update(baseline_sql.encode("utf-8"))
    h.update(b"\0")
    for role in sorted(roles):
        h.update(role.encode("utf-8"))
        h.update(b"\0")
    h.update(b"::")  # separator between role and extension lists
    for ext in sorted(extensions):
        h.update(ext.encode("utf-8"))
        h.update(b"\0")
    return h.hexdigest()[:16]


def cached_image_tag(key: str) -> str:
    """Return the full ``repo:tag`` form of a cache key —
    ``pgrls-baseline:<KEY>``."""
    return f"{CACHE_IMAGE_REPO}:{key}"


def image_exists(tag: str) -> bool:
    """Return True iff a Docker image with ``tag`` is available
    in the local daemon. Returns False on any docker-side error
    (daemon down, network issue, etc.) so the caller falls back
    cleanly to the cache-miss path rather than crashing.
    """
    try:
        import docker
        from docker.errors import APIError, ImageNotFound
    except ImportError:
        # docker SDK not installed — `pgrls[diff-apply]` extra
        # ensures it's present, but if for any reason it isn't,
        # treat as cache miss rather than crash.
        return False

    try:
        client = docker.from_env()
        client.images.get(tag)
        return True
    except ImageNotFound:
        return False
    except APIError as exc:
        # Docker daemon is reachable but rejected the request —
        # log and treat as miss. Don't surface to user; they'll
        # see a working uncached run.
        logger.debug("docker images.get(%r) APIError: %s", tag, exc)
        return False
    except Exception as exc:  # noqa: BLE001
        # Catch-all (e.g. docker daemon unreachable). Cache is a
        # best-effort optimization — never fail the diff command
        # because we couldn't talk to docker about the cache.
        logger.debug("docker images.get(%r) unexpected error: %s", tag, exc)
        return False


def commit_baseline(*, container_id: str, tag: str) -> None:
    """Commit a running container into a tagged image.

    The caller must have already issued ``CHECKPOINT;`` to the
    Postgres instance so that the data files on disk are
    consistent at the moment of commit; without it, the image
    captured here may have torn writes that confuse the cached
    Postgres on next boot.

    Errors are logged at DEBUG and swallowed — committing is
    best-effort. A commit failure on run N just means run N+1
    pays the full setup cost again, not that anything is broken.
    """
    try:
        import docker
    except ImportError:
        return

    repo, _, tag_part = tag.partition(":")
    try:
        client = docker.from_env()
        container = client.containers.get(container_id)
        container.commit(
            repository=repo,
            tag=tag_part,
            # Label so `docker image prune --filter label=…`
            # finds these without false-positives on user images.
            conf={"Labels": {CACHE_LABEL_KEY: CACHE_LABEL_VALUE}},
        )
        logger.debug("Committed baseline cache: %s", tag)
    except Exception as exc:  # noqa: BLE001
        logger.debug("docker commit %r failed: %s", tag, exc)
