"""HYG002 — Policy named like a placeholder.

A policy named `todo`, `fixme`, `tmp`, `hack`, `xxx`, `debug`, or
`placeholder` is almost always a forgotten scaffold from an
unfinished migration. The migration introduced an RLS policy as a
"figure this out later" stub and never came back to harden it.

Detection is a case-insensitive identifier-token match against
the policy name (handles `snake_case`, `camelCase`, and
`SCREAMING_SNAKE`). Default vocabulary: `todo`, `fixme`, `tmp`,
`hack`, `xxx`, `debug`, `placeholder`. Override with
`[lint.rules.HYG002].placeholder_words = [...]` — the override
REPLACES the default list (consistent with SEC004 / PERF001's
`auth_functions` shape). Allowlist exact policy IDs that
legitimately use the words.

Default vocabulary deliberately excludes `temp`, `draft`, and
`wip` — all are real domain words. `temp` collides with
"temperature" in IoT / sensor schemas; `draft` is a CMS publish
state; `wip` is an inventory accounting term ("work in process").
Users who want the broader scaffolding-detection set can opt back
in via `placeholder_words`.

Severity: warning.
"""
from __future__ import annotations

import re
from typing import Any

from pgrls.model import Schema
from pgrls.violations import Severity, Violation

_DEFAULT_PLACEHOLDER_WORDS: tuple[str, ...] = (
    "todo",
    "fixme",
    "tmp",
    "hack",
    "xxx",
    "debug",
    "placeholder",
)


def _parse_allowlist(options: dict[str, Any]) -> set[str]:
    raw = options.get("allowlist", [])
    if not isinstance(raw, list) or not all(isinstance(s, str) for s in raw):
        raise TypeError(
            "[lint.rules.HYG002].allowlist must be a list of policy IDs "
            "of the form 'schema.table.policy_name'"
        )
    return set(raw)


def _parse_placeholder_words(options: dict[str, Any]) -> tuple[str, ...]:
    raw = options.get("placeholder_words")
    if raw is None:
        return _DEFAULT_PLACEHOLDER_WORDS
    if not isinstance(raw, list) or not all(isinstance(s, str) for s in raw):
        raise TypeError(
            "[lint.rules.HYG002].placeholder_words must be a list of "
            "strings (the override REPLACES the default list)"
        )
    return tuple(s.lower() for s in raw)


_TOKEN_RE = re.compile(r"[A-Z]?[a-z]+|[A-Z]+(?=[A-Z_]|\d|$)|\d+")


def _tokenize_identifier(name: str) -> list[str]:
    """Split an identifier into lower-cased words.

    Handles snake_case (`todo_owner` → `todo`, `owner`), camelCase
    (`TmpReadAll` → `tmp`, `read`, `all`), and SCREAMING_SNAKE
    (`TODO_OWNER` → `todo`, `owner`). Used by HYG002 to spot
    placeholder words inside any of those styles.
    """
    return [m.group(0).lower() for m in _TOKEN_RE.finditer(name)]


def _name_contains_placeholder(
    name: str, words: tuple[str, ...]
) -> bool:
    if not words:
        return False
    word_set = {w.lower() for w in words}
    return any(tok in word_set for tok in _tokenize_identifier(name))


class HYG002:
    id: str = "HYG002"
    severity: Severity = "warning"
    title: str = "Policy named like a placeholder"

    def check(
        self, schema: Schema, options: dict[str, Any]
    ) -> list[Violation]:
        allowlist = _parse_allowlist(options)
        words = _parse_placeholder_words(options)

        out: list[Violation] = []
        for table in schema.tables:
            for policy in table.policies:
                if not _name_contains_placeholder(policy.name, words):
                    continue
                policy_id = (
                    f"{table.schema}.{table.name}.{policy.name}"
                )
                if policy_id in allowlist:
                    continue
                out.append(
                    Violation(
                        rule_id="HYG002",
                        severity="warning",
                        title=self.title,
                        message=(
                            f"Policy {policy.name!r} on "
                            f"{table.qualified_name} has a name that "
                            "looks like a forgotten placeholder "
                            "(`todo`, `fixme`, `wip`, etc.). Common "
                            "shape of an unfinished migration. Rename "
                            "to a descriptive policy name or, if the "
                            "policy is truly final, allowlist it "
                            "explicitly."
                        ),
                        location=policy_id,
                    )
                )
        return out
