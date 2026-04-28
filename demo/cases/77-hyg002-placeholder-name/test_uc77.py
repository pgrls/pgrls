"""Use case 77: HYG002 — placeholder-named policy."""
from __future__ import annotations


def test_uc77_hyg002_fires_on_todo_named_policy(
    lint_output: str,
) -> None:
    # The policy is named `todo_replace_me_later`. The identifier
    # tokenizer sees `todo` as the first segment and matches it
    # against the default placeholder vocabulary.
    assert (
        "HYG002  app.placeholder_named.todo_replace_me_later\n"
        in lint_output
    )
