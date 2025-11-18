"""Nox sessions for exercising VectorScan across supported Python versions."""

from __future__ import annotations

import nox

PYTHON_VERSIONS = ("3.9", "3.10", "3.11", "3.12")


@nox.session(python=PYTHON_VERSIONS)
def tests(session: nox.Session) -> None:
    """Run the full pytest suite under each supported interpreter."""

    session.install("-r", "requirements-dev.txt")
    session.run("pytest")


@nox.session
def lint(session: nox.Session) -> None:
    """Run style and type checks with the active interpreter."""

    session.install("-r", "requirements-dev.txt")
    session.run("ruff", "check", ".")
    session.run("black", "--check", ".")
    session.run("isort", "--check-only", "--diff", ".")
    session.run("mypy", "tools/vectorscan")
