"""Top-level source package marker for test and packaging compatibility.

This file makes the `src` directory a regular package so imports like
`import src.pillar` succeed in environments where the repository root is on
`sys.path`.

Note: This is a lightweight marker and intentionally contains no runtime
side-effects.
"""
