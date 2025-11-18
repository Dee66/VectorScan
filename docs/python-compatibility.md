# Python Compatibility Guide

VectorScan officially supports CPython 3.9 through 3.12. The CLI now enforces this window during startup so users get a clear error when an unsupported interpreter is detected.

## Running the Test Suite on Multiple Versions

Use the provided `noxfile.py` to exercise the full suite across every supported version:

```bash
nox -s tests-3.9
nox -s tests-3.10
nox -s tests-3.11
nox -s tests-3.12
```

Each session installs `requirements-dev.txt` and executes `pytest`, matching the workflow our CI matrix runs.

## Frequently Asked Questions

- **Why limit to 3.9–3.12?** VectorScan stays dependency-free and aligns with the Python versions shipped on current LTS developer workstations and CI runners. We drop older versions once they fall out of upstream security support and add newer versions after they stabilize.
- **What about PyPy or nightly builds?** They might work, but they are outside of the guarantee. Set `PYTHONWARNINGS=always` and monitor the CLI output if you experiment with alternative interpreters.
- **How do I request support for new versions?** Open an issue describing your environment and any failing tests. Include `nox -s tests-<version>` logs so we can reproduce the problem.
