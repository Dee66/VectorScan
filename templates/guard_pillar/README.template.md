# GuardSuite Pillar Template

This template bootstraps a GuardSuite pillar implementation.

## Structure

```
src/pillar/
  cli.py
  constants.py
  schema.py
  renderer.py
  canonical_utils.py
  engine/
    loader.py
    evaluator.py
    remediation.py
    engines/
  adapters/
  preview/
  telemetry/
  upgrade/
  policies/
  utils/
fixpack/
tests/
  shared/
  unit/
  integration/
  snapshots/
```

## Usage

1. Copy this template into `src/<pillar_name>/`.
2. Replace `pillar` imports with the new package name.
3. Update `PILLAR_NAME_REPLACE_ME` markers.
4. Implement pillar-specific logic inside the engine and adapters.
5. Run `poetry install && pytest` to verify the scaffold.
