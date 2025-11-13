# Security Policy

## Reporting a Vulnerability
If you believe you've found a security vulnerability, please email:

- security@nowhere.invalid

Include as much detail as possible:
- Affected files and versions
- Steps to reproduce
- Impact assessment

We will acknowledge receipt within 72 hours and provide an ETA for the fix after triage.

## Scope
This repository is a reference blueprint. It does not guarantee regulatory compliance. See `DISCLAIMER.md`.

## Best Practices
- Never commit secrets
- Use least-privilege AWS roles
- Run OPA/Conftest policy checks in CI for all changes to IaC
