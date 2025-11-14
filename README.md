[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](#)
[![Python: 3.9+](https://img.shields.io/badge/Python-3.9%2B-blue.svg)](#)
[![Status: Stable MVP](https://img.shields.io/badge/Status-Stable%20MVP-yellowgreen.svg)](#)

# VectorScan

**A lightweight, MIT-licensed policy-as-code scanner for Terraform plans.**  
VectorScan enforces a minimal set of high-impact governance checks that catch the most common misconfigurations in AI, data, and cloud-native stacks.

**Philosophy:**  
> **Governance must be codified, not documented.**

---

## Why this tool exists

Terraform plans often conceal subtle but high-risk issues — especially in data-heavy or RAG/vector workloads. Across cloud teams, two failures repeatedly cause the majority of governance drift:

- **Data services deployed without encryption or KMS keys.**  
- **Missing cost and ownership tags that destabilize FinOps.**

VectorScan helps you catch these issues *before deployment* with a tiny, auditable policy bundle.

---

## Features (benefits first)

- **P-SEC-001 / Encryption Mandate — *Prevent Data Exfiltration.***  
  Validates that data services enforce encryption with a defined KMS key so sensitive workloads remain protected.

- **P-FIN-001 / Mandatory Tagging — *Stop Uncontrolled Spend.***  
  Validates that essential FinOps tags like `CostCenter` and `Project` are present and non-empty.

- **Single-file CLI with zero dependency on your local Terraform installation.**  
  VectorScan evaluates any `tfplan.json` input without requiring Terraform to be installed on the runner.

- **Optional bundled Terraform binary** (for advanced module-level tests).

- **CI-friendly YAML ledger** for compliance evidence and audit trails.

- **MIT license** — safe for open source, startups, and enterprises.

---

## Quick start (60 seconds)

```bash
git clone https://github.com/Dee66/VectorScan.git
cd VectorScan

python vectorscan.py ../../examples/aws-pgvector-rag/tfplan-pass.json
