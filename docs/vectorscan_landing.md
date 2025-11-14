# VectorScan – Instant Terraform Plan Guardrail Scan

<div align="center">
  <img src="./images/vectorscan_hero_placeholder.png" alt="VectorScan Hero" width="820" height="200" />
  <p><em>Catch the two highest-impact config gaps in seconds, before they hit production.</em></p>
</div>

Identify two high-impact gaps in under 3 seconds:

| Check | Why It Matters | Failure Impact |
|-------|----------------|----------------|
| Encryption Mandate (P-SEC-001) | Ensures data-at-rest encryption for regulated data | Breach blast radius, compliance fines |
| Mandatory Tagging (P-FIN-001) | Enables cost attribution & anomaly detection | Unallocated spend, budgeting blind spots |

## Try It Locally
```bash
python3 tools/vectorscan/vectorscan.py examples/aws-pgvector-rag/tfplan-pass.json
python3 tools/vectorscan/vectorscan.py examples/aws-pgvector-rag/tfplan-fail.json --json
```

Tip: add <code>--email you@example.com --lead-capture</code> to generate a local JSON capture (no network). To send it to an endpoint, set <code>VSCAN_LEAD_ENDPOINT</code>.

## Upgrade Path
| Tier | What You Get | Primary Outcome |
|------|--------------|-----------------|
| Free (VectorScan) | 2 Critical Checks | Quick risk signal |
| $79 Blueprint | 6 Zero-Trust + FinOps Policies, Audit Templates | Shift-left governance |
| $449 Enterprise | Extended policies, evidence packs, support | Faster audits & onboarding |

> The paid tiers inherit 469 Rego policy tests (OPA) plus Python/Terratest automation, so every upgrade builds on proven enforcement.

Upgrade with UTM-tracked links:

- Free → Download: [Download Signed Bundle](https://github.com/Dee66/VectorScan/releases/latest?utm_source=vectorscan&utm_medium=cta&utm_campaign=vectorscan&utm_content=download)
- Free → Blueprint: [Get the Blueprint](https://gumroad.com/l/vectorguard-blueprint?utm_source=vectorscan&utm_medium=cta&utm_campaign=vectorscan&utm_content=blueprint)
- Free → Enterprise: [Talk to us](https://github.com/Dee66/VectorScan#distribution--gumroad?utm_source=vectorscan&utm_medium=cta&utm_campaign=vectorscan&utm_content=enterprise)

## Download & Verify
- Download `vectorscan-free.zip` from `https://github.com/Dee66/VectorScan/releases/latest` or the VectorScan Gumroad listing so you can confirm the CI-signed artifact is installed.
- Each release ships with `<bundle>.zip.sha256`, `<bundle>.zip.sig`, and `<bundle>.zip.crt`; use `docs/release-distribution.md` to run `sha256sum -c` and `cosign verify-blob` before deploying.
- Reference the release tag/URL in your audit ledger so reviewers can trace the signed bundle back to the repository and the verification evidence.

## Lead Capture (Optional)
Provide an email to generate a local capture JSON (no network unless you set an endpoint):
```bash
VSCAN_LEAD_ENDPOINT="https://api.example.com/lead" \
python3 tools/vectorscan/vectorscan.py examples/aws-pgvector-rag/tfplan-fail.json \
  --email you@example.com --lead-capture
```

## Sample Output
```bash
FAIL - tfplan.json - VectorScan checks
   P-SEC-001: aws_rds_cluster 'vector_db' has storage_encrypted != true
   P-FIN-001: aws_rds_cluster 'vector_db' missing/empty tag 'CostCenter'
```

<div align="center">
  <img src="./images/sample_output_placeholder.png" alt="Sample Output" width="820" height="200" />
</div>

## Why Only Two Checks in Free?
They represent the most common AND high-leverage early failures (security + cost). The Blueprint layers network isolation, IAM drift prevention, scaling caps, immutable logging, and more.

## Next Steps
1. Run VectorScan
2. Patch failures (add encryption + tags)
3. Integrate the full policy gate for deeper coverage
4. Generate audit evidence automatically

**Ready for full Zero-Trust coverage?** → See the main README for the Blueprint.

---

Footer CTA:
- [Download VectorScan (Free)](https://github.com/Dee66/VectorScan/releases/latest?utm_source=vectorscan&utm_medium=footer&utm_campaign=vectorscan&utm_content=download)
- [Blueprint ($79/year)](https://gumroad.com/l/vectorguard-blueprint?utm_source=vectorscan&utm_medium=footer&utm_campaign=vectorscan&utm_content=blueprint)
- [Enterprise ($449/year)](https://github.com/Dee66/VectorScan#distribution--gumroad?utm_source=vectorscan&utm_medium=footer&utm_campaign=vectorscan&utm_content=enterprise)
