# VectorScan Gumroad Delivery Email

**Subject:** Your signed VectorScan bundle + verification steps

Hi there,

Thanks for requesting the free VectorScan Terraform scanner. Every download ships as the signed `vectorscan-free.zip` bundle so you can verify the artifact before running it.

## 1. Download
- Primary (GitHub Releases): https://github.com/Dee66/VectorScan/releases/latest
- Mirror (Gumroad library): your Gumroad receipt includes the same `vectorscan-free.zip`, `.sha256`, `.sig`, and `.crt` files

## 2. Verify before unpacking
Inside the download you will find `vectorscan-free.zip`, `vectorscan-free.zip.sha256`, `vectorscan-free.zip.sig`, and `vectorscan-free.zip.crt`. Run the same commands from `docs/release-distribution.md`:

```bash
sha256sum -c vectorscan-free.zip.sha256
cosign verify-blob \
  --key vectorscan-free.zip.crt \
  --signature vectorscan-free.zip.sig \
  vectorscan-free.zip
```

Only proceed if both commands pass. This ensures the Gumroad mirror matches the GitHub CI release.

## 3. Run VectorScan locally
```bash
python3 tools/vectorscan/vectorscan.py examples/aws-pgvector-rag/tfplan-pass.json
```
Add `--json` or `--email you@example.com --lead-capture` as needed.

## 4. Upgrade path
Need the complete Zero-Trust blueprint? Grab the paid VectorGuard Governance Blueprint here (same UTM tags as the README):
https://gumroad.com/l/vectorguard-blueprint?utm_source=vectorscan&utm_medium=cta&utm_campaign=vectorscan&utm_content=blueprint

Reply to this email or ping support@vectorguard.com if you have any trouble verifying the bundle.

 -  VectorScan Team
