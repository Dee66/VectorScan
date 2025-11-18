# VectorScan Signing & Key Rotation Runbook

VectorScan authenticates every distribution bundle with [Sigstore Cosign](https://github.com/sigstore/cosign). This runbook explains how we:

- Create and store signing keys
- Rotate keys without breaking consumers who pin the previous key
- Verify overlap between retiring and new keys
- Communicate key changes to downstream users

The process is intentionally tooling-light so it works from any developer laptop or CI runner.

## Key Inventory & Storage

| State      | Location / Owner                                   | Notes |
|------------|----------------------------------------------------|-------|
| **Active** | CI secret store (`COSIGN_PRIVATE_KEY`, `COSIGN_PASSWORD`) | Used by `scripts/create_release_bundle.py` & release workflows. Matches the public key published in `README` and Gumroad emails. |
| **Staging**| Hardware-backed or KMS-backed key pair awaiting promotion | Generate with `cosign generate-key-pair` or KMS (preferred) at least one release ahead of promotion. |
| **Retired**| Archived public keys stored in `keys/archive/<YEAR>-<QTR>-cosign.pub` (not committed) | Keep all previous public keys so customers can continue verifying historical releases. |

Never commit private keys to the repository. Only the public key fingerprint and rotation log belong in Git.

## Rotation Cadence

- Rotate at least once per quarter or immediately if compromise is suspected.
- Overlap the old and new keys for a single release to avoid breaking automation: publish two signatures for the same bundle so either key succeeds.
- Update `README`, Gumroad email template, and any downstream integration docs with the hash of the newly promoted public key.

## Rotation Procedure

1. **Generate the next key pair**
   ```bash
   cosign generate-key-pair \
     --output-key-pair /secure/location/vectorscan-2025q1
   ```
   For cloud-backed workflows prefer `cosign generate-key-pair --kms <arn>` so the private material never leaves KMS/HSM.

2. **Stage the new key in CI**
   - Add the private key + password (or KMS reference) to the release workflow secrets.
   - Publish the public key under `keys/active/vectorscan.pub` in the secrets repo (not this repo) and queue the README/email updates.

3. **Sign the release with both keys**
   - Produce the bundle via `scripts/create_release_bundle.py`.
   - Sign with the active key first (status quo) and store the signature as `dist/vectorscan-free.zip.sig.old`.
   - Sign again with the staged key and store the signature as `dist/vectorscan-free.zip.sig` (this becomes the default once rotation is complete).

4. **Verify overlap with the automation helper**
   ```bash
   python3 scripts/signing_key_rotation.py \
     --bundle dist/vectorscan-free.zip \
     --bundle-version 1.5.0 \
     --old-key /secure/archive/2024q4_cosign.pub \
     --old-signature dist/vectorscan-free.zip.sig.old \
     --new-key /secure/staging/2025q1_cosign.pub \
     --new-signature dist/vectorscan-free.zip.sig \
     --rotation-log docs/signing_key_rotation_log.json \
     --note "2025Q1 rotation"
   ```
   The script requires `cosign` on `PATH`. It verifies both signatures and appends a structured entry to `docs/signing_key_rotation_log.json` so we have an auditable history (bundle hash, fingerprints, timestamp, operator note).

5. **Publish artifacts**
   - Upload the bundle, both signatures, and updated public key to GitHub Releases and Gumroad.
   - Update `scripts/verify.sh` instructions in README/Gumroad email to point to the new public key while keeping the old instructions in the "Historical keys" section.

6. **Communicate the rotation**
   - Announce in the changelog/README with the new key fingerprint.
   - Email Gumroad customers using the template in the next section.
   - Update any downstream automation (e.g., weekly verification workflow) with the new key path.

7. **Decommission the old key** (one release after promotion)
   - Remove the old private key from CI secrets.
   - Move the corresponding public key into the archive location.
   - Ensure `docs/signing_key_rotation_log.json` reflects the retirement date.

## Emergency Response & Revocation

If a key is believed to be compromised:

1. Generate a new key pair immediately and follow steps 2–6 above without waiting for the normal cadence.
2. Update the README and Gumroad email with bold warnings instructing users to stop trusting the compromised key.
3. Re-sign the most recent release with the new key and re-upload.
4. Verify the replacement signature with the revocation helper (below) and record the incident in `docs/signing_key_revocations.json`.
5. Cross-link the revocation log entry inside `docs/signing_key_rotation_log.json` so rotations and revocations share the same incident ID.
6. File an incident report (link in `SECURITY.md`) referencing the revocation log entry.

### Emergency revocation helper

Run `scripts/signing_key_revocation.py` to assert that the replacement key successfully signs the re-issued bundle and to append structured evidence to the revocation ledger:

```bash
python3 scripts/signing_key_revocation.py \
   --bundle dist/vectorscan-free.zip \
   --bundle-version 1.5.1-hotfix \
   --revoked-key /secure/archive/2024q4_cosign.pub \
   --replacement-key /secure/staging/2025q1_cosign.pub \
   --replacement-signature dist/vectorscan-free.zip.sig \
   --revocation-reason INC-1234 \
   --revocation-log docs/signing_key_revocations.json \
   --note "revoked via pagerduty #INC-1234"
```

The helper requires `cosign` on `PATH`, verifies the new signature, captures SHA256 fingerprints for both keys, stores the bundle hash, and appends everything to `docs/signing_key_revocations.json` (which ships with the repo for auditability). Treat the log as append-only - never rewrite history. If the helper exits with code 3, the signature verification failed; fix the signing inputs before publishing incident comms.

## Testing the Rotation Workflow

- Unit/Integration coverage: `pytest tests/integration/test_signing_key_rotation.py` uses a cosign stub to ensure the helper script passes/fails in the right scenarios.
- Manual dry run: run the helper script against a fixture bundle plus stubbed cosign binary (set `PATH` to include the stub) before touching real keys.
- Consumer validation: execute `scripts/verify.sh -f dist/vectorscan-free.zip -k <new-key>` with `cosign` pointing to the promoted key and confirm success, then repeat with the archived key to validate historical releases remain verifiable.

## Customer Notification Template

```
Subject: VectorScan signing key rotation – action recommended

Hi VectorScan user,

We rotated the release signing key on <DATE>. The new public key SHA256 fingerprint is <FPR>. The previous key (<OLD_FPR>) will remain valid for releases ≤ <VERSION> and is archived at <URL>.

Next steps for you:
1. Download the new `vectorscan-signing.pub` from <URL>.
2. Verify the latest bundle with `scripts/verify.sh -k vectorscan-signing.pub`.
3. Update any pinned keys in CI by <DEADLINE>.

Let us know via security@vectorguard.dev if you spot any verification issues.
```

Refer to `docs/signing_key_rotation_log.json` for the authoritative timeline of promotions and revocations.
