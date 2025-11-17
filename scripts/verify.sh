#!/usr/bin/env bash
set -euo pipefail

# verify.sh: Verify a VectorScan release bundle by SHA256 and optional cosign signature.
# Usage:
#   scripts/verify.sh -f dist/vectorscan-free.zip [-d dist/vectorscan-free.zip.sha256 | -h <sha256_hex>] [-k public-key.pem]
# Options:
#   -f  Path to the bundle file (zip)
#   -d  Path to a file containing the expected SHA256 (hex)
#   -h  Expected SHA256 (hex string)
#   -k  Path to cosign public key (.pem). If provided and cosign is installed, signature will be verified.
#
# Notes:
# - If both -d and -h are provided, -h takes precedence.
# - Requires sha256sum (Linux) or shasum -a 256 (macOS). Falls back automatically.
# - Cosign verification is optional and will be skipped if cosign or key is missing.

usage() {
  sed -n '2,20p' "$0"
}

BUNDLE=""
HEX=""
HEX_FILE=""
COSIGN_KEY=""

while getopts ":f:d:h:k:" opt; do
  case "$opt" in
    f) BUNDLE="$OPTARG" ;;
    d) HEX_FILE="$OPTARG" ;;
    h) HEX="$OPTARG" ;;
    k) COSIGN_KEY="$OPTARG" ;;
    *) usage; exit 2 ;;
  esac
done

if [[ -z "$BUNDLE" ]]; then
  echo "error: bundle (-f) is required" >&2
  usage
  exit 2
fi
if [[ ! -f "$BUNDLE" ]]; then
  echo "error: bundle not found: $BUNDLE" >&2
  exit 2
fi

if [[ -z "$HEX" && -n "$HEX_FILE" ]]; then
  if [[ ! -f "$HEX_FILE" ]]; then
    echo "error: sha256 file not found: $HEX_FILE" >&2
    exit 2
  fi
  # Read first token from file as hex digest
  HEX=$(head -n1 "$HEX_FILE" | awk '{print $1}')
fi

calc_sha256() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{print $1}'
  else
    echo "error: neither sha256sum nor shasum found" >&2
    exit 2
  fi
}

CALC_DIGEST=$(calc_sha256 "$BUNDLE")

if [[ -n "$HEX" ]]; then
  if [[ "$CALC_DIGEST" != "$HEX" ]]; then
    echo "SHA256 MISMATCH" >&2
    echo " expected: $HEX" >&2
    echo "   actual: $CALC_DIGEST" >&2
    exit 3
  fi
  echo "SHA256 OK ($CALC_DIGEST)"
else
  echo "SHA256 (no expected hex provided): $CALC_DIGEST"
fi

# Optional cosign verify
if [[ -n "$COSIGN_KEY" ]]; then
  if ! command -v cosign >/dev/null 2>&1; then
    echo "cosign not found; skipping signature verification" >&2
  elif [[ ! -f "$COSIGN_KEY" ]]; then
    echo "cosign key not found at: $COSIGN_KEY; skipping signature verification" >&2
  else
    echo "Verifying signature with cosign..."
    if cosign verify-blob --key "$COSIGN_KEY" --signature "$BUNDLE.sig" "$BUNDLE"; then
      echo "Cosign signature OK"
    else
      echo "Cosign signature verification FAILED" >&2
      exit 4
    fi
  fi
else
  echo "No cosign key provided; skipping signature verification"
fi

echo "Verification completed successfully"
