#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -lt 3 ]; then
  echo "Usage: $0 APKSIGNER PREVIOUS_APK RELEASE_APK..." >&2
  exit 2
fi

signer=$1
previous=$2
shift 2

certificates() {
  local report digests
  # Do not hide verification failures behind a successful text-processing pipe.
  report=$("$signer" verify --print-certs "$1") || return "$?"
  # Build-tools 37 uses "V3.0 Signer:" instead of the older "Signer #1".
  digests=$(printf '%s\n' "$report" | sed -nE 's/^.*Signer.*certificate SHA-256 digest: ([[:xdigit:]]{64})[[:space:]]*$/\1/p' | tr '[:upper:]' '[:lower:]' | LC_ALL=C sort -u)
  if [ -z "$digests" ]; then
    echo "No signing certificate SHA-256 digest found: $1" >&2
    return 1
  fi
  printf '%s\n' "$digests"
}

expected=$(certificates "$previous")
for apk in "$@"; do
  actual=$(certificates "$apk")
  if [ "$actual" != "$expected" ]; then
    echo "Signing certificate changed: $apk" >&2
    exit 1
  fi
done
echo "All release APK signing certificates match the previous release."
