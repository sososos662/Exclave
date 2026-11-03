#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
temp=$(mktemp -d)
trap 'rm -f "$temp/apksigner"; rmdir "$temp"' EXIT

cat > "$temp/apksigner" <<'MOCK'
#!/usr/bin/env bash
set -euo pipefail
test "$1" = verify
test "$2" = --print-certs
hash=2062a81fad5fddda32198038de4afd5b92768610ac348eae9e50c5a4cac5ab48
case "$3" in
  previous.apk) echo "Signer #1 certificate SHA-256 digest: $hash" ;;
  release.apk) echo "V3.0 Signer: certificate SHA-256 digest: $hash" ;;
  repeated.apk)
    echo "V2 Signer: certificate SHA-256 digest: $hash"
    echo "V3.0 Signer: certificate SHA-256 digest: $hash"
    ;;
  changed.apk) echo 'V3.0 Signer: certificate SHA-256 digest: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' ;;
  missing.apk) echo 'No certificate information' ;;
  invalid.apk)
    echo "Signer #1 certificate SHA-256 digest: $hash"
    exit 1
    ;;
  *) exit 2 ;;
esac
MOCK
chmod +x "$temp/apksigner"

bash "$root/bin/verify-apk-signatures.sh" "$temp/apksigner" previous.apk release.apk repeated.apk
for apk in changed.apk missing.apk invalid.apk; do
  if bash "$root/bin/verify-apk-signatures.sh" "$temp/apksigner" previous.apk "$apk" > /dev/null 2>&1; then
    echo "Incorrectly accepted $apk" >&2
    exit 1
  fi
done
echo "Signing verification regression tests passed."
