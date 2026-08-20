#!/usr/bin/env sh
set -eu
version="${1:-0.1.0}"
out="${2:-dist}"
mkdir -p "$out"

write_sha256() {
  path="$1"
  name="$(basename "$path")"
  if command -v sha256sum >/dev/null 2>&1; then
    hash="$(sha256sum "$path")"
  else
    hash="$(shasum -a 256 "$path")"
  fi
  hash="${hash%% *}"
  printf '%s  %s\n' "$hash" "$name" > "$path.sha256"
}

for target in "windows amd64 windows-amd64.exe" "windows arm64 windows-arm64.exe" "linux amd64 linux-amd64" "linux arm64 linux-arm64" "darwin amd64 macos-amd64" "darwin arm64 macos-arm64"; do
  set -- $target
  goos="$1"; goarch="$2"; suffix="$3"
  path="$out/cps-bundle-$suffix"
  GOOS="$goos" GOARCH="$goarch" go build -trimpath -ldflags "-s -w -X main.version=$version" -o "$path" .
  write_sha256 "$path"
done
echo "Built CPS Bundle artifacts in $out. Apply platform signing/notarization in the release pipeline before distribution."
