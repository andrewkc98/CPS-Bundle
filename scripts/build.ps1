param(
  [string]$Version = "0.1.0",
  [string]$Output = "dist"
)

$ErrorActionPreference = "Stop"
New-Item -ItemType Directory -Force -Path $Output | Out-Null
$targets = @(
  @{ GOOS = "windows"; GOARCH = "amd64"; Suffix = "windows-amd64.exe" },
  @{ GOOS = "windows"; GOARCH = "arm64"; Suffix = "windows-arm64.exe" },
  @{ GOOS = "linux"; GOARCH = "amd64"; Suffix = "linux-amd64" },
  @{ GOOS = "linux"; GOARCH = "arm64"; Suffix = "linux-arm64" },
  @{ GOOS = "darwin"; GOARCH = "amd64"; Suffix = "macos-amd64" },
  @{ GOOS = "darwin"; GOARCH = "arm64"; Suffix = "macos-arm64" }
)

foreach ($target in $targets) {
  $env:GOOS = $target.GOOS
  $env:GOARCH = $target.GOARCH
  $name = "cps-bundle-$($target.Suffix)"
  $path = Join-Path $Output $name
  go build -trimpath -ldflags "-s -w -X main.version=$Version" -o $path .
  if ($target.GOOS -eq "windows" -and (Get-Command mt.exe -ErrorAction SilentlyContinue)) {
    mt.exe -manifest cps-bundle.manifest -outputresource:"$path;#1" | Out-Null
  }
  Get-FileHash -Algorithm SHA256 $path | ForEach-Object { "$($_.Hash.ToLower())  $name" } | Out-File -Encoding ascii "$path.sha256"
}

Remove-Item Env:GOOS,Env:GOARCH -ErrorAction SilentlyContinue
Write-Host "Built CPS Bundle artifacts in $Output. Apply platform signing/notarization in the release pipeline before distribution."
