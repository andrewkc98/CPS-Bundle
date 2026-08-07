# CPS Bundle

`cps-bundle` creates an offline, normalized support bundle for Windows, Linux, and macOS. The same top-level JSON schema is used on every platform; native command output is retained only as bounded evidence for support review.

## Quick start

```text
# Linux/macOS (from the repository after building)
sudo ./cps-bundle

# Windows (from an elevated terminal or the signed executable)
cps-bundle.exe
```

The collector asks for confirmation because the default bundle includes useful support identifiers such as the hostname, serial number, MAC/IP addresses, SSIDs, and event messages. For unattended workflows use `--yes`; use `--redact` to mask common identifiers before packaging.

The result is a ZIP containing `00-summary.html`, `bundle.json`, the embedded schema, bounded evidence excerpts, a collection log, and a SHA-256 manifest. No network connection is made and no model or cloud service is required.

## macOS quick start

Install Go 1.22 or newer, then clone the repository, build the native executable, and run it with administrator privileges:

```sh
git clone https://github.com/andrewkc98/CPS-Bundle.git
cd CPS-Bundle
go build -trimpath -o cps-bundle .

# Keep the sensitive output private and owned by your user account.
mkdir -p build-check
chmod 700 build-check
sudo ./cps-bundle --yes --output ./build-check
```

The resulting ZIP is written to `build-check/`. Omit `--yes` to review the interactive confirmation, or add `--redact` to mask common identifiers before packaging.

For an existing checkout, update and rebuild it with:

```sh
git pull --ff-only
go build -trimpath -o cps-bundle .
```

Cloning is recommended over downloading a source ZIP because a clone can be updated with `git pull`. The `cps-bundle` executable is generated locally and is not committed to the repository.

To make the command available outside the repository, optionally install it in a system path:

```sh
sudo install -m 0755 ./cps-bundle /usr/local/bin/cps-bundle
sudo /usr/local/bin/cps-bundle --yes --output ./build-check
```

## Commands

```text
cps-bundle [collect] [--output PATH] [--since 72h] [--yes] [--redact]
           [--include SECTION] [--exclude SECTION] [--no-enrichers]
           [--max-events 2000]
cps-bundle schema
cps-bundle version
```

Collectors report partial coverage when an OS API or optional utility is unavailable. The first release supports Windows 10/11 and Server 2019+, macOS 13+, Ubuntu 22.04+, and RHEL 9+.

## Development

The project uses only the Go standard library and build-tagged platform files. Build targets are selected by Go's normal `GOOS`/`GOARCH` settings. Run `go test ./...` on a machine with Go 1.22 or newer; integration coverage should run on each supported operating system because native collectors intentionally use that OS's built-in APIs and tools.
