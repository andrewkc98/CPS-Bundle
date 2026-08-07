# CPS Bundle

`cps-bundle` creates an offline, normalized support bundle for Windows, Linux, and macOS. The same top-level JSON schema is used on every platform; native command output is retained only as bounded evidence for support review.

## Quick start

```text
# Linux/macOS
sudo cps-bundle

# Windows (from an elevated terminal or the signed executable)
cps-bundle.exe
```

The collector asks for confirmation because the default bundle includes useful support identifiers such as the hostname, serial number, MAC/IP addresses, SSIDs, and event messages. For unattended workflows use `--yes`; use `--redact` to mask common identifiers before packaging.

The result is a ZIP containing `00-summary.html`, `bundle.json`, the embedded schema, bounded evidence excerpts, a collection log, and a SHA-256 manifest. No network connection is made and no model or cloud service is required.

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
