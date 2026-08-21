# CPS Bundle

`cps-bundle` creates an offline, normalized support bundle for Windows, Linux, and macOS. The same top-level JSON schema is used on every platform; native command output is retained only as bounded evidence for support review.

## Quick start

```text
# Linux/macOS (from the repository after building)
sudo ./cps-bundle

# Windows (from an elevated terminal or the signed executable)
cps-bundle.exe
```

The collector asks for confirmation because the default bundle includes useful support identifiers such as the hostname, serial number, MAC/IP addresses, SSIDs, and event messages. For unattended workflows use `--yes`. Use `--redact` when a smaller, lower-exposure bundle is preferable: common structured identifiers are replaced, event messages and update history are blanked with `[REDACTED]`, collector errors are redacted in the packaged log, and raw evidence files are omitted. Redaction reduces exposure but cannot guarantee anonymity.

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

macOS's unified-log command accepts whole-hour lookbacks. The collector therefore rounds `--since` up to the next whole hour; every positive value below one hour collects one hour.

## Linux quick start

Install Go 1.22 or newer and Git using your organization's approved package source, then verify the Go version before building. The remaining commands are the same on Ubuntu/Debian and RHEL/Fedora:

```sh
go version
git clone https://github.com/andrewkc98/CPS-Bundle.git
cd CPS-Bundle
go build -trimpath -o cps-bundle .

# Keep support output private. The ZIP is returned to the invoking sudo user.
install -d -m 0700 "$HOME/cps-bundle-output"
sudo ./cps-bundle collect --yes --output "$HOME/cps-bundle-output"
```

For a lower-exposure bundle, add `--redact`. Automated scripts or RMM tooling can add `--strict`; a degraded collection still writes its ZIP but exits with status 3 so automation can distinguish it from a complete collection.

For an existing checkout, update and rebuild it with:

```sh
git pull --ff-only
go build -trimpath -o cps-bundle .
```

To install the collector system-wide:

```sh
sudo install -m 0755 ./cps-bundle /usr/local/bin/cps-bundle
install -d -m 0700 "$HOME/cps-bundle-output"
sudo /usr/local/bin/cps-bundle collect --yes --output "$HOME/cps-bundle-output"
```

On RHEL/Fedora, RPM is the preferred software inventory source. On Ubuntu/Debian, `dpkg-query` is preferred. DNS falls back to `/etc/resolv.conf` when `resolvectl` is unavailable.

## Commands

```text
cps-bundle [collect] [--output PATH] [--since 72h] [--yes] [--redact]
           [--include SECTION] [--exclude SECTION] [--no-enrichers]
           [--max-events 2000] [--strict]
cps-bundle schema
cps-bundle version
```

Collectors report partial coverage when an OS API or optional utility is unavailable. The first release supports Windows 10/11 and Server 2019+, macOS 13+, Ubuntu 22.04+, and RHEL 9+.

By default, a degraded collection prints its non-OK sections and exits successfully because a useful bundle was written. `--strict` changes that completed-but-degraded outcome to exit status 3. Fatal collection or packaging failures use status 1, and unknown commands use status 2. Sections intentionally excluded by the user do not make a strict run degraded.

If the collector reports an ownership or final-close error after naming an archive, a ZIP has already been published at that final path. Do not assume it is usable after a final-close error; inspect or remove that exact archive before retrying. The collector will not overwrite it.

## Development

The project uses only the Go standard library and build-tagged platform files. Build targets are selected by Go's normal `GOOS`/`GOARCH` settings. Run `go test ./...` on a machine with Go 1.22 or newer; integration coverage should run on each supported operating system because native collectors intentionally use that OS's built-in APIs and tools.
