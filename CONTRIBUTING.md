# Contributing

Thanks for your interest in improving `shogunhound`.

## Prerequisites

- Go 1.25+
- `golangci-lint` (install guide: https://golangci-lint.run/usage/install/)

## Build

```bash
make build
# or
go build -o shogunhound ./cmd/server
```

## Test

```bash
make test
# or
go test ./...
```

## Lint

```bash
make lint
# or
golangci-lint run
```

`make lint` expects `golangci-lint` to be installed on your system.

## Before opening a PR

Run the full quality gate:

```bash
make test           # go test ./...
make lint           # golangci-lint run
make release-check  # vet + cross-compile check
```

Checklist:
- [ ] `make test` passes
- [ ] `make lint` passes
- [ ] `make release-check` passes
- [ ] README and/or `docs/DESIGN.md` updated if tool behavior or contracts changed
- [ ] `CHANGELOG.md` entry added under `[Unreleased]` if the change is user-visible
- [ ] Issue opened first for non-trivial changes

## Architecture references

- `docs/DESIGN.md` for architecture and tool contracts
- `.cursor/AGENTS.md` for developer-agent implementation notes

## Release checklist

1. Move `[Unreleased]` entries to a versioned block in `CHANGELOG.md`
2. Run `make release-check`
3. Tag the release: `git tag vX.Y.Z && git push --tags`
4. GitHub Actions release workflow builds and publishes binaries and the GHCR image
