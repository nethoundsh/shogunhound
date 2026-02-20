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

- Run `make test`
- Run `make lint`
- Open an issue first for non-trivial changes

## Architecture references

- `docs/DESIGN.md` for architecture and tool contracts
- `.cursor/AGENTS.md` for developer-agent implementation notes
