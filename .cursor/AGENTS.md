<!-- Internal implementation notes for developer agents. Not end-user documentation. -->

# shogunhound — Implementation Instructions

Read `docs/DESIGN.md` for full context, rationale, and data model before starting.

## Core constraints

- Transport is stdio-only in the current MVP; do not add HTTP/SSE runtime behavior.
- Keep MCP output plain text/JSON (no TTY spinner or ANSI styling).
- Treat all input as untrusted; preserve strict public-IP validation behavior.
- Preserve cache + audit logging expectations and non-secret handling of API key material.

## Package layout

- `internal/validator`
- `internal/cache`
- `internal/shodan`
- `internal/formatter`
- `internal/handler`

## Build and test

```bash
go build -o shogunhound ./cmd/server
go test ./...
go vet ./...
```
