# Technical Design: shogunhound

| Field | Value |
|---|---|
| Status | Active |
| Version | v4.0 |
| Last Updated | 2026-02-19 |
| Last Verified Against | code on `main` |
| Repository | `github.com/nethoundsh/shogunhound` |

## 1) Purpose

`shogunhound` is an MCP stdio server that exposes Shodan intelligence workflows for analyst and agent use. It is designed for secure, low-friction lookups with deterministic tool contracts, strict input validation, bounded caching, and structured audit logs.

## 2) Runtime Model

- Transport: **stdio only** (no HTTP/SSE runtime in current implementation).
- Entry point: `cmd/server/main.go`.
- Startup requirements:
  - `SHODAN_API_KEY` must be set.
  - Cache and log paths are resolved from env (`CACHE_PATH`, `LOG_PATH`) with `~` expansion.
- Server registers all tools on one MCP server instance.

## 3) Package Architecture

- `internal/validator`: public-IP validation and blocked-range checks.
- `internal/cache`: local JSON cache with TTL, bounded size, atomic save, and corruption fallback.
- `internal/shodan`: go-shodan wrapper, response mapping, sentinel error normalization, process-wide pacing.
- `internal/formatter`: pretty/markdown/json output formatting.
- `internal/handler`: MCP request handlers, validation, cache orchestration, logging, and humanized errors.

## 4) Tool Surface

Registered MCP tools:

- `shodan_ip_query`
- `shodan_count`
- `shodan_search`
- `shodan_dns_resolve`
- `shodan_dns_reverse`
- `shodan_alert_create`
- `shodan_alert_list`
- `shodan_alert_delete`
- `shodan_cve_lookup`
- `shodan_ip_query_bulk`
- `shodan_report`

Notes:

- `tier` request args are accepted for backward compatibility where present, but pacing is process-wide and controlled by startup tier (`SHODAN_TIER`).
- Bulk/report handlers enforce 1..100 entries and worker bounds.

## 5) Data Model

Primary host model (`internal/shodan/model.go`):

- `ShodanHostResult`
  - identity: IP, org, ISP, ASN, hostnames, tags, OS
  - geo: country/city
  - exposure: ports, services, banners
  - vulns: sorted CVE IDs
  - `LastSeen`
- `ServiceRecord`
  - port/transport/module/product/version
  - raw banner (suppressed when `minify=true`)
  - CPE list

## 6) Validation and Safety

`validator.ValidateIP` rejects non-public and special ranges before any Shodan call, including:

- loopback, private, multicast, unspecified, link-local
- CGNAT (`100.64.0.0/10`)
- TEST-NET blocks (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`)
- reserved `240.0.0.0/4`
- documentation IPv6 prefix `2001:db8::/32`
- IPv4-mapped IPv6 is normalized via `To4()` before checks

## 7) Caching

- Default path: `~/.shodan_cache.json`
- TTL: 24h
- max entries: 100
- eviction: oldest `QueriedAt`
- persistence: temp file + atomic rename in same directory
- corrupt JSON: warning to stderr, continue with empty cache
- cache hits and misses both produce audit logs

## 8) Rate Limiting and Timeouts

- Client-wide limiter exists in `internal/shodan/client.go` and gates all Shodan-backed methods.
- Tier behavior:
  - `free`: approx 1 req/s
  - `paid`: approx 10 req/s
- Host query path uses a 4-second timeout.
- CVE lookup uses a bounded timeout window to prevent long-tail stalls.

## 9) Error Model

Shodan/API errors are normalized to sentinel errors:

- `ErrUnauthorized`
- `ErrRateLimited`
- `ErrNotFound`

Handlers map these into human-friendly MCP tool errors (authentication, rate limit, not indexed/no results, timeout, generic retry-later).

## 10) Output Contracts

Supported output modes across tools:

- `pretty`: plain text (no ANSI)
- `markdown`
- `json`

Formatting expectations:

- markdown output escapes table-breaking characters where needed
- nil-safe formatters avoid panics on empty result sets
- JSON output uses stable top-level field names matching struct tags

## 11) Logging and Auditability

- Log file opened with mode `0600`.
- Logger: `slog` JSON handler.
- Per-query logs include:
  - IP/query context
  - format
  - cache hit
  - duration
  - success/error
- Batch operations include aggregate counts (`successes`, `cache_hits`, `errors`).

## 12) Testing Strategy

Automated checks:

- `go test ./...`
- `go vet ./...`
- CI and release workflows include `govulncheck` and `golangci-lint`.

Test principles:

- Hermetic tests only (no live Shodan calls in unit tests).
- `httptest` for API behavior simulation.
- Coverage focus on `internal/*` behavior and error/edge-case handling.

## 13) Build and Delivery

Build:

```bash
go build -ldflags "-X main.version=vX.Y.Z" -o shogunhound ./cmd/server
```

Artifacts:

- Linux release binaries
- GHCR Docker image

## 14) Non-Goals (Current)

- HTTP/SSE serving mode
- autonomous offensive actions
- persistent database backend beyond local file cache
- distributed rate limiting across multiple server processes
