# Technical Design Document: shogunhound

| Field | Value |
|---|---|
| Author | droid.eleven |
| Status | Active |
| Version | v3.0 |
| Last Updated | 2026-02-18 |
| Repository | `github.com/nethoundsh/shogunhound` |
| Binary | `shogunhound` |
| MCP Tool ID | `shodan_ip_query` |

---

## Design Changelog

| Version | Date | Summary |
|---|---|---|
| v3.0 | 2026-02-18 | Consolidated to MCP stdio-only architecture; removed CLI subcommand assumptions, runtime HTTP/SSE mode assumptions, spinner/TTY behavior, and ANSI color requirements from the active design baseline. |
| v2.x | 2026-02 | Transitional design that still documented dual-mode operation (MCP + CLI) and optional HTTP/SSE deployment guidance. |

---

## 1. Background

Security analysts frequently need fast host intelligence for public IP addresses: open ports, service fingerprints, exposed banners, organizational ownership, and known CVEs.

`shogunhound` provides this through a single MCP tool so an LLM can query Shodan directly inside an investigation workflow without context switching.

This document reflects the current implementation baseline:

- MCP stdio server only
- One tool: `shodan_ip_query`
- No CLI subcommands
- No HTTP/SSE runtime mode in this MVP
- Plain-text pretty output and JSON output

---

## 2. Goals and Non-Goals

### Goals

- Query Shodan host intelligence for one public IP at a time.
- Enforce strict public-IP validation before any Shodan request.
- Cache results locally (24h TTL, bounded size, atomic writes).
- Return results as either plain-text `pretty` or structured `json`.
- Provide human-readable error messages to MCP clients.
- Log every query (cache hit and miss) for auditability.

### Non-Goals

- Batch/multi-IP queries.
- Domain lookup or hostname resolution.
- Shodan search/facets tools (non-host endpoint workflows).
- HTTP/SSE server transport in this release.
- Built-in risk scoring or autonomous remediation actions.

---

## 3. System Overview

`shogunhound` runs as an MCP stdio subprocess and is invoked by an MCP client (Cursor, editor agent, or terminal-based MCP client).

```text
MCP Client (stdio)
       |
       v
  shogunhound
   |   |   |
   |   |   +--> Audit Log (JSON lines)
   |   +------> Local Cache (JSON file)
   +----------> Shodan API
```

Core internal packages:

- `internal/validator`: public-IP validation
- `internal/cache`: local JSON cache with TTL + eviction
- `internal/shodan`: go-shodan wrapper and result mapping
- `internal/formatter`: pretty/json output renderer
- `internal/handler`: tool request lifecycle, logging, error humanization

---

## 4. Tool Contract

### Tool Name

`shodan_ip_query`

### Description

Queries Shodan for public IP host intelligence: open ports, running services, banner data, organization, geolocation, and known CVEs. Returns structured findings for security analysis. For ethical, authorized use only. Comply with Shodan Terms of Service: https://www.shodan.io/about/terms

### Parameters

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `ip` | string | Yes | — | Public IPv4 or IPv6 address to query |
| `format` | string | No | `pretty` | Output format: `pretty` or `json` |
| `history` | boolean | No | `false` | Include historical banner data |
| `minify` | boolean | No | `false` | Omit banner strings from the response |
| `tier` | string | No | `free` | Rate limit tier: `free` or `paid` |
| `clear_cache` | boolean | No | `false` | Evict cached result before querying |

---

## 5. Data Model

```go
type ServiceRecord struct {
    Port      int
    Transport string
    Module    string
    Product   string
    Version   string
    Banner    string
    CPE       []string
}

type ShodanHostResult struct {
    IP              string
    Organization    string
    ISP             string
    ASN             string
    Country         string
    City            string
    OS              string
    Ports           []int
    Hostnames       []string
    Tags            []string
    Vulnerabilities []string
    Services        []ServiceRecord
    LastSeen        time.Time
}
```

Mapping notes:

- `tags` is decoded from raw host JSON via an envelope type around go-shodan host structs.
- Vulnerability IDs are normalized and sorted.
- `module` is extracted from `_shodan.module` on service records.

---

## 6. Component Design

### 6.1 Validator

`ValidateIP(ip string) error` rejects:

- invalid parse
- loopback
- private RFC1918
- multicast
- unspecified
- link-local unicast
- CGNAT (`100.64.0.0/10`)
- TEST-NET blocks (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`)
- reserved `240.0.0.0/4`

IPv4-mapped IPv6 is normalized with `To4()` before checks.

### 6.2 Cache

- Default path: `~/.shodan_cache.json`
- TTL: 24h
- Max entries: 100
- Eviction: oldest by `QueriedAt`
- Persistence: write temp file in same directory + atomic rename
- Corrupt cache file: non-fatal; start with empty cache

### 6.3 Shodan Client

- Uses `go-shodan/v4`
- Query timeout: 4s (`context.WithTimeout`)
- Sentinel errors:
  - `ErrUnauthorized`
  - `ErrRateLimited`
  - `ErrNotFound`
- Post-success pacing:
  - `free`: 1000ms
  - `paid`: 100ms
- Sleep is context-aware and cancelable.

### 6.4 Formatter

`Format(result, format)` supports:

- `json`: `json.MarshalIndent`
- `pretty`: plain text sections

Pretty output sections:

- Header
- Identity
- Location
- Vulnerabilities
- Open ports and services
- Banners (only if non-empty banners exist)

No ANSI coloring is emitted.

### 6.5 Handler

`HandleShodanIPQuery(ctx, req)` flow:

1. Parse and type-check arguments
2. Validate IP
3. Optional `clear_cache` eviction
4. Attempt cache read
5. On hit: log cache hit and return formatted output
6. On miss: query Shodan
7. On error: log failure and return humanized tool error
8. On success: cache set, success log, formatted output

Audit log entry fields:

- `ip`
- `format`
- `cache_hit`
- `duration_ms`
- `success`
- `error`

---

## 7. Error Handling

Tool errors are returned as MCP tool results with `isError=true` semantics.

| Condition | Message |
|---|---|
| Invalid IP format | `invalid IP address: <input>` |
| Non-public IP | `IP <input> is not a public address and cannot be queried` |
| Missing API key at startup | `SHODAN_API_KEY not set; cannot query Shodan` |
| Unauthorized | `Shodan authentication failed; check your API key` |
| Rate limited | `Shodan rate limit exceeded; wait 60 seconds and retry` |
| Not indexed | `No Shodan data found for <ip>; host may not be indexed` |
| Timeout | `Shodan query timed out after 4 seconds; try again` |
| Other failures | `Shodan API error; try again later` |

---

## 8. Security Considerations

- API key is read from environment only.
- API key is never logged or persisted.
- Only public IPs can be queried.
- Query logs include plaintext IPs by design for auditability.
- Log file should remain permission-restricted (`0600`).

Recommended environment variables:

- `SHODAN_API_KEY` (required)
- `CACHE_PATH` (optional)
- `LOG_PATH` (optional)
- `MCP_PORT` (reserved, unused)

---

## 9. Testing Strategy

### Automated

- Unit tests for `validator`, `cache`, `formatter`, and `shodan` client.
- Hermetic HTTP tests using `httptest` for Shodan client behavior.
- No live Shodan calls in automated tests.

### Key Cases

- Validator: full matrix of public/private/invalid ranges
- Cache: hit/miss/expiry/persistence/eviction/corrupt file recovery
- Shodan: 200/401/429/404/timeout/malformed JSON
- Formatter: pretty/json/empty result behavior

Run:

```bash
go test ./...
```

---

## 10. Operations

### Build

```bash
go build -ldflags "-X main.version=v2.3.0" -o shogunhound ./cmd/server
```

### Install

```bash
sudo mv shogunhound /usr/local/bin/shogunhound
sudo chmod +x /usr/local/bin/shogunhound
```

### MCP config example

```json
{
  "mcpServers": {
    "shogunhound": {
      "command": "/usr/local/bin/shogunhound",
      "env": {
        "SHODAN_API_KEY": "${env:SHODAN_API_KEY}"
      }
    }
  }
}
```

### Deploy asset

`deploy/shogunhound.service` is included for future service management workflows. Current MVP remains stdio-first.

---

## 11. Known Risks

- go-shodan response shape can drift; verify field mappings on dependency upgrades.
- Tags/module extraction relies on response JSON compatibility.
- Free-tier rate limits can increase latency for repeated uncached requests.

---

## 12. Future Work

- Additional tools (search/facets/count)
- Batch queries
- Stronger cache backend (e.g., BoltDB) if throughput requirements grow
- HTTP/SSE transport as a separate implementation track
- Metrics export for operational observability

---

## 13. Appendix: Pretty Output Shape

```text
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 SHODAN HOST INTELLIGENCE — <IP>
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

IDENTITY
 Organization : <value or (unknown)>
 ISP : <value or (unknown)>
 ASN : <value or (unknown)>
 OS : <value or (unknown)>
 Hostnames : <comma-separated or (none)>
 Tags : <comma-separated or (none)>
 Last Seen : <YYYY-MM-DD or (unknown)>

LOCATION
 Country : <value or (unknown)>
 City : <value or (unknown)>

VULNERABILITIES
 <CVE list or "None detected">

OPEN PORTS & SERVICES
 <port>/<transport> <module> — <product> <version>

BANNERS
 Port <n>: <banner truncated to 200 chars>
```
