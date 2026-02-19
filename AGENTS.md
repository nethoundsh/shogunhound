# shogunhound — Implementation Instructions

Read `DESIGN.md` for full context, rationale, and data model before starting.
This file supersedes any open questions or ambiguities in DESIGN.md.

---

## Resolved Design Decisions

| Decision | Resolution |
|---|---|
| Transport | **stdio only** — HTTP/SSE is not implemented in this MVP |
| `OS` field | **Included** in `ShodanHostResult` |
| Cache hit logging | **Yes** — every query (hit and miss) produces an audit log entry |
| TTY detection | **Not used** — spinner and ANSI color removed; MCP output is plain text |
| Package layout | `internal/validator`, `internal/cache`, `internal/shodan`, `internal/formatter`, `internal/handler` |
| CLI framework | **None** — MCP stdio server only; no `query` subcommand, no cobra |
| Health check | **Not implemented** — stdio mode has no HTTP listener; deferred to future HTTP/SSE work |

---

## Module and Dependencies

```
Module: github.com/nethoundsh/shogunhound
Go:     1.21+
```

```bash
go mod init github.com/nethoundsh/shogunhound
go get github.com/mark3labs/mcp-go@latest
go get github.com/ns3777k/go-shodan/v4@latest
```

---

## Directory Structure

```
shogunhound/
├── cmd/
│   └── server/
│       └── main.go              # MCP server startup only — no CLI subcommands
├── internal/
│   ├── validator/
│   │   ├── validator.go
│   │   └── validator_test.go
│   ├── cache/
│   │   ├── cache.go
│   │   └── cache_test.go
│   ├── shodan/
│   │   ├── model.go             # ShodanHostResult and ServiceRecord types
│   │   ├── client.go            # ShodanClient wrapping go-shodan
│   │   └── client_test.go
│   ├── formatter/
│   │   ├── formatter.go
│   │   └── formatter_test.go
│   └── handler/
│       └── handler.go           # MCP tool handler + audit logger + error humanizer
└── deploy/
    └── shogunhound.service      # systemd unit (for future HTTP/SSE use; include now)
```

---

## Implementation Steps

Implement strictly in this order. Each step depends on the previous.

---

### Step 1 — Data Model (`internal/shodan/model.go`)

Define the canonical internal types used across all packages.

```go
package shodan

import "time"

type ServiceRecord struct {
    Port      int
    Transport string   // "tcp" or "udp"
    Module    string   // e.g. "dns-udp", "ssh"
    Product   string   // e.g. "OpenSSH"
    Version   string
    Banner    string   // raw banner; empty when minify=true
    CPE       []string
}

type ShodanHostResult struct {
    IP              string
    Organization    string
    ISP             string
    ASN             string
    Country         string
    City            string
    OS              string          // OS fingerprint; empty string if not detected
    Ports           []int
    Hostnames       []string
    Tags            []string
    Vulnerabilities []string        // CVE IDs, e.g. "CVE-2021-44228"; sorted
    Services        []ServiceRecord
    LastSeen        time.Time
}
```

No tests needed — pure types.

---

### Step 2 — Validator (`internal/validator/`)

#### `validator.go`

Implement one exported function:

```go
func ValidateIP(ip string) error
```

Returns `nil` for a valid, publicly routable IP. Returns a descriptive error otherwise.

**Rejection checks in order:**

1. `net.ParseIP(ip) == nil` → `fmt.Errorf("invalid IP address: %s", ip)`
2. `parsed.IsLoopback()` → reject
3. `parsed.IsPrivate()` → reject (covers RFC 1918: 10/8, 172.16/12, 192.168/16)
4. `parsed.IsMulticast()` → reject
5. `parsed.IsUnspecified()` → reject (0.0.0.0, ::)
6. `parsed.IsLinkLocalUnicast()` → reject (169.254/16, fe80::/10)
7. CGNAT `100.64.0.0/10` (RFC 6598) → reject
8. TEST-NET `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24` (RFC 5737) → reject
9. Reserved `240.0.0.0/4` (RFC 1112) → reject

For checks 7–9: parse the CIDR ranges with `net.ParseCIDR` at package `init()` into a `[]*net.IPNet` slice. For each range check `cidr.Contains(parsed)`.

For IPv4-mapped IPv6 addresses (e.g., `::ffff:192.168.1.1`): call `parsed.To4()` — if non-nil, run all checks against the IPv4 form.

**Error messages:**
- Invalid format: `"invalid IP address: <ip>"`
- Any rejected range: `"IP <ip> is not a public address and cannot be queried"`

#### `validator_test.go`

Table-driven tests. Cover every case:

| Input | Expected |
|---|---|
| `8.8.8.8` | nil |
| `1.1.1.1` | nil |
| `2001:4860:4860::8888` | nil |
| `127.0.0.1` | error |
| `::1` | error |
| `10.0.0.1` | error |
| `172.16.0.1` | error |
| `172.31.255.255` | error |
| `192.168.1.1` | error |
| `224.0.0.1` | error |
| `0.0.0.0` | error |
| `::` | error |
| `169.254.1.1` | error |
| `fe80::1` | error |
| `100.64.0.1` | error |
| `100.127.255.255` | error |
| `192.0.2.1` | error |
| `198.51.100.1` | error |
| `203.0.113.1` | error |
| `240.0.0.1` | error |
| `""` | error |
| `"not-an-ip"` | error |
| `"google.com"` | error |
| `"::ffff:192.168.1.1"` | error (IPv4-mapped private) |

---

### Step 3 — Cache (`internal/cache/`)

#### `cache.go`

```go
package cache

import (
    "encoding/json"
    "os"
    "path/filepath"
    "sync"
    "time"

    "github.com/nethoundsh/shogunhound/internal/shodan"
)

const (
    cacheTTL    = 24 * time.Hour
    maxEntries  = 100
    cacheVersion = 1
)

type Entry struct {
    QueriedAt time.Time              `json:"queried_at"`
    ExpiresAt time.Time              `json:"expires_at"`
    Data      *shodan.ShodanHostResult `json:"data"`
}

type cacheFile struct {
    Version int               `json:"version"`
    Entries map[string]Entry  `json:"entries"`
}

type Cache struct {
    path    string
    mu      sync.RWMutex
    entries map[string]Entry
}
```

**Constructor:** `func New(path string) (*Cache, error)`
- Resolve `~` in path using `os.UserHomeDir()`.
- Call `load()`. If the file does not exist, start with empty `entries` — not an error.
- If the file exists but fails JSON decode: log warning to stderr, start with empty entries, do not return error.

**`Get(ip string) (*shodan.ShodanHostResult, bool)`**
- Read lock.
- Return entry data if present and `time.Now().Before(entry.ExpiresAt)`.
- Return `nil, false` on miss or expired entry.

**`Set(ip string, result *shodan.ShodanHostResult)`**
- Write lock.
- Insert entry: `QueriedAt = now`, `ExpiresAt = now + 24h`.
- If `len(entries) > maxEntries`: find and delete the entry with the oldest `QueriedAt`.
- Call `save()`; on error, log warning to stderr and continue (non-fatal).

**`Evict(ip string)`**
- Write lock.
- Delete entry. Call `save()`.

**`save() error`** (unexported)
- Marshal `cacheFile{Version: 1, Entries: c.entries}` to JSON.
- Write to a temp file in the same directory as the cache file:
  `os.CreateTemp(filepath.Dir(c.path), ".shodan_cache_*.tmp")`
- `os.Rename(tmp.Name(), c.path)` — atomic on the same filesystem.
- Clean up temp file on any error path.

**`load() error`** (unexported)
- `os.ReadFile(c.path)`, unmarshal into `cacheFile`, populate `c.entries`.

#### `cache_test.go`

| Test | Assertion |
|---|---|
| Get hit | entry present and not expired → returns data |
| Get miss (absent) | returns nil, false |
| Get miss (expired) | entry with ExpiresAt in past → returns nil, false |
| Set and persist | call Set; create new Cache from same path; Get returns result |
| TTL boundary | entry with QueriedAt 25h ago → Get returns miss |
| 100-entry eviction | insert 101 entries (oldest first); verify entry count = 100 and oldest is gone |
| Atomic write | no `.tmp` file left after Set |
| Corrupt file | write invalid JSON to path; `New` succeeds, entries empty |

---

### Step 4 — Shodan Client (`internal/shodan/client.go`)

#### Sentinel errors

```go
var (
    ErrRateLimited  = errors.New("rate limited")
    ErrNotFound     = errors.New("not found")
    ErrUnauthorized = errors.New("unauthorized")
)
```

#### Client

```go
type ShodanClient struct {
    client *goshodan.Client
    tier   string  // "free" or "paid"
}

func NewClient(apiKey, tier string) *ShodanClient
```

**`QueryHost(ctx context.Context, ip string, history, minify bool) (*ShodanHostResult, error)`**

1. Create `ctx, cancel = context.WithTimeout(ctx, 4*time.Second)`; defer cancel.
2. Call `go-shodan`'s host information method (verify exact method name and signature against the library source).
3. Map the response to `ShodanHostResult`:
   - `Vulnerabilities` comes from the embedded `goshodan.Host` as `[]string`; copy and sort with `sort.Strings`.
   - `Module`: extract from `data.ShodanData["module"]` where `ShodanData` is `map[string]interface{}`.
   - If `minify=true`: set `ServiceRecord.Banner = ""`.
   - `OS`: map from go-shodan's `OS` field; empty string if absent.
4. On success: apply rate limit sleep — `free` = 1000ms, `paid` = 100ms — using `time.Sleep`. Sleep happens after mapping, not before calling the API.
5. Error mapping (via `mapAPIError(err error) error`):
   - `errors.Is(err, context.DeadlineExceeded)` or `errors.Is(err, context.Canceled)` → return as-is
   - `strings.Contains(msg, "401")` or `"invalid api key"` or `"unauthorized"` → `ErrUnauthorized`
   - `strings.Contains(msg, "429")` or `"rate limit"` → `ErrRateLimited`
   - `strings.Contains(msg, "404")` or `"no information available for that ip"` → `ErrNotFound`
   - default → `fmt.Errorf("shodan API error: %w", err)`

#### `client_test.go`

Use `net/http/httptest` to mock the Shodan API. Do not call the real Shodan API in tests.

| Scenario | Assertion |
|---|---|
| Valid 200 response for 8.8.8.8 | returned struct fields match mock payload |
| 401 response | returns `ErrUnauthorized` |
| 429 response | returns `ErrRateLimited` |
| 404 response | returns `ErrNotFound` |
| Response delayed >4s | returns `context.DeadlineExceeded` |
| Malformed JSON body | returns non-nil error |

#### Additional client methods

```go
func (c *ShodanClient) Count(ctx context.Context, query string) (int, error)
func (c *ShodanClient) Search(ctx context.Context, query string, page int) (*SearchResult, error)
func (c *ShodanClient) DNSResolve(ctx context.Context, hostnames []string) (map[string]string, error)
func (c *ShodanClient) DNSReverse(ctx context.Context, ips []string) (map[string][]string, error)
```

Search helpers:

```go
type SearchResult struct {
    Total   int
    Matches []*ShodanHostResult
}

func mapHostDataToResult(data *goshodan.HostData) *ShodanHostResult
```

Notes:
- `Search` maps `HostData` records (one port per match) to `ShodanHostResult`.
- `DNSResolve` converts `map[string]*net.IP` to `map[string]string`.
- `DNSReverse` parses `[]string` into `[]net.IP` and converts `map[string]*[]string` to `map[string][]string`.

---

### Step 5 — Formatter (`internal/formatter/`)

#### `formatter.go`

```go
func Format(result *shodan.ShodanHostResult, format string) string
func FormatSearchResult(result *shodan.SearchResult, format string) string
```

**JSON mode** (`format == "json"`):
- `json.MarshalIndent(result, "", "  ")` — return as string. No color codes.

**Markdown mode** (`format == "markdown"`):

- Header: `## Shodan Host Intelligence — <IP>`
- Identity/location summary fields in markdown
- Vulnerabilities as markdown bullet list (or `None detected.`)
- Services as markdown table
- Optional banners section if non-empty banners exist

**Pretty mode** (`format == "pretty"` or any other value):

Use `strings.Builder` for construction. No ANSI color codes — plain text only (MCP clients are LLMs, not TTYs).

Output layout (match Appendix B.1 of DESIGN.md):

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  SHODAN HOST INTELLIGENCE — <IP>
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

IDENTITY
  Organization : <value or "(unknown)">
  ISP          : <value or "(unknown)">
  ASN          : <value or "(unknown)">
  OS           : <value or "(unknown)">
  Hostnames    : <comma-separated or "(none)">
  Tags         : <comma-separated or "(none)">
  Last Seen    : <YYYY-MM-DD>

LOCATION
  Country      : <value or "(unknown)">
  City         : <value or "(unknown)">

VULNERABILITIES
  <CVE-ID per line>
  — or —
  None detected

OPEN PORTS & SERVICES
  <port>/<transport>  <module>  — <product> <version>
  (one line per ServiceRecord; omit product/version if empty)

BANNERS
  Port <n>: <banner, first 200 chars>
  (omit this section entirely if all banners are empty)
```

#### `formatter_test.go`

| Test | Assertion |
|---|---|
| Pretty with CVEs | CVE section header present; CVE IDs listed as plain text |
| Pretty without CVEs | "None detected" present as plain text |
| Pretty with empty ports | ports section shows explicit "(none)" |
| JSON format | output is valid JSON; unmarshals back to ShodanHostResult with matching fields |
| Empty/zero-value result | must not panic |
| Markdown with CVEs | markdown header, CVEs, and services table row present |
| Markdown no panic | nil/empty results render safely |
| Search result formatting | pretty, markdown, and json modes return expected shape |

---

### Step 6 — MCP Tool Handler (`internal/handler/handler.go`)

```go
package handler

type ToolHandler struct {
    cache  *cache.Cache
    shodan *shodan.ShodanClient
    logger *slog.Logger
}

func New(cache *cache.Cache, client *shodan.ShodanClient, logPath string) (*ToolHandler, error)
```

Constructor:
- Open log file: `os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)`.
  Resolve `~` via `os.UserHomeDir()`.
- Create `slog.Logger` with `slog.NewJSONHandler(logFile, nil)`.
- On log file open failure: return error (this is fatal; the handler requires a log).

#### `HandleShodanIPQuery`

```go
func (h *ToolHandler) HandleShodanIPQuery(
    ctx context.Context,
    req mcp.CallToolRequest,
) (*mcp.CallToolResult, error)
```

**Parameter extraction** via `req.GetArguments()`:

```go
ip        string  // required; return ToolResultError if missing or not a string
format    string  // default "pretty"
history   bool    // default false
minify    bool    // default false
tier      string  // default "free"; pass to ShodanClient
clearCache bool   // default false
```

**Request lifecycle:**

```
1.  Extract parameters; validate types.
    Missing/invalid ip → return mcp.NewToolResultError("missing required parameter: ip")

2.  validator.ValidateIP(ip)
    Error → return mcp.NewToolResultError(err.Error())

3.  if clearCache: h.cache.Evict(ip)

4.  result, hit := h.cache.Get(ip)

5.  if hit:
        h.logQuery(ip, format, true, 0, true, "")
        goto Format

6.  start := time.Now()

7.  result, err := h.shodan.QueryHost(ctx, ip, history, minify)
    duration := time.Since(start)

8.  if err != nil:
        h.logQuery(ip, format, false, duration, false, err.Error())
        return mcp.NewToolResultError(humanizeError(ip, err))

9.  h.cache.Set(ip, result)

10. h.logQuery(ip, format, false, duration, true, "")

Format:
11. output := formatter.Format(result, format)
    return mcp.NewToolResultText(output)
```

**`logQuery` helper** — writes one slog record:

```json
{
  "time": "...",
  "level": "INFO",
  "msg": "query",
  "ip": "<ip>",
  "format": "<format>",
  "cache_hit": <bool>,
  "duration_ms": <int64>,
  "success": <bool>,
  "error": "<string or empty>"
}
```

Use `slog.With(...)` or `slog.Info(...)` with explicit key-value pairs. `duration_ms` is `duration.Milliseconds()` (0 for cache hits).

On slog write failure: write to stderr, continue.

**`humanizeError(ip string, err error) string`**

| Error | Message |
|---|---|
| `shodan.ErrUnauthorized` | `"Shodan authentication failed; check your API key"` |
| `shodan.ErrRateLimited` | `"Shodan rate limit exceeded; wait 60 seconds and retry"` |
| `shodan.ErrNotFound` | `"No Shodan data found for <ip>; host may not be indexed"` |
| `context.DeadlineExceeded` | `"Shodan query timed out after 4 seconds; try again"` |
| anything else | `"Shodan API error; try again later"` |

Use `errors.Is` for matching.

#### Additional handlers

```go
func (h *ToolHandler) HandleShodanCount(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error)
func (h *ToolHandler) HandleShodanSearch(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error)
func (h *ToolHandler) HandleShodanDNSResolve(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error)
func (h *ToolHandler) HandleShodanDNSReverse(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error)
```

Shared helpers:

```go
func humanizeSearchError(err error) string
func splitAndTrim(s string) []string
```

Notes:
- `HandleShodanSearch` supports `format` (`pretty|markdown|json`) and optional `page`.
- DNS handlers accept comma-separated strings, enforce 1..100 entries, and return line-by-line mappings.
- DNS reverse validates each IP with `validator.ValidateIP` before querying Shodan.

---

### Step 7 — MCP Server Entry Point (`cmd/server/main.go`)

The binary has one mode: start the MCP stdio server. No CLI subcommands, no cobra.

#### Version

Set at build time via ldflags:

```bash
go build -ldflags "-X main.version=v2.3.0" -o shogunhound ./cmd/server
```

#### `main()`

```go
func main() {
    if os.Getenv("SHODAN_API_KEY") == "" {
        fmt.Fprintln(os.Stderr, "SHODAN_API_KEY not set; cannot query Shodan")
        os.Exit(1)
    }
    _, _, h, err := initComponents()
    if err != nil {
        fmt.Fprintln(os.Stderr, err)
        os.Exit(1)
    }
    mcpServer := server.NewMCPServer("shogunhound", version)
    mcpServer.AddTool(mcpTool(), h.HandleShodanIPQuery)
    mcpServer.AddTool(countTool(), h.HandleShodanCount)
    mcpServer.AddTool(searchTool(), h.HandleShodanSearch)
    mcpServer.AddTool(dnsResolveTool(), h.HandleShodanDNSResolve)
    mcpServer.AddTool(dnsReverseTool(), h.HandleShodanDNSReverse)
    if err := server.ServeStdio(mcpServer); err != nil {
        fmt.Fprintln(os.Stderr, err)
        os.Exit(1)
    }
}
```

#### Initialization helper

```go
func initComponents() (*cache.Cache, *shodan.ShodanClient, *handler.ToolHandler, error)
```

1. Read `CACHE_PATH` env (default `~/.shodan_cache.json`).
2. Read `LOG_PATH` env (default `~/shodan_queries.log`).
3. Read `SHODAN_API_KEY` env.
4. `cache.New(cachePath)`
5. `shodan.NewClient(apiKey, "free")`
6. `handler.New(cache, client, logPath)`

#### `mcpTool()` — tool definition

```go
mcp.NewTool("shodan_ip_query",
    mcp.WithDescription("Queries Shodan for public IP host intelligence: open ports, running services, "+
        "banner data, organization, geolocation, and known CVEs. Returns structured findings for security analysis. "+
        "For ethical, authorized use only. Comply with Shodan Terms of Service: https://www.shodan.io/about/terms"),
    mcp.WithString("ip",
        mcp.Required(),
        mcp.Description("Public IPv4 or IPv6 address to query")),
    mcp.WithString("format",
        mcp.Description("Output format: pretty (plain text), markdown, or json (default: pretty)")),
    mcp.WithBoolean("history",
        mcp.Description("Include historical banner data")),
    mcp.WithBoolean("minify",
        mcp.Description("Return lightweight response omitting banner strings")),
    mcp.WithString("tier",
        mcp.Description("Rate limit tier: free (1 req/s) or paid (10 req/s) (default: free)")),
    mcp.WithBoolean("clear_cache",
        mcp.Description("Evict cached result for this IP before querying")),
    mcp.WithReadOnlyHintAnnotation(true),
)
```

Additional tool definitions:

```go
func countTool() mcp.Tool
func searchTool() mcp.Tool
func dnsResolveTool() mcp.Tool
func dnsReverseTool() mcp.Tool
```

> Verify exact `mcp-go` API for tool/parameter registration against the library's README or source.

---

### Step 8 — Deploy Assets (`deploy/shogunhound.service`)

Create the systemd unit file from DESIGN.md Section 11.4. Include it in the repo for future HTTP/SSE use — it is not needed for stdio-only deployment but belongs in the repo.

---

## Environment Variables

| Variable | Required | Default | Description |
|---|---|---|---|
| `SHODAN_API_KEY` | Yes | — | Shodan API key; never logged or written to disk |
| `CACHE_PATH` | No | `~/.shodan_cache.json` | Cache file path |
| `LOG_PATH` | No | `~/shodan_queries.log` | Audit log path |
| `MCP_PORT` | No | 8080 | Reserved; unused in this implementation |

---

## Testing Requirements

- Target: >80% coverage across all `internal/` packages.
- All tests must be hermetic — no real Shodan API calls. Use `net/http/httptest` for Shodan client tests.
- Run: `go test ./...`
- Manual checklist from DESIGN.md Section 10.4 must pass against the live Shodan API before release.

---

## Build

```bash
# Build
go build -ldflags "-X main.version=v2.3.0" -o shogunhound ./cmd/server

# Test
go test ./...

# Install
sudo mv shogunhound /usr/local/bin/shogunhound
sudo chmod +x /usr/local/bin/shogunhound
```

---

## Known Implementation Risks

1. **`mcp-go` API**: Verify method names for tool registration and server startup (e.g., `ServeStdio`) against the library's current README or source — MCP libraries are evolving quickly.
