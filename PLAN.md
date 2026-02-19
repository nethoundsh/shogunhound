# shogunhound — Implementation Plan: MCP Server Improvements

## Before Starting

Read `DESIGN.md` and `AGENTS.md` for context. Run `go test ./...` to confirm the baseline passes before touching any code.

All library API details in this plan have been verified against the actual source at:
- `/home/nethound/go/pkg/mod/github.com/ns3777k/go-shodan/v4@v4.2.0/shodan/`
- `/home/nethound/go/pkg/mod/github.com/mark3labs/mcp-go@v0.44.0/mcp/`

Implement the parts in order. Run `go test ./...` after each part.

---

## Part 1: AGENTS.md Accuracy Fixes

File: `AGENTS.md`
Doc-only changes — no code. Make these first.

### 1a. Fix `Vulns` mapping description (around line 291)

Replace:
```
- `Vulns` in go-shodan is `map[string]<type>` — extract map keys as CVE ID strings, sort with `sort.Strings`.
```
With:
```
- `Vulnerabilities` is `[]string` on the embedded `goshodan.Host` — assign directly and sort with `sort.Strings`.
```

### 1b. Fix `Module` extraction description (around line 292)

Replace:
```
- `Module`: in go-shodan's `Banner` struct, the module is at `banner.Shodan.Module` — verify field name against library source before implementing.
```
With:
```
- `Module`: extracted from `data.ShodanData["module"]` (a `map[string]interface{}` field named `_shodan` in the API response) via the `moduleFromShodanData()` helper.
```

### 1c. Fix error mapping description (around lines 296–301)

Replace the entire error mapping block:
```
5. Error mapping:
   - HTTP 401 → `ErrUnauthorized`
   - HTTP 429 → `ErrRateLimited`
   - HTTP 404 → `ErrNotFound`
   - `context.DeadlineExceeded` or `context.Canceled` → return as-is
   - Other non-2xx → `fmt.Errorf("shodan API error (%d)", statusCode)`
```
With:
```
5. Error mapping via `mapAPIError(err error) error`:
   - `errors.Is(err, context.DeadlineExceeded/Canceled)` → return as-is
   - `strings.Contains(msg, "401")` or `"invalid api key"` or `"unauthorized"` → `ErrUnauthorized`
   - `strings.Contains(msg, "429")` or `"rate limit"` → `ErrRateLimited`
   - `strings.Contains(msg, "404")` or `"no information available for that ip"` → `ErrNotFound`
   - default → `fmt.Errorf("shodan API error: %w", err)`
   Where `msg = strings.ToLower(strings.TrimSpace(err.Error()))`.
```

Also remove the note below that block:
```
> **Note:** Inspect `go-shodan/v4`'s actual struct definitions before coding the field mapping. The library's type for `Vulns` and the nested `Shodan` struct inside `Banner` are the two most likely sources of surprise.
```

### 1d. Fix parameter extraction API (around line 410)

Replace:
```
**Parameter extraction** from `req.Params.Arguments`:
```
With:
```
**Parameter extraction** via `req.GetArguments()`:
```

### 1e. Remove Known Implementation Risk #1

Find and delete (around lines 608–610):
```
1. **`go-shodan` struct fields**: Inspect the library's actual types before implementing the field mapping in `client.go`. Specifically verify:
   - How `Vulns` is typed (likely `map[string]interface{}` — extract keys)
   - Where `Module` is nested inside `Banner` (likely `banner.Shodan.Module`)
```

Renumber the remaining risk as #1:
```
1. **`mcp-go` API**: Verify method names for tool registration and server startup...
```

---

## Part 2: Tool Annotations

File: `cmd/server/main.go`

In `mcpTool()`, add `WithReadOnlyHintAnnotation(true)` as the last option in the `mcp.NewTool(...)` call:

```go
func mcpTool() mcp.Tool {
    return mcp.NewTool("shodan_ip_query",
        mcp.WithDescription("..."),     // existing, unchanged
        mcp.WithString("ip", ...),      // existing, unchanged
        mcp.WithString("format", ...),  // existing, unchanged
        mcp.WithBoolean("history", ...), // existing, unchanged
        mcp.WithBoolean("minify", ...),  // existing, unchanged
        mcp.WithString("tier", ...),     // existing, unchanged
        mcp.WithBoolean("clear_cache", ...), // existing, unchanged
        mcp.WithReadOnlyHintAnnotation(true),
    )
}
```

> **Note:** The correct function is `mcp.WithReadOnlyHintAnnotation(bool)` — NOT `mcp.WithAnnotation(mcp.ToolAnnotation{...})`.

Also update the `format` parameter description while you're in this file:
```go
mcp.WithString("format",
    mcp.Description("Output format: pretty (plain text), markdown, or json (default: pretty)")),
```

Verify: `go build ./...` passes.

---

## Part 3: Markdown Output Format

### 3a. `internal/formatter/formatter.go`

Add a `"markdown"` branch to `Format()` before the default (pretty) case:

```go
func Format(result *shodan.ShodanHostResult, format string) string {
    switch format {
    case "json":
        // existing JSON branch — unchanged
    case "markdown":
        if result == nil {
            result = &shodan.ShodanHostResult{}
        }
        return formatMarkdown(result)
    default:
        // existing pretty branch — unchanged
    }
}
```

Implement `formatMarkdown(result *shodan.ShodanHostResult) string` producing:

```
## Shodan Host Intelligence — <IP>

**Organization:** <org> | **ISP:** <isp> | **ASN:** <asn>
**Country:** <country> | **City:** <city>
**OS:** <os> | **Last Seen:** <YYYY-MM-DD>
**Hostnames:** <comma-separated or none>
**Tags:** <comma-separated or none>

### Vulnerabilities

- CVE-XXXX-YYYY
- CVE-XXXX-ZZZZ

(or "None detected." if empty)

### Open Ports & Services

| Port | Transport | Module | Product/Version |
|------|-----------|--------|----------------|
| 443 | tcp | https | nginx 1.25.0 |

(or "None indexed." if empty)

### Banners          ← omit entire section if all banners are empty

**Port 443:** <banner text, first 200 chars>
```

Rules:
- Use `valueOr()`, `joinOr()`, `dateOrUnknown()` helpers (already in the package).
- Each field falls back to `(unknown)` or `(none)` using the existing helpers.
- Banner section is omitted entirely when all banners are empty (same logic as pretty format — use `collectBanners()`).
- CVEs are prefixed with `- `.
- Table row for services: `| <port> | <transport> | <module> | <product version or —> |`

### 3b. `internal/formatter/formatter.go` — Add `FormatSearchResult()`

Add a new exported function for search results (needed by Part 4):

```go
type SearchResult interface{ ... }  // use the actual shodan.SearchResult type
```

```go
func FormatSearchResult(result *shodan.SearchResult, format string) string {
    if result == nil {
        return ""
    }
    switch format {
    case "json":
        out, err := json.MarshalIndent(result, "", " ")
        if err != nil {
            return "{}"
        }
        return string(out)
    case "markdown":
        return formatSearchResultMarkdown(result)
    default:
        return formatSearchResultPretty(result)
    }
}
```

`formatSearchResultPretty()` output shape:
```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 SHODAN SEARCH — <N> total results
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

 <IP>  <org>  <country>  ports: <comma-separated>
 ...
```

`formatSearchResultMarkdown()` output shape:
```markdown
## Shodan Search Results — <N> total

| IP | Organization | Country | Ports |
|----|-------------|---------|-------|
| x.x.x.x | Acme Corp | US | 22, 80, 443 |
```

For ports in search results: use `strconv.Itoa` on each port in `result.Matches[i].Ports` joined with `", "`.

### 3c. `internal/formatter/formatter_test.go`

Add two new tests:

```go
func TestFormatMarkdownWithCVEs(t *testing.T) {
    result := &shodan.ShodanHostResult{
        IP:              "8.8.8.8",
        Organization:    "Google LLC",
        Vulnerabilities: []string{"CVE-2021-44228", "CVE-2024-0001"},
        Services: []shodan.ServiceRecord{
            {Port: 443, Transport: "tcp", Module: "https", Product: "nginx", Version: "1.25.0"},
        },
        LastSeen: time.Date(2026, 2, 17, 0, 0, 0, 0, time.UTC),
    }
    out := Format(result, "markdown")
    if !strings.Contains(out, "## Shodan Host Intelligence") {
        t.Fatalf("missing markdown header: %q", out)
    }
    if !strings.Contains(out, "CVE-2021-44228") {
        t.Fatalf("missing CVE: %q", out)
    }
    if !strings.Contains(out, "| 443 |") {
        t.Fatalf("missing services table row: %q", out)
    }
}

func TestFormatMarkdownNoPanic(t *testing.T) {
    t.Parallel()
    _ = Format(nil, "markdown")
    _ = Format(&shodan.ShodanHostResult{}, "markdown")
}
```

---

## Part 4: New Shodan Tools

All new tools follow the same pattern as `shodan_ip_query`:
1. Add method to `ShodanClient` in `internal/shodan/client.go`
2. Add handler method to `ToolHandler` in `internal/handler/handler.go`
3. Register the tool in `cmd/server/main.go`
4. Add client tests in `internal/shodan/client_test.go`

### Verified go-shodan API signatures (from library source)

```go
// Count
func (c *Client) GetHostsCountForQuery(ctx context.Context, options *HostQueryOptions) (*HostMatch, error)
// HostMatch.Total is int; HostQueryOptions.Query is string

// Search
func (c *Client) GetHostsForQuery(ctx context.Context, options *HostQueryOptions) (*HostMatch, error)
// HostMatch.Matches is []*HostData — NOT a Host-embedding struct; it IS HostData directly
// HostData fields relevant for mapping:
//   IP           net.IP                 (ip_str)
//   Organization string                 (org)
//   ISP          string                 (isp)
//   ASN          string                 (asn)
//   OS           string
//   Port         int                    (single port, not a slice)
//   Hostnames    []string
//   Product      string
//   Version      IntString
//   Transport    string
//   CPE          []string
//   Data         string                 (banner text)
//   Banner       string
//   ShodanData   map[string]interface{} (_shodan)
//   Location     *HostLocation          → .Country, .City

// DNS Resolve
func (c *Client) GetDNSResolve(ctx context.Context, hostnames []string) (map[string]*net.IP, error)
// Returns map[string]*net.IP — guard for nil pointer before calling .String()

// DNS Reverse
func (c *Client) GetDNSReverse(ctx context.Context, ip []net.IP) (map[string]*[]string, error)
// Takes []net.IP — parse strings with net.ParseIP() before calling
// Returns map[string]*[]string — guard for nil pointer before dereferencing
```

---

### Tool 4a: `shodan_count`

#### `internal/shodan/client.go`

```go
func (c *ShodanClient) Count(ctx context.Context, query string) (int, error) {
    ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
    defer cancel()

    result, err := c.client.GetHostsCountForQuery(ctx, &goshodan.HostQueryOptions{Query: query})
    if err != nil {
        return 0, mapAPIError(err)
    }
    return result.Total, nil
}
```

#### `internal/handler/handler.go`

Add `humanizeSearchError()` function (used by all new handlers):

```go
func humanizeSearchError(err error) string {
    switch {
    case errors.Is(err, shodan.ErrUnauthorized):
        return "Shodan authentication failed; check your API key"
    case errors.Is(err, shodan.ErrRateLimited):
        return "Shodan rate limit exceeded; wait 60 seconds and retry"
    case errors.Is(err, context.DeadlineExceeded):
        return "Shodan query timed out; try again"
    default:
        return "Shodan API error; try again later"
    }
}
```

Add handler:

```go
func (h *ToolHandler) HandleShodanCount(
    ctx context.Context,
    req mcp.CallToolRequest,
) (*mcp.CallToolResult, error) {
    query, ok := req.GetArguments()["query"].(string)
    if !ok || strings.TrimSpace(query) == "" {
        return mcp.NewToolResultError("missing required parameter: query"), nil
    }

    count, err := h.shodan.Count(ctx, query)
    if err != nil {
        return mcp.NewToolResultError(humanizeSearchError(err)), nil
    }

    return mcp.NewToolResultText(fmt.Sprintf("%d hosts match: %s", count, query)), nil
}
```

#### `cmd/server/main.go`

```go
func countTool() mcp.Tool {
    return mcp.NewTool("shodan_count",
        mcp.WithDescription("Returns the number of Shodan-indexed hosts matching a search query. "+
            "Use to assess scope before a full search. Supports all Shodan search filters. "+
            "For ethical, authorized use only. Free tier compatible."),
        mcp.WithString("query",
            mcp.Required(),
            mcp.Description("Shodan search query (e.g. 'port:22 country:DE', 'vuln:CVE-2021-44228', 'asn:AS15169 nginx')")),
        mcp.WithReadOnlyHintAnnotation(true),
    )
}
```

#### `internal/shodan/client_test.go`

```go
func TestCountSuccess(t *testing.T) {
    t.Parallel()

    server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        if !strings.Contains(r.URL.Path, "count") {
            http.Error(w, "wrong path", http.StatusBadRequest)
            return
        }
        w.Header().Set("Content-Type", "application/json")
        _, _ = w.Write([]byte(`{"total": 42}`))
    }))
    defer server.Close()

    client := NewClient("test-key", "free")
    client.client.BaseURL = server.URL

    count, err := client.Count(context.Background(), "nginx")
    if err != nil {
        t.Fatalf("Count() error = %v", err)
    }
    if count != 42 {
        t.Fatalf("Count() = %d, want 42", count)
    }
}

func TestCountUnauthorized(t *testing.T) {
    t.Parallel()
    client := newTestClientWithStatus(t, http.StatusUnauthorized)
    _, err := client.Count(context.Background(), "nginx")
    if !errors.Is(err, ErrUnauthorized) {
        t.Fatalf("error = %v, want ErrUnauthorized", err)
    }
}
```

---

### Tool 4b: `shodan_search`

#### `internal/shodan/client.go`

Add the result type:

```go
type SearchResult struct {
    Total   int
    Matches []*ShodanHostResult
}
```

Add a helper for mapping `HostData` to `ShodanHostResult` (search results have one port per record):

```go
func mapHostDataToResult(data *goshodan.HostData) *ShodanHostResult {
    r := &ShodanHostResult{
        Organization: data.Organization,
        ISP:          data.ISP,
        ASN:          data.ASN,
        OS:           data.OS,
        Hostnames:    append([]string(nil), data.Hostnames...),
        Ports:        []int{data.Port},
    }

    r.IP = data.IP.String()

    if data.Location != nil {
        r.Country = data.Location.Country
        r.City = data.Location.City
    }

    banner := data.Data
    if banner == "" {
        banner = data.Banner
    }

    version := ""
    if v := data.Version.String(); v != "" {
        version = v
    }

    r.Services = []ServiceRecord{{
        Port:      data.Port,
        Transport: data.Transport,
        Module:    moduleFromShodanData(data.ShodanData),
        Product:   data.Product,
        Version:   version,
        Banner:    banner,
        CPE:       append([]string(nil), data.CPE...),
    }}

    return r
}
```

Add the method:

```go
func (c *ShodanClient) Search(ctx context.Context, query string, page int) (*SearchResult, error) {
    ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
    defer cancel()

    if page < 1 {
        page = 1
    }

    result, err := c.client.GetHostsForQuery(ctx, &goshodan.HostQueryOptions{
        Query: query,
        Page:  page,
    })
    if err != nil {
        return nil, mapAPIError(err)
    }

    sr := &SearchResult{Total: result.Total}
    for _, match := range result.Matches {
        if match == nil {
            continue
        }
        sr.Matches = append(sr.Matches, mapHostDataToResult(match))
    }

    return sr, nil
}
```

#### `internal/handler/handler.go`

```go
func (h *ToolHandler) HandleShodanSearch(
    ctx context.Context,
    req mcp.CallToolRequest,
) (*mcp.CallToolResult, error) {
    query, ok := req.GetArguments()["query"].(string)
    if !ok || strings.TrimSpace(query) == "" {
        return mcp.NewToolResultError("missing required parameter: query"), nil
    }

    format, err := optionalString(req.GetArguments(), "format", "pretty")
    if err != nil {
        return mcp.NewToolResultError(err.Error()), nil
    }

    page := 1
    if p, ok := req.GetArguments()["page"].(float64); ok && p >= 1 {
        page = int(p)
    }

    result, err := h.shodan.Search(ctx, query, page)
    if err != nil {
        h.logger.Info("search", "query", query, "format", format, "success", false, "error", err.Error())
        return mcp.NewToolResultError(humanizeSearchError(err)), nil
    }

    h.logger.Info("search", "query", query, "format", format, "success", true, "error", "")
    return mcp.NewToolResultText(formatter.FormatSearchResult(result, format)), nil
}
```

#### `cmd/server/main.go`

```go
func searchTool() mcp.Tool {
    return mcp.NewTool("shodan_search",
        mcp.WithDescription("Searches Shodan for hosts matching a query. Returns IP, organization, "+
            "country, and open ports for each match. Supports all Shodan search filters and facets. "+
            "Requires a paid Shodan API key for most queries. "+
            "For ethical, authorized use only. Comply with Shodan Terms of Service: https://www.shodan.io/about/terms"),
        mcp.WithString("query",
            mcp.Required(),
            mcp.Description("Shodan search query (e.g. 'port:22 country:DE', 'vuln:CVE-2021-44228 org:\"Acme Corp\"')")),
        mcp.WithString("format",
            mcp.Description("Output format: pretty, markdown, or json (default: pretty)")),
        mcp.WithNumber("page",
            mcp.Description("Result page number, 100 results per page (default: 1)")),
        mcp.WithReadOnlyHintAnnotation(true),
    )
}
```

---

### Tool 4c: `shodan_dns_resolve`

#### `internal/shodan/client.go`

```go
func (c *ShodanClient) DNSResolve(ctx context.Context, hostnames []string) (map[string]string, error) {
    ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
    defer cancel()

    result, err := c.client.GetDNSResolve(ctx, hostnames)
    if err != nil {
        return nil, mapAPIError(err)
    }

    // GetDNSResolve returns map[string]*net.IP — convert to map[string]string
    out := make(map[string]string, len(result))
    for hostname, ip := range result {
        if ip == nil {
            out[hostname] = ""
            continue
        }
        out[hostname] = ip.String()
    }
    return out, nil
}
```

#### `internal/handler/handler.go`

Add the package-level helper (shared by both DNS handlers):

```go
// splitAndTrim splits a comma-separated string and trims whitespace from each element.
func splitAndTrim(s string) []string {
    parts := strings.Split(s, ",")
    out := make([]string, 0, len(parts))
    for _, p := range parts {
        if p = strings.TrimSpace(p); p != "" {
            out = append(out, p)
        }
    }
    return out
}
```

Add the handler:

```go
func (h *ToolHandler) HandleShodanDNSResolve(
    ctx context.Context,
    req mcp.CallToolRequest,
) (*mcp.CallToolResult, error) {
    raw, ok := req.GetArguments()["hostnames"].(string)
    if !ok || strings.TrimSpace(raw) == "" {
        return mcp.NewToolResultError("missing required parameter: hostnames"), nil
    }

    hostnames := splitAndTrim(raw)
    if len(hostnames) == 0 {
        return mcp.NewToolResultError("hostnames must contain at least one entry"), nil
    }
    if len(hostnames) > 100 {
        return mcp.NewToolResultError("hostnames must not exceed 100 entries"), nil
    }

    result, err := h.shodan.DNSResolve(ctx, hostnames)
    if err != nil {
        return mcp.NewToolResultError(humanizeSearchError(err)), nil
    }

    var b strings.Builder
    for _, hostname := range hostnames {
        if ip, ok := result[hostname]; ok && ip != "" {
            fmt.Fprintf(&b, "%s → %s\n", hostname, ip)
        } else {
            fmt.Fprintf(&b, "%s → (not found)\n", hostname)
        }
    }
    return mcp.NewToolResultText(b.String()), nil
}
```

#### `cmd/server/main.go`

```go
func dnsResolveTool() mcp.Tool {
    return mcp.NewTool("shodan_dns_resolve",
        mcp.WithDescription("Resolves hostnames to IP addresses using Shodan's DNS database. "+
            "Accepts up to 100 hostnames per call. Faster than live DNS for Shodan-indexed domains."),
        mcp.WithString("hostnames",
            mcp.Required(),
            mcp.Description("Comma-separated list of hostnames to resolve (e.g. 'google.com,cloudflare.com')")),
        mcp.WithReadOnlyHintAnnotation(true),
    )
}
```

---

### Tool 4d: `shodan_dns_reverse`

#### `internal/shodan/client.go`

```go
func (c *ShodanClient) DNSReverse(ctx context.Context, ips []string) (map[string][]string, error) {
    ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
    defer cancel()

    // GetDNSReverse takes []net.IP — parse each string first
    netIPs := make([]net.IP, 0, len(ips))
    for _, ipStr := range ips {
        parsed := net.ParseIP(ipStr)
        if parsed == nil {
            return nil, fmt.Errorf("invalid IP address: %s", ipStr)
        }
        netIPs = append(netIPs, parsed)
    }

    result, err := c.client.GetDNSReverse(ctx, netIPs)
    if err != nil {
        return nil, mapAPIError(err)
    }

    // GetDNSReverse returns map[string]*[]string — dereference the pointer
    out := make(map[string][]string, len(result))
    for ip, hostnames := range result {
        if hostnames == nil {
            out[ip] = nil
            continue
        }
        out[ip] = append([]string(nil), *hostnames...)
    }
    return out, nil
}
```

> **Important:** `DNSReverse` in `client.go` does NOT re-validate that IPs are public — the handler does that before calling. Do not add duplicate validation here.

#### `internal/handler/handler.go`

```go
func (h *ToolHandler) HandleShodanDNSReverse(
    ctx context.Context,
    req mcp.CallToolRequest,
) (*mcp.CallToolResult, error) {
    raw, ok := req.GetArguments()["ips"].(string)
    if !ok || strings.TrimSpace(raw) == "" {
        return mcp.NewToolResultError("missing required parameter: ips"), nil
    }

    ips := splitAndTrim(raw)
    if len(ips) == 0 {
        return mcp.NewToolResultError("ips must contain at least one entry"), nil
    }
    if len(ips) > 100 {
        return mcp.NewToolResultError("ips must not exceed 100 entries"), nil
    }

    // Validate each IP is a valid public address before querying
    for _, ip := range ips {
        if err := validator.ValidateIP(ip); err != nil {
            return mcp.NewToolResultError(fmt.Sprintf("invalid IP %q: %s", ip, err.Error())), nil
        }
    }

    result, err := h.shodan.DNSReverse(ctx, ips)
    if err != nil {
        return mcp.NewToolResultError(humanizeSearchError(err)), nil
    }

    var b strings.Builder
    for _, ip := range ips {
        if hostnames, ok := result[ip]; ok && len(hostnames) > 0 {
            fmt.Fprintf(&b, "%s → %s\n", ip, strings.Join(hostnames, ", "))
        } else {
            fmt.Fprintf(&b, "%s → (none)\n", ip)
        }
    }
    return mcp.NewToolResultText(b.String()), nil
}
```

#### `cmd/server/main.go`

```go
func dnsReverseTool() mcp.Tool {
    return mcp.NewTool("shodan_dns_reverse",
        mcp.WithDescription("Looks up hostnames for IP addresses using Shodan's DNS database. "+
            "Accepts up to 100 IPs per call. Only queries public IPs."),
        mcp.WithString("ips",
            mcp.Required(),
            mcp.Description("Comma-separated list of public IPv4 or IPv6 addresses (e.g. '8.8.8.8,1.1.1.1')")),
        mcp.WithReadOnlyHintAnnotation(true),
    )
}
```

---

## Part 5: Update `main()` Registration

`cmd/server/main.go` — update `main()` to register all tools:

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

---

## Part 6: Update Documentation

### `AGENTS.md`

- **Step 4**: Add `Count()`, `Search()`, `DNSResolve()`, `DNSReverse()` client method descriptions. Add `mapHostDataToResult()` helper note.
- **Step 6**: Add `HandleShodanCount`, `HandleShodanSearch`, `HandleShodanDNSResolve`, `HandleShodanDNSReverse` handler descriptions. Add `humanizeSearchError()` and `splitAndTrim()` helper notes.
- **Step 7**: Add `countTool()`, `searchTool()`, `dnsResolveTool()`, `dnsReverseTool()` snippets to match implementation. Update `mcpTool()` snippet with `WithReadOnlyHintAnnotation`.

### `README.md`

Update the Tool Reference table to add the four new tools:

| Tool | Description | Tier |
|------|-------------|------|
| `shodan_ip_query` | Host intelligence for a single public IP | Free |
| `shodan_count` | Count hosts matching a search query | Free |
| `shodan_search` | Search hosts by query, returns list | Paid |
| `shodan_dns_resolve` | Resolve hostnames → IPs via Shodan DNS | Free |
| `shodan_dns_reverse` | Reverse-resolve IPs → hostnames via Shodan DNS | Free |

Add markdown format to the Output Formats section with a short example.

Add entries to the Manual Testing Checklist:
```
[ ] shodan_ip_query ip=8.8.8.8 format=markdown     → renders markdown table
[ ] shodan_count query="port:22 country:US"         → returns integer
[ ] shodan_search query="port:22 country:US" page=1 → returns list of hosts
[ ] shodan_dns_resolve hostnames="google.com,cloudflare.com" → IPs returned
[ ] shodan_dns_reverse ips="8.8.8.8,1.1.1.1"       → hostnames returned
[ ] shodan_dns_reverse ips="192.168.1.1"            → validation error (private IP)
[ ] shodan_count query="invalid::query::"           → graceful error, not panic
```

---

## Imports to Add

### `internal/shodan/client.go`
- `"net"` — for `net.IP`, `net.ParseIP()`

### `internal/handler/handler.go`
- `"github.com/nethoundsh/shogunhound/internal/formatter"` is already imported
- `"github.com/nethoundsh/shogunhound/internal/validator"` is already imported

### `internal/formatter/formatter.go`
- `"strconv"` — for `strconv.Itoa()` in search result formatting

---

## Checklist

After each part, run `go test ./...` and confirm it passes.

- [ ] Part 1: AGENTS.md doc fixes — `go test ./...` passes
- [ ] Part 2: `WithReadOnlyHintAnnotation` added — `go build ./...` passes
- [ ] Part 3: Markdown format + tests — `go test ./...` passes
- [ ] Part 4a: `shodan_count` — `go test ./...` passes
- [ ] Part 4b: `shodan_search` — `go test ./...` passes
- [ ] Part 4c: `shodan_dns_resolve` — `go test ./...` passes
- [ ] Part 4d: `shodan_dns_reverse` — `go test ./...` passes
- [ ] Part 5: `main()` updated — `go build ./...` passes
- [ ] Part 6: Docs updated
