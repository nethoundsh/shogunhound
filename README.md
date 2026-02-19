# shogunhound

**Shodan host intelligence as an MCP tool.**

shogunhound is an [MCP](https://modelcontextprotocol.io) server that gives LLM agents direct access to [Shodan's](https://shodan.io) host intelligence API. Query open ports, running services, banner data, geolocation, ASN, and known CVEs from inside a conversation — without switching to a browser or separate terminal.

Built for security analysts working ransomware recovery, OSINT research, and incident response. Part of the [nethound.sh](https://nethound.sh) open-source toolchain.

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 SHODAN HOST INTELLIGENCE — 1.1.1.1
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

IDENTITY
 Organization : APNIC and Cloudflare DNS Resolver project
 ISP          : APNIC
 ASN          : AS13335
 OS           : (unknown)
 Hostnames    : one.one.one.one
 Tags         : (none)
 Last Seen    : 2026-02-17

LOCATION
 Country : Australia
 City    : Sydney

VULNERABILITIES
 None detected

OPEN PORTS & SERVICES
 53/udp  dns-udp
 53/tcp  dns
 80/tcp  http    — cloudflare
 443/tcp https   — cloudflare
 2082/tcp http
 2083/tcp https
 8080/tcp http
 8443/tcp https

BANNERS
 Port 80: HTTP/1.1 301 Moved Permanently
```

---

## Table of Contents

- [How It Works](#how-it-works)
- [Use Cases](#use-cases)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
  - [MCP Server — Cursor over SSH](#mcp-server--cursor-over-ssh)
  - [MCP Server — Claude Code](#mcp-server--claude-code)
- [Tool Reference](#tool-reference)
- [Output Formats](#output-formats)
- [IP Validation](#ip-validation)
- [Caching](#caching)
- [Audit Logging](#audit-logging)
- [Security](#security)
- [Known Limitations](#known-limitations)
- [Development](#development)
- [Project Structure](#project-structure)
- [Contributing](#contributing)
- [Ethics](#ethics)
- [License](#license)

---

## How It Works

shogunhound runs as a subprocess on your VPS. An MCP client — Cursor, a terminal agent, or any MCP-compatible editor — communicates with it over stdin/stdout. When the LLM decides it needs host intelligence for an IP, it calls the `shodan_ip_query` tool directly. Results come back as formatted text or raw JSON, ready for the model to synthesize into recommendations or investigation notes.

```
Cursor (Remote SSH)
      │ stdio
      ▼
 shogunhound              ~/.shodan_cache.json
      │                   ~/shodan_queries.log
      │ HTTPS
      ▼
  api.shodan.io
```

The binary lives on the VPS. No open ports. No daemon to manage. The MCP client invokes it as a subprocess over your existing SSH session.

---

## Use Cases

1. **Ransomware recovery**
   During active recovery, quickly profile every public IP on a victim network. Check exposed services, recency, and CVEs before deep log triage.
   - "What ports were open on `203.0.113.45` and are there any known CVEs?"

2. **Penetration testing recon**
   In passive recon, enumerate exposed services and banners without sending packets to target infrastructure.
   - "How many hosts in `AS12345` are running an exposed RDP port?"

3. **Threat intelligence and attacker infrastructure profiling**
   Pivot from suspicious IPs in alerts and enrich with organization, ASN, and service profile details.
   - "What organization owns `185.220.101.34` and what services is it running?"

4. **Vulnerability management**
   Rapidly assess whether critical CVEs appear on known public IPs without waiting for a full scan cycle.
   - "Does `198.51.100.10` show signs of affected software and known CVEs?"

5. **Incident response triage**
   Reverse-resolve suspicious IPs, then profile their exposed services to prioritize escalation.
   - "Reverse DNS on `45.33.32.156`, then give me its full Shodan profile."

---

## Prerequisites

- A VPS running Linux (Ubuntu 22.04+ or Debian 12+ recommended)
- [Go 1.21+](https://go.dev/dl/)
- A [Shodan API key](https://account.shodan.io/) (free tier works; 1 req/s rate limit applies)
- `git`

---

## Installation

```bash
git clone https://github.com/nethoundsh/shogunhound
cd shogunhound
go build -ldflags "-X main.version=$(git describe --tags --always --dirty)" -o shogunhound ./cmd/server
sudo mv shogunhound /usr/local/bin/shogunhound
sudo chmod +x /usr/local/bin/shogunhound
```

Verify:

```bash
which shogunhound
# /usr/local/bin/shogunhound
```

---

## Configuration

shogunhound is configured entirely through environment variables. Add these to your `~/.bashrc` or `~/.zshrc` on the VPS:

```bash
export SHODAN_API_KEY="your_api_key_here"   # Required
export CACHE_PATH="$HOME/.shodan_cache.json" # Optional; this is the default
export LOG_PATH="$HOME/shodan_queries.log"   # Optional; this is the default
export SHODAN_TIER="free"                    # Optional; "paid" enables faster pacing defaults
```

| Variable | Required | Default | Description |
|---|---|---|---|
| `SHODAN_API_KEY` | **Yes** | — | Your Shodan API key. Never logged or written to disk. |
| `CACHE_PATH` | No | `~/.shodan_cache.json` | Path to the local result cache. |
| `LOG_PATH` | No | `~/shodan_queries.log` | Path to the audit log. |
| `SHODAN_TIER` | No | `free` | Default Shodan tier for client pacing (`free` or `paid`). |

Protect the log file after creation:

```bash
touch ~/shodan_queries.log
chmod 600 ~/shodan_queries.log
```

---

## Usage

### Future: HTTP/SSE Deployment

The `deploy/shogunhound.service` unit is included as an experimental future-facing asset. The current MVP is stdio-only, so this service file is not part of the supported runtime path yet.

### MCP Server — Cursor over SSH

This is the primary use case. Cursor's Remote SSH extension runs editor processes — including MCP servers — directly on the VPS. shogunhound is invoked as a subprocess over stdin/stdout; no extra server setup is needed.

**Add to your Cursor MCP config.** This file lives at either:

- Per-project: `.cursor/mcp.json` in your project root on the VPS
- Global: `~/.cursor/mcp.json` on the VPS

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

`${env:SHODAN_API_KEY}` pulls the value from your SSH session's shell environment. Make sure the variable is exported in your shell profile on the VPS before connecting.

**Verify the tool is available:**

1. Connect to your VPS via Cursor Remote SSH
2. Open Cursor Settings → MCP
3. `shogunhound` should appear as a connected server with `shodan_ip_query` listed
4. In the chat, ask: *"What ports are open on 8.8.8.8?"* — the agent will invoke `shodan_ip_query` automatically

**Troubleshooting:**

| Symptom | Likely Cause | Fix |
|---|---|---|
| Tool not appearing in MCP panel | Binary path wrong or not executable | Run `which shogunhound` in the SSH session; verify it matches the config path |
| `SHODAN_API_KEY not set` error | Env var not exported before Cursor connected | Add `export SHODAN_API_KEY=...` to `~/.bashrc` and reconnect |
| Tool visible but returns no data | API key invalid | Verify your key at https://account.shodan.io and restart the MCP server process |
| Server shown as disconnected | shogunhound crashed on startup | Check Cursor MCP logs; run the binary manually to see the error |

---

### MCP Server — Claude Code

Claude Code natively supports MCP stdio servers. `shogunhound` works without any modification.

> **Important:** `SHODAN_API_KEY` must be set persistently in your `~/.bashrc` or `~/.zshrc` — not just exported temporarily in a terminal session. Claude Code reads environment variables from your shell profile at startup. A one-off `export` in a terminal will not carry over to Claude Code or its MCP subprocesses.
>
> Add this to your `~/.bashrc` or `~/.zshrc` before proceeding:
> ```bash
> export SHODAN_API_KEY="your_api_key_here"
> ```
> Then reload your shell (`source ~/.bashrc` or open a new terminal) before running the commands below.

Add globally (available in all Claude Code sessions on this machine):

```bash
claude mcp add --transport stdio \
  --env SHODAN_API_KEY="${SHODAN_API_KEY}" \
  shogunhound -- /usr/local/bin/shogunhound
```

Or add to a project (checked into git, shared with the team) by creating `.mcp.json` in the repo root:

```json
{
  "mcpServers": {
    "shogunhound": {
      "type": "stdio",
      "command": "/usr/local/bin/shogunhound",
      "env": {
        "SHODAN_API_KEY": "${SHODAN_API_KEY}"
      }
    }
  }
}
```

Verify it is connected:

```bash
claude mcp list
# shogunhound   stdio   /usr/local/bin/shogunhound
```

Or inside a Claude Code session, run `/mcp` and confirm `shogunhound` appears as connected.

Using the investigation prompts:

```text
/mcp__shogunhound__investigate_ip ip=8.8.8.8
/mcp__shogunhound__recon query="org:\"Acme Corp\""
```

---

## Tool Reference

| Tool | Description | Tier |
|------|-------------|------|
| `shodan_ip_query` | Host intelligence for a single public IP | Free |
| `shodan_count` | Count hosts matching a search query | Free |
| `shodan_search` | Search hosts by query, returns list | Paid |
| `shodan_dns_resolve` | Resolve hostnames -> IPs via Shodan DNS | Free |
| `shodan_dns_reverse` | Reverse-resolve IPs -> hostnames via Shodan DNS | Free |
| `shodan_ip_query_bulk` | Bulk host lookups for multiple public IPs | Free/Paid |
| `shodan_cve_lookup` | CVE intelligence: host count + exploit availability | Free/Paid |
| `shodan_alert_create` | Create Shodan Monitor alert | Paid |
| `shodan_alert_list` | List Shodan Monitor alerts | Paid |
| `shodan_alert_delete` | Delete Shodan Monitor alert by ID | Paid |
| `shodan_report` | Multi-IP exposure report generation | Free/Paid |

---

**Tool name:** `shodan_ip_query`

**Description (as seen by the LLM):**
> Queries Shodan for public IP host intelligence: open ports, running services, banner data, organization, geolocation, and known CVEs. Returns structured findings for security analysis. For ethical, authorized use only. Comply with Shodan Terms of Service: https://www.shodan.io/about/terms

**Ask the agent:**
- "What ports are open on `8.8.8.8`?"
- "Give me the full Shodan profile for `45.33.32.156` as markdown."
- "Has this IP got any known CVEs: `185.220.101.34`?"

**Example parameters:**

```json
{
  "ip": "8.8.8.8",
  "format": "markdown",
  "history": false,
  "minify": false,
  "tier": "free",
  "clear_cache": false
}
```

**Example output (excerpt):**

```markdown
## Shodan Host Intelligence — 8.8.8.8
...
### Open Ports & Services
| Port | Transport | Module | Product/Version |
|------|-----------|--------|-----------------|
| 53 | udp | dns-udp | — |
```

**Parameters:**

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `ip` | string | **Yes** | — | Public IPv4 or IPv6 address to query |
| `format` | string | No | `pretty` | Output format: `pretty`, `markdown`, or `json` |
| `history` | boolean | No | `false` | Include historical banner data |
| `minify` | boolean | No | `false` | Omit banner strings from the response |
| `tier` | string | No | `free` | Rate limit tier: `free` or `paid` |
| `clear_cache` | boolean | No | `false` | Evict cached result before querying |

**Error responses** are returned as MCP tool errors with human-readable messages:

| Condition | Message |
|---|---|
| Invalid IP format | `invalid IP address: <input>` |
| Private or reserved IP | `IP <input> is not a public address and cannot be queried` |
| API key not set | `SHODAN_API_KEY not set; cannot query Shodan` |
| Authentication failure | `Shodan authentication failed; check your API key` |
| Rate limit exceeded | `Shodan rate limit exceeded; wait 60 seconds and retry` |
| IP not indexed by Shodan | `No Shodan data found for <ip>; host may not be indexed` |
| Query timeout | `Shodan query timed out after 4 seconds; try again` |
| Shodan API error | `Shodan API error; try again later` |

---

**Tool name:** `shodan_count`

**Description (as seen by the LLM):**
> Returns the number of Shodan-indexed hosts matching a search query. Use to assess scope before running a full search. Supports all Shodan search filters. Free tier compatible.

**Ask the agent:**
- "How many SSH servers are exposed in Germany right now?"
- "Before I search, how large is `vuln:CVE-2021-44228`?"

**Example parameters:**

```json
{
  "query": "port:22 country:US"
}
```

**Example output:**

```text
1842934 hosts match: port:22 country:US
```

**Parameters:**

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `query` | string | **Yes** | — | Shodan search query (e.g. `port:22 country:DE`, `vuln:CVE-2021-44228`) |

**Error responses** are returned as MCP tool errors with human-readable messages:

| Condition | Message |
|---|---|
| Authentication failure | `Shodan authentication failed; check your API key` |
| Rate limit exceeded | `Shodan rate limit exceeded; wait 60 seconds and retry` |
| Query timeout | `Shodan query timed out; try again` |
| Shodan API error | `Shodan API error; try again later` |

---

**Tool name:** `shodan_search`

**Description (as seen by the LLM):**
> Searches Shodan for hosts matching a query. Returns IP, organization, country, and open ports for each match. Requires a paid Shodan API key for most queries.

**Ask the agent:**
- "Find nginx servers in France."
- "Show me hosts with `CVE-2021-44228` at Hetzner, page 2, as markdown."

**Example parameters:**

```json
{
  "query": "port:22 country:DE org:Hetzner",
  "format": "pretty",
  "page": 1
}
```

**Example output:**

```text
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 SHODAN SEARCH — 24381 total results
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

 5.9.243.12    Hetzner Online GmbH    Germany    ports: 22
 78.46.120.44  Hetzner Online GmbH    Germany    ports: 22, 80, 443
```

**Parameters:**

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `query` | string | **Yes** | — | Shodan search query |
| `format` | string | No | `pretty` | Output format: `pretty`, `markdown`, or `json` |
| `page` | number | No | `1` | Result page (100 results per page) |

**Error responses** are returned as MCP tool errors with human-readable messages:

| Condition | Message |
|---|---|
| Authentication failure | `Shodan authentication failed; check your API key` |
| Rate limit exceeded | `Shodan rate limit exceeded; wait 60 seconds and retry` |
| Query timeout | `Shodan query timed out; try again` |
| Shodan API error | `Shodan API error; try again later` |

---

**Tool name:** `shodan_dns_resolve`

**Description (as seen by the LLM):**
> Resolves hostnames to IP addresses using Shodan's DNS database. Up to 100 hostnames per call.

**Ask the agent:**
- "What IPs do `google.com` and `cloudflare.com` resolve to?"
- "Resolve these domains: `example.com, github.com, microsoft.com`."

**Example parameters:**

```json
{
  "hostnames": "google.com,cloudflare.com,github.com"
}
```

**Example output:**

```text
google.com -> 142.250.80.46
cloudflare.com -> 104.16.133.229
github.com -> 140.82.121.4
```

**Parameters:**

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `hostnames` | string | **Yes** | — | Comma-separated hostnames (e.g. `google.com,cloudflare.com`). Max 100. |

**Error responses** are returned as MCP tool errors with human-readable messages:

| Condition | Message |
|---|---|
| Missing or empty hostname list | `missing required parameter: hostnames` or `hostnames must contain at least one entry` |
| Too many hostnames | `hostnames must not exceed 100 entries` |
| Authentication failure | `Shodan authentication failed; check your API key` |
| Rate limit exceeded | `Shodan rate limit exceeded; wait 60 seconds and retry` |
| Query timeout | `Shodan query timed out; try again` |
| Shodan API error | `Shodan API error; try again later` |

---

**Tool name:** `shodan_dns_reverse`

**Description (as seen by the LLM):**
> Looks up hostnames for IP addresses using Shodan's DNS database. Accepts only public IPs. Up to 100 IPs per call.

**Ask the agent:**
- "What hostname does `8.8.8.8` belong to?"
- "Reverse DNS lookup on `8.8.8.8` and `1.1.1.1`."

**Example parameters:**

```json
{
  "ips": "8.8.8.8,1.1.1.1"
}
```

**Example output:**

```text
8.8.8.8 -> dns.google
1.1.1.1 -> one.one.one.one
```

**Parameters:**

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `ips` | string | **Yes** | — | Comma-separated public IPv4/IPv6 addresses (e.g. `8.8.8.8,1.1.1.1`). Max 100. |

**Error responses** are returned as MCP tool errors with human-readable messages:

| Condition | Message |
|---|---|
| Missing or empty IP list | `missing required parameter: ips` or `ips must contain at least one entry` |
| Too many IPs | `ips must not exceed 100 entries` |
| Invalid/private IP | `invalid IP "<ip>": <validation message>` |
| Authentication failure | `Shodan authentication failed; check your API key` |
| Rate limit exceeded | `Shodan rate limit exceeded; wait 60 seconds and retry` |
| Query timeout | `Shodan query timed out; try again` |
| Shodan API error | `Shodan API error; try again later` |

---

## Output Formats

### Pretty (default)

Human-readable plain text output optimized for MCP tool responses.

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 SHODAN HOST INTELLIGENCE — 8.8.8.8
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

IDENTITY
 Organization : Google LLC
 ISP          : Google LLC
 ASN          : AS15169
 OS           : (unknown)
 Hostnames    : dns.google
 Tags         : (none)
 Last Seen    : 2026-02-17

LOCATION
 Country : United States
 City    : Mountain View

VULNERABILITIES
 None detected

OPEN PORTS & SERVICES
 53/udp  dns-udp
 443/tcp https

BANNERS
 Port 53: recursion available, EDNS version 0
```

### JSON

Structured output suitable for chaining with other tools and downstream LLM processing.

```json
{
 "IP": "8.8.8.8",
 "Organization": "Google LLC",
 "ISP": "Google LLC",
 "ASN": "AS15169",
 "Country": "United States",
 "City": "Mountain View",
 "OS": "",
 "Ports": [53, 443],
 "Hostnames": ["dns.google"],
 "Tags": [],
 "Vulnerabilities": [],
 "Services": [
  {
   "Port": 53,
   "Transport": "udp",
   "Module": "dns-udp",
   "Product": "",
   "Version": "",
   "Banner": "recursion available, EDNS version 0",
   "CPE": []
  }
 ],
 "LastSeen": "2026-02-17T00:00:00Z"
}
```

### Markdown

Markdown output is designed for direct rendering in chat surfaces and reports.

```markdown
## Shodan Host Intelligence — 8.8.8.8

**Organization:** Google LLC | **ISP:** Google LLC | **ASN:** AS15169
**Country:** United States | **City:** Mountain View
**OS:** (unknown) | **Last Seen:** 2026-02-17
**Hostnames:** dns.google
**Tags:** (none)

### Vulnerabilities

None detected.

### Open Ports & Services

| Port | Transport | Module | Product/Version |
|------|-----------|--------|-----------------|
| 53 | udp | dns-udp | — |
| 443 | tcp | https | — |
```

---

## IP Validation

All inputs are validated before any API call is made. The following ranges are rejected:

| Range | RFC | Reason |
|---|---|---|
| `127.0.0.0/8`, `::1` | — | Loopback |
| `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` | RFC 1918 | Private |
| `224.0.0.0/4` | — | Multicast |
| `0.0.0.0`, `::` | — | Unspecified |
| `169.254.0.0/16`, `fe80::/10` | — | Link-local |
| `100.64.0.0/10` | RFC 6598 | CGNAT |
| `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24` | RFC 5737 | TEST-NET |
| `240.0.0.0/4` | RFC 1112 | Reserved |

IPv4-mapped IPv6 addresses (e.g., `::ffff:192.168.1.1`) are correctly resolved to their IPv4 form before validation — the private range check catches them.

---

## Caching

Results are cached locally to reduce redundant API calls and support offline re-analysis.

- **Location:** `~/.shodan_cache.json` (configurable via `CACHE_PATH`)
- **TTL:** 24 hours from query time
- **Capacity:** 100 entries. When full, the oldest entry by query time is evicted.
- **Writes:** Atomic — results are written to a temp file and renamed to prevent corruption on crash.
- **Force refresh:** Pass `clear_cache=true` (MCP) to evict and re-query.

The cache is loaded into memory at startup. If the cache file is corrupt or unreadable, shogunhound starts cleanly with an empty cache and logs a warning to stderr.

---

## Audit Logging

Every query — cache hit or miss — produces a structured JSON log entry:

```json
{
  "time": "2026-02-18T14:22:01Z",
  "level": "INFO",
  "msg": "query",
  "ip": "8.8.8.8",
  "format": "pretty",
  "cache_hit": false,
  "duration_ms": 1243,
  "success": true,
  "error": ""
}
```

- **Location:** `~/shodan_queries.log` (configurable via `LOG_PATH`)
- **Format:** JSON lines, one record per query
- **Permissions:** The log file should be `chmod 600`. See [Security](#security).

The log is intentionally not anonymized. In an investigation context, knowing exactly what was queried and when is the point of an audit log.
The log is in JSON lines format (one JSON object per line, no surrounding array). Standard `jq` works directly on the file.

**Quick log analysis:**

```bash
# Cache hit rate
grep -c '"cache_hit":true' ~/shodan_queries.log
grep -c '"cache_hit":false' ~/shodan_queries.log

# All failed queries
jq 'select(.success == false)' ~/shodan_queries.log

# P95 latency estimate
jq '.duration_ms' ~/shodan_queries.log | sort -n | awk 'BEGIN{c=0} {a[c++]=$1} END{print a[int(c*0.95)]}'
```

---

## Security

### API Key

`SHODAN_API_KEY` is loaded from the environment only. It is never logged, written to disk, hardcoded, or included in error messages.

### Input Validation

All IP inputs are parsed with Go's `net.ParseIP` before any further processing. This rejects any non-IP string including those with shell metacharacters. No IP string is ever passed to a shell command.

### Audit Log

The log contains plaintext queried IPs. Protect it at the filesystem level:

```bash
chmod 600 ~/shodan_queries.log
```

**If you use shogunhound during client engagements** where queried IPs are sensitive, treat the log as sensitive case material:

- Run shogunhound locally rather than on a shared VPS
- Rotate and delete logs after each engagement
- Consider encrypting the log directory at rest

### Exposed Attack Surface

The primary (stdio) deployment model requires no open ports. The binary is invoked as a subprocess over your SSH session. There is no network listener to attack.

---

## Known Limitations

**Bulk query is summary-first.**
`shodan_ip_query_bulk` optimizes for breadth and quick triage. For deep per-host analysis, follow up with `shodan_ip_query` on specific IPs.

**`shodan_ip_query` requires IP addresses.**
The `ip` parameter only accepts IPv4 or IPv6 addresses — not hostnames. Use `shodan_dns_resolve` to resolve a hostname to an IP first, then query it.

---

## Development

### Build

```bash
# Development build
go build -o shogunhound ./cmd/server

# Release build (with version embedded)
go build -ldflags "-X main.version=$(git describe --tags --always --dirty)" -o shogunhound ./cmd/server
```

### Test

```bash
go test ./...
```

All tests are hermetic — no live Shodan API calls are made. The Shodan client tests use `net/http/httptest` to mock API responses. Expected output:

```
ok  github.com/nethoundsh/shogunhound/internal/cache       (8 tests)
ok  github.com/nethoundsh/shogunhound/internal/formatter   (5 tests)
ok  github.com/nethoundsh/shogunhound/internal/shodan      (6 tests)
ok  github.com/nethoundsh/shogunhound/internal/validator   (23 subtests)
```

> The `shodan` package tests take ~5 seconds. This is expected: the timeout test waits for a 4-second context deadline to elapse.

### Manual Testing Checklist

Run these against a real `SHODAN_API_KEY` before tagging a release:

```
[ ] MCP call ip=8.8.8.8 format=pretty            → Google DNS host data
[ ] MCP call ip=1.1.1.1 format=pretty            → Cloudflare host data
[ ] MCP call ip=192.168.1.1                      → validation error (private)
[ ] MCP call ip=not-an-ip                        → validation error (invalid)
[ ] MCP call ip=8.8.8.8 twice                    → cache hit on second call (cache_hit=true)
[ ] MCP call ip=8.8.8.8 clear_cache=true         → fresh API call (cache_hit=false)
[ ] MCP call ip=8.8.8.8 format=json              → valid JSON output
[ ] shodan_ip_query ip=8.8.8.8 format=markdown   → renders markdown table
[ ] shodan_count query="port:22 country:US"      → returns integer
[ ] shodan_search query="port:22 country:US" page=1 → returns list of hosts
[ ] shodan_dns_resolve hostnames="google.com,cloudflare.com" → IPs returned
[ ] shodan_dns_reverse ips="8.8.8.8,1.1.1.1"     → hostnames returned
[ ] shodan_dns_reverse ips="192.168.1.1"         → validation error (private IP)
[ ] shodan_count query="invalid::query::"        → graceful error, not panic
[ ] Kill network mid-query             → timeout error within 4 seconds
[ ] Corrupt cache file, restart        → starts cleanly, cache rebuilt from scratch
```

---

## Project Structure

```
shogunhound/
├── cmd/
│   └── server/
│       └── main.go              # Entry point: MCP stdio server startup
├── internal/
│   ├── validator/
│   │   ├── validator.go         # IP validation (public ranges only)
│   │   └── validator_test.go
│   ├── cache/
│   │   ├── cache.go             # Local JSON cache with atomic writes
│   │   └── cache_test.go
│   ├── shodan/
│   │   ├── model.go             # ShodanHostResult and ServiceRecord types
│   │   ├── client.go            # go-shodan wrapper with timeout and rate limiting
│   │   └── client_test.go
│   ├── formatter/
│   │   ├── formatter.go         # Pretty, markdown, and JSON output formatters
│   │   └── formatter_test.go
│   └── handler/
│       └── handler.go           # MCP tool handler, audit logger, error humanizer
├── deploy/
│   └── shogunhound.service      # systemd unit (for future HTTP/SSE deployment)
├── DESIGN.md                    # Full technical design document
├── AGENTS.md                    # Implementation instructions (used during development)
├── go.mod
└── go.sum
```

---

## Contributing

Contributions are welcome. Please open an issue before submitting a pull request for non-trivial changes.

**Areas actively looking for contributions:**

- Fix for the [Tags field limitation](#known-limitations) (custom decode envelope around `go-shodan`)
- Handler integration tests
- IPv6 end-to-end testing against the live Shodan API
- Docker image / GHCR publish workflow

See `DESIGN.md` for full architectural context and `AGENTS.md` for component-level implementation notes.

---

## Ethics

shogunhound is designed for defensive security research on public infrastructure.

- Only publicly routable IPs can be queried (enforced in code, not just policy)
- All queries are logged for audit purposes
- The tool description shown to the LLM includes a reference to Shodan's Terms of Service

Users are responsible for ensuring their use of Shodan data complies with applicable law and [Shodan's Terms of Service](https://www.shodan.io/about/terms). This tool is not appropriate for offensive reconnaissance against systems you do not own or have explicit authorization to assess.

---

## License

MIT — see [LICENSE](LICENSE).

---

*shogunhound is part of the [nethound.sh](https://nethound.sh) open-source OSINT toolchain.*
