# shogunhound
[![CI](https://github.com/nethoundsh/shogunhound/actions/workflows/ci.yml/badge.svg)](https://github.com/nethoundsh/shogunhound/actions/workflows/ci.yml)

**Shodan host intelligence as an MCP tool.**

shogunhound is an [MCP](https://modelcontextprotocol.io) server that gives LLM agents direct access to [Shodan's](https://shodan.io) host intelligence API. Query open ports, running services, banner data, geolocation, ASN, and known CVEs from inside a conversation without switching to a browser or separate terminal.

Built for security analysts working in ransomware recovery, OSINT research, and incident response. It is part of the [nethound.sh](https://nethound.sh) open-source toolchain.

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
 Last Seen    : 2026-02-17 (recent)

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

## Quick start

```bash
# 1. Install
git clone https://github.com/nethoundsh/shogunhound && cd shogunhound
go build -o shogunhound ./cmd/server && sudo mv shogunhound /usr/local/bin/

# 2. Configure
export SHODAN_API_KEY="your_key_here"  # add to ~/.bashrc to persist
export SHODAN_TIER="free"              # optional; use "paid" for faster pacing defaults

# 3. Add to Claude Code
claude mcp add --transport stdio \
  --env SHODAN_API_KEY="${SHODAN_API_KEY}" \
  --env SHODAN_TIER="${SHODAN_TIER}" \
  shogunhound -- /usr/local/bin/shogunhound

# 4. Query
# In Claude Code: "What ports are open on 8.8.8.8?"
```

---

## Table of Contents

- [Quick start](#quick-start)
- [How It Works](#how-it-works)
- [Use Cases](#use-cases)
- [Workflow Examples](#workflow-examples)
- [Versioning and Support Policy](#versioning-and-support-policy)
- [Compatibility](#compatibility)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
  - [Build from Source](#build-from-source)
  - [Docker](#docker)
- [Configuration](#configuration)
- [Usage](#usage)
  - [MCP Server — Cursor over SSH](#mcp-server--cursor-over-ssh)
  - [MCP Server — Claude Code](#mcp-server--claude-code)
  - [MCP Server — Docker](#mcp-server--docker)
- [Tool Reference](#tool-reference)
- [Tier and Plan Behavior](#tier-and-plan-behavior)
- [Output Formats](#output-formats)
- [IP Validation](#ip-validation)
- [Caching](#caching)
- [Audit Logging](#audit-logging)
- [Security](#security)
- [Known Limitations](#known-limitations)
- [Exit Codes](#exit-codes)
- [Development](#development)
- [Project Structure](#project-structure)
- [Contributing](#contributing)
- [Ethics](#ethics)
- [License](#license)

---

## How It Works

shogunhound runs as a subprocess on your VPS. An MCP client (Cursor, a terminal agent, or any MCP-compatible editor) communicates with it over stdin/stdout. When the LLM needs Shodan intelligence, it calls focused tools (`shodan_ip_query`, `shodan_search`, `shodan_dns_*`, `shodan_cve_lookup`, `shodan_ip_query_bulk`, `shodan_report`, and Shodan Monitor alert tools). Results come back as formatted text or raw JSON, ready to drop into investigation notes.

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
  - "What ports were open on `8.8.8.8` and are there any known CVEs?"
2. **Penetration testing recon**
  In passive recon, enumerate exposed services and banners without sending packets to target infrastructure.
  - "How many hosts in `AS12345` are running an exposed RDP port?"
3. **Threat intelligence and attacker infrastructure profiling**
  Pivot from suspicious IPs in alerts and enrich with organization, ASN, and service profile details.
  - "What organization owns `185.220.101.34` and what services is it running?"
4. **Vulnerability management**
  Rapidly assess whether critical CVEs appear on known public IPs without waiting for a full scan cycle.
  - "Does `1.1.1.1` show signs of affected software and known CVEs?"
5. **Incident response triage**
  Reverse-resolve suspicious IPs, then profile their exposed services to prioritize escalation.
  - "Reverse DNS on `45.33.32.156`, then give me its full Shodan profile."

---

## Workflow Examples

**IR triage**

Prompt:
"I have a suspicious IP from our firewall logs: `45.33.32.156`.
Reverse-resolve it, then give me the full Shodan profile,
and flag any CVEs."

Typical chain:
`shodan_dns_reverse` -> `shodan_ip_query` -> CVE-focused analyst summary

**CVE exposure sweep**

Prompt:
"How many hosts are exposed to `CVE-2021-44228` (Log4Shell)?
Is there a public exploit available?"

Typical chain:
`shodan_cve_lookup` -> host count + CVSS + exploit availability

**Ransomware recovery bulk triage**

Prompt:
"Here are 8 public IPs from the victim network scope:
`8.8.8.8, 1.1.1.1, 9.9.9.9, ...`
Generate a markdown exposure report with CVE counts and top ports."

Typical chain:
`shodan_report` -> `## Shodan Exposure Report`

---

## Versioning and Support Policy

shogunhound follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html). For release history, see [`CHANGELOG.md`](CHANGELOG.md).

Support policy:

- The latest released version is supported with fixes.
- Older releases may work but are not guaranteed to receive patches.
- The server targets MCP stdio integrations and Go 1.25+.

---

## Compatibility

Validated environments:

- **Go toolchain:** 1.25+
- **Runtime OS (native binary):** Linux (Ubuntu 22.04+ / Debian 12+ recommended)
- **MCP clients tested:** Cursor (Remote SSH MCP), Claude Code (stdio MCP)
- **Container runtime:** Docker / Docker Compose with GHCR image support

Release artifact policy:

- GitHub Release binaries are published for `linux/amd64` and `linux/arm64`.
- Container images are published to GHCR for tagged releases (`vX.Y.Z`) and `latest`.

---

## Prerequisites

- Linux (Ubuntu 22.04+ or Debian 12+ recommended) — **Linux only; macOS and Windows are not supported**
- [Go 1.25+](https://go.dev/dl/)
- A [Shodan API key](https://account.shodan.io/) (free tier works; 1 req/s rate limit applies)
- `git`

> **Alternative:** If you prefer not to install Go, you can run shogunhound via Docker. See [Docker installation](#docker) below. A Docker host and internet access to `ghcr.io` are the only requirements. Docker is also the recommended path if you are on macOS or Windows and want to run the server locally for development.

---

## Installation

### Build from Source

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

### Docker

Pre-built images are published to GitHub Container Registry on every tagged release:

```bash
docker pull ghcr.io/nethoundsh/shogunhound:latest
```

Available tags:
- `latest` — most recent release
- `v0.1.0`, `v0.1.1`, `v0.1.2`, `v0.1.3`, `v0.1.5`, etc. — specific releases

**Verify the image starts cleanly:**

```bash
docker run --rm ghcr.io/nethoundsh/shogunhound:latest
# Expected: "SHODAN_API_KEY not set; cannot query Shodan" on stderr, exit 1
```

**Build the image yourself from source:**

```bash
git clone https://github.com/nethoundsh/shogunhound
cd shogunhound
docker build -t shogunhound:local .
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


| Variable         | Required | Default                | Description                                               |
| ---------------- | -------- | ---------------------- | --------------------------------------------------------- |
| `SHODAN_API_KEY` | **Yes**  | —                      | Your Shodan API key. Never logged or written to disk.     |
| `CACHE_PATH`     | No       | `~/.shodan_cache.json` | Path to the local result cache.                           |
| `LOG_PATH`       | No       | `~/shodan_queries.log` | Path to the audit log.                                    |
| `SHODAN_TIER`    | No       | `free`                 | Default Shodan tier for client pacing (`free` or `paid`). |


Protect the log file after creation:

```bash
touch ~/shodan_queries.log
chmod 600 ~/shodan_queries.log
```

---

## Usage

### CLI flags

shogunhound is MCP-first, but the binary exposes lightweight CLI flags for diagnostics:

```bash
shogunhound --help
shogunhound --version
```

On normal startup (with `SHODAN_API_KEY` set), shogunhound prints a one-line self-check to `stderr` showing version, cache path, log path, and active tier. The API key is never printed.

### Roadmap: HTTP/SSE Transport (Not Implemented)

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
        "SHODAN_API_KEY": "${env:SHODAN_API_KEY}",
        "SHODAN_TIER": "${env:SHODAN_TIER}"
      }
    }
  }
}
```

`${env:SHODAN_API_KEY}` pulls the value from your SSH session's shell environment. Make sure the variable is exported in your shell profile on the VPS before connecting.

**Verify the tool is available:**

1. Connect to your VPS via Cursor Remote SSH
2. Open Cursor Settings → MCP
3. `shogunhound` should appear as a connected server with tools like `shodan_ip_query`, `shodan_search`, and `shodan_dns_reverse`
4. In the chat, ask: *"What ports are open on 8.8.8.8?"* — the agent will invoke `shodan_ip_query` automatically

**Troubleshooting:**


| Symptom                          | Likely Cause                                 | Fix                                                                                                          |
| -------------------------------- | -------------------------------------------- | ------------------------------------------------------------------------------------------------------------ |
| Tool not appearing in MCP panel  | Binary path wrong or not executable          | Run `which shogunhound` in the SSH session; verify it matches the config path                                |
| `SHODAN_API_KEY not set` error   | Env var not exported before Cursor connected | Add `export SHODAN_API_KEY=...` to `~/.bashrc` and reconnect                                                 |
| Tool visible but returns no data | API key invalid                              | Verify your key at [https://account.shodan.io](https://account.shodan.io) and restart the MCP server process |
| Server shown as disconnected     | shogunhound crashed on startup               | Check Cursor MCP logs; run the binary manually to see the error                                              |


---

### MCP Server — Claude Code

Claude Code natively supports MCP stdio servers. `shogunhound` works without any modification.

> **Important:** `SHODAN_API_KEY` must be set persistently in your `~/.bashrc` or `~/.zshrc` — not just exported temporarily in a terminal session. Claude Code reads environment variables from your shell profile at startup. A one-off `export` in a terminal will not carry over to Claude Code or its MCP subprocesses.
>
> Add this to your `~/.bashrc` or `~/.zshrc` before proceeding:
>
> ```bash
> export SHODAN_API_KEY="your_api_key_here"
> ```
>
> Then reload your shell (`source ~/.bashrc` or open a new terminal) before running the commands below.

Add globally (available in all Claude Code sessions on this machine):

```bash
claude mcp add --transport stdio \
  --env SHODAN_API_KEY="${SHODAN_API_KEY}" \
  --env SHODAN_TIER="${SHODAN_TIER}" \
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
        "SHODAN_API_KEY": "${SHODAN_API_KEY}",
        "SHODAN_TIER": "${SHODAN_TIER}"
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

Example slash-commands:

```text
/mcp__shogunhound__shodan_ip_query ip=8.8.8.8 format=pretty
/mcp__shogunhound__shodan_search query="org:\"Acme Corp\"" format=markdown
```

---

### MCP Server — Docker

Docker is useful if you want to run shogunhound without installing Go, or if you are on macOS or Windows and want to run the server locally for development (pre-built binaries are Linux-only).

shogunhound must run in **interactive stdin mode** (`-i` flag). The container receives MCP JSON-RPC calls over stdin and writes responses to stdout, just like the native binary.

**Cache and log persistence**

By default, the container's filesystem is ephemeral — the cache and audit log are lost when the container exits. Mount host paths to persist them:

```bash
# Create the files on the host first (Docker bind-mounts require the source to exist)
touch ~/.shodan_cache.json ~/shodan_queries.log
chmod 600 ~/.shodan_cache.json ~/shodan_queries.log

# Run with persistence
docker run --rm -i \
  -e SHODAN_API_KEY="${SHODAN_API_KEY}" \
  -e SHODAN_TIER="${SHODAN_TIER}" \
  -e CACHE_PATH=/data/cache.json \
  -e LOG_PATH=/data/queries.log \
  -v "$HOME/.shodan_cache.json:/data/cache.json" \
  -v "$HOME/shodan_queries.log:/data/queries.log" \
  ghcr.io/nethoundsh/shogunhound:latest
```

The container runs as a non-root user (`nonroot` from the distroless base image). The mounted files must be readable and writable by UID 65532.

**MCP client configuration — Cursor**

Add to `.cursor/mcp.json` (per-project) or `~/.cursor/mcp.json` (global):

```json
{
  "mcpServers": {
    "shogunhound": {
      "command": "docker",
      "args": [
        "run", "--rm", "-i",
        "-e", "SHODAN_API_KEY=${env:SHODAN_API_KEY}",
        "-e", "SHODAN_TIER=${env:SHODAN_TIER}",
        "-e", "CACHE_PATH=/data/cache.json",
        "-e", "LOG_PATH=/data/queries.log",
        "-v", "${env:HOME}/.shodan_cache.json:/data/cache.json",
        "-v", "${env:HOME}/shodan_queries.log:/data/queries.log",
        "ghcr.io/nethoundsh/shogunhound:latest"
      ]
    }
  }
}
```

> **Note:** `${env:HOME}` expansion in Cursor's MCP config uses your local home directory. On Windows, substitute the full path (e.g. `C:/Users/you/.shodan_cache.json`).

**MCP client configuration — Claude Code**

```bash
claude mcp add --transport stdio shogunhound -- \
  docker run --rm -i \
  -e SHODAN_API_KEY="${SHODAN_API_KEY}" \
  -e SHODAN_TIER="${SHODAN_TIER}" \
  -e CACHE_PATH=/data/cache.json \
  -e LOG_PATH=/data/queries.log \
  -v "$HOME/.shodan_cache.json:/data/cache.json" \
  -v "$HOME/shodan_queries.log:/data/queries.log" \
  ghcr.io/nethoundsh/shogunhound:latest
```

Verify the connection:

```bash
claude mcp list
# shogunhound   stdio   docker run ...
```

**Docker Compose (optional)**

For teams or repeated use, a `docker-compose.yml` at the project root can wrap the run parameters:

```yaml
services:
  shogunhound:
    image: ghcr.io/nethoundsh/shogunhound:latest
    stdin_open: true
    tty: false
    environment:
      SHODAN_API_KEY: "${SHODAN_API_KEY}"
      SHODAN_TIER: "${SHODAN_TIER}"
      CACHE_PATH: /data/cache.json
      LOG_PATH: /data/queries.log
    volumes:
      - "${HOME}/.shodan_cache.json:/data/cache.json"
      - "${HOME}/shodan_queries.log:/data/queries.log"
```

Then in the MCP config, replace the `docker run ...` args with `["compose", "run", "--rm", "shogunhound"]`.

**Troubleshooting (Docker-specific)**

| Symptom | Likely Cause | Fix |
|---------|--------------|-----|
| `permission denied` writing cache or log | Host file not writable by UID 65532 | `chmod 666 ~/.shodan_cache.json ~/shodan_queries.log` or `chown 65532` |
| Container exits immediately with no output | Missing `-i` flag | Ensure `stdin_open: true` or the `-i` flag is present |
| `Cannot connect to the Docker daemon` | Docker not running | Start Docker Desktop or `sudo systemctl start docker` |
| `pull access denied` for `ghcr.io/...` | Image not yet public | Log in: `docker login ghcr.io -u <github-username>` |
| Cache not persisting between runs | Mount path typo or file doesn't exist on host | Run `touch ~/.shodan_cache.json` first; verify `-v` source path |

---

## Tool Reference


| Tool                   | Description                                         | Tier           |
| ---------------------- | --------------------------------------------------- | -------------- |
| `shodan_ip_query`      | Host intelligence for a single public IP            | Free           |
| `shodan_count`         | Count hosts matching a search query                 | Free           |
| `shodan_search`        | Search hosts by query, returns list                 | Paid           |
| `shodan_dns_resolve`   | Resolve hostnames -> IPs via Shodan DNS             | Free           |
| `shodan_dns_reverse`   | Reverse-resolve IPs -> hostnames via Shodan DNS     | Free           |
| `shodan_ip_query_bulk` | Bulk host lookups for multiple public IPs           | Free/Paid      |
| `shodan_cve_lookup`    | CVE intelligence: host count + exploit availability | Free/Paid      |
| `shodan_alert_create`  | Create Shodan Monitor alert                         | Plan-dependent |
| `shodan_alert_list`    | List Shodan Monitor alerts                          | Plan-dependent |
| `shodan_alert_delete`  | Delete Shodan Monitor alert by ID                   | Plan-dependent |
| `shodan_report`        | Multi-IP exposure report generation                 | Free/Paid      |


---

## Tier and Plan Behavior

Use this as the quick decision matrix when selecting tools:

| Tool | Free Tier Behavior | Paid/Plan Behavior | Typical Failure Message |
| ---- | ------------------ | ------------------ | ----------------------- |
| `shodan_count` | Works on common queries | Works; better throughput under paid pacing | `Shodan rate limit exceeded; wait 60 seconds and retry` |
| `shodan_ip_query` | Works | Works with server-level paid pacing (`SHODAN_TIER=paid`) | `Shodan authentication failed; check your API key` |
| `shodan_search` | May be limited depending on Shodan plan/query | Intended primary mode for filtered searches | `Shodan authentication failed; check your API key` |
| `shodan_dns_resolve` / `shodan_dns_reverse` | Works for indexed DNS data | Same behavior; higher request budgets may apply by plan | `Shodan rate limit exceeded; wait 60 seconds and retry` |
| `shodan_ip_query_bulk` | Works; pacing follows server startup tier | Works with faster server-level pacing when `SHODAN_TIER=paid` | `Shodan rate limit exceeded; wait 60 seconds and retry` |
| `shodan_cve_lookup` | Works with plan-dependent dataset coverage | Works; same behavior with improved throughput characteristics by plan | `Shodan query timed out; try again` |
| `shodan_report` | Works; markdown/json only | Works; uses server default tier pacing | `invalid parameter value: format must be markdown or json` |
| `shodan_alert_*` | Usually unavailable | Requires Monitor-capable Shodan plan | `Shodan authentication failed; check your API key` or provider plan errors |

If a request is valid but unavailable to your Shodan plan, shogunhound returns a human-readable MCP error and does not crash.

---

**Tool name:** `shodan_ip_query`

**Description (as seen by the LLM):**

> Queries Shodan for a single public IP: open ports, running services, banner data, organization, geolocation, and CVEs. Use this first when investigating a specific IP.
>
> Format guidance: use format=markdown for chat responses, format=json when chaining with other tools or scripts, format=pretty for plain-text summaries.
>
> After receiving results: flag any CVEs as high-priority findings. Note unexpected services (admin panels, databases, RDP, Telnet). Highlight the organization and ASN for attribution. If the result contains no services, the host may be unindexed — note this and suggest the user verify the IP is public and reachable.
>
> For ethical, authorized use only. Comply with Shodan Terms of Service: [https://www.shodan.io/about/terms](https://www.shodan.io/about/terms)

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


| Parameter     | Type    | Required | Default  | Description                                    |
| ------------- | ------- | -------- | -------- | ---------------------------------------------- |
| `ip`          | string  | **Yes**  | —        | Public IPv4 or IPv6 address to query           |
| `format`      | string  | No       | `pretty` | Output format: `pretty`, `markdown`, or `json` |
| `history`     | boolean | No       | `false`  | Include historical banner data                 |
| `minify`      | boolean | No       | `false`  | Omit banner strings from the response          |
| `tier`        | string  | No       | `free`   | Deprecated compatibility field; per-request override is ignored |
| `clear_cache` | boolean | No       | `false`  | Evict cached result before querying            |


**Error responses** are returned as MCP tool errors with human-readable messages:


| Condition                | Message                                                    |
| ------------------------ | ---------------------------------------------------------- |
| Invalid IP format        | `invalid IP address: <input>`                              |
| Private or reserved IP   | `IP <input> is not a public address and cannot be queried` |
| API key not set          | `SHODAN_API_KEY not set; cannot query Shodan`              |
| Authentication failure   | `Shodan authentication failed; check your API key`         |
| Rate limit exceeded      | `Shodan rate limit exceeded; wait 60 seconds and retry`    |
| IP not indexed by Shodan | `No Shodan data found for <ip>; host may not be indexed`   |
| Query timeout            | `Shodan query timed out after 4 seconds; try again`        |
| Shodan API error         | `Shodan API error; try again later`                        |


---

**Tool name:** `shodan_count`

**Description (as seen by the LLM):**

> Returns the number of Shodan-indexed hosts matching a search query — no result details and no query credits consumed.
>
> Use before shodan_search to gauge scope and avoid unexpectedly large result sets. If the count exceeds ~500, suggest refining the query with additional filters (country:XX, org:"name", port:N, version:"x.y") before searching.
>
> Supports all Shodan search filters. Free tier compatible.
> For ethical, authorized use only.

**Ask the agent:**

- "How many SSH servers are exposed in Germany right now?"
- "Before I search, how large is `vuln:CVE-2021-44228`?"
- "How many hosts in AS15169 have port 443 open?"

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


| Parameter | Type   | Required | Default | Description                                                            |
| --------- | ------ | -------- | ------- | ---------------------------------------------------------------------- |
| `query`   | string | **Yes**  | —       | Shodan search query (e.g. `port:22 country:DE`, `vuln:CVE-2021-44228`) |


**Error responses** are returned as MCP tool errors with human-readable messages:


| Condition              | Message                                                 |
| ---------------------- | ------------------------------------------------------- |
| Authentication failure | `Shodan authentication failed; check your API key`      |
| Rate limit exceeded    | `Shodan rate limit exceeded; wait 60 seconds and retry` |
| Query timeout          | `Shodan query timed out; try again`                     |
| Shodan API error       | `Shodan API error; try again later`                     |


---

**Tool name:** `shodan_search`

**Description (as seen by the LLM):**

> Searches Shodan and returns matching hosts with IP, organization, country, and open ports. Use after shodan_count to confirm the result set is manageable. 100 results per page.
>
> Format guidance: format=markdown produces a table suitable for chat; format=json is best for downstream processing.
>
> After receiving results: look for repeated organizations, geographic clustering, and shared service versions. Flag hosts running unexpected or known-vulnerable services, then call shodan_ip_query for deeper host-level analysis.
>
> Requires a paid Shodan API key for most filtered queries.
> For ethical, authorized use only. Comply with Shodan Terms of Service: [https://www.shodan.io/about/terms](https://www.shodan.io/about/terms)

**Ask the agent:**

- "Find nginx servers in France."
- "Show me hosts with `CVE-2021-44228` at Hetzner, page 2, as markdown."
- "Search for Redis servers exposed on port 6379 in the US and return results as markdown."

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

 5.9.243.12       Hetzner Online GmbH            Germany           ports: 22
 78.46.120.44     Hetzner Online GmbH            Germany           ports: 22, 80, 443
```

**Parameters:**


| Parameter | Type   | Required | Default  | Description                                    |
| --------- | ------ | -------- | -------- | ---------------------------------------------- |
| `query`   | string | **Yes**  | —        | Shodan search query                            |
| `format`  | string | No       | `pretty` | Output format: `pretty`, `markdown`, or `json` |
| `page`    | number | No       | `1`      | Result page (100 results per page)             |


**Error responses** are returned as MCP tool errors with human-readable messages:


| Condition              | Message                                                 |
| ---------------------- | ------------------------------------------------------- |
| Authentication failure | `Shodan authentication failed; check your API key`      |
| Rate limit exceeded    | `Shodan rate limit exceeded; wait 60 seconds and retry` |
| Query timeout          | `Shodan query timed out; try again`                     |
| Shodan API error       | `Shodan API error; try again later`                     |


---

**Tool name:** `shodan_dns_resolve`

**Description (as seen by the LLM):**

> Resolves hostnames to IP addresses using Shodan's DNS database. Up to 100 hostnames per call.
>
> Use when given a domain instead of an IP: resolve first, then call shodan_ip_query on the result. Also useful for bulk resolution from threat intel feeds.
>
> If a hostname is not found in Shodan's database, try live DNS as a fallback.

**Ask the agent:**

- "What IPs do `google.com` and `cloudflare.com` resolve to?"
- "Resolve these domains: `example.com, github.com, microsoft.com`."
- "Resolve `suspicious-c2.example.com` to its IP so I can query it in Shodan."

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


| Parameter   | Type   | Required | Default | Description                                                            |
| ----------- | ------ | -------- | ------- | ---------------------------------------------------------------------- |
| `hostnames` | string | **Yes**  | —       | Comma-separated hostnames (e.g. `google.com,cloudflare.com`). Max 100. |


**Error responses** are returned as MCP tool errors with human-readable messages:


| Condition                      | Message                                                                                |
| ------------------------------ | -------------------------------------------------------------------------------------- |
| Missing or empty hostname list | `missing required parameter: hostnames` or `hostnames must contain at least one entry` |
| Too many hostnames             | `hostnames must not exceed 100 entries`                                                |
| Authentication failure         | `Shodan authentication failed; check your API key`                                     |
| Rate limit exceeded            | `Shodan rate limit exceeded; wait 60 seconds and retry`                                |
| Query timeout                  | `Shodan query timed out; try again`                                                    |
| Shodan API error               | `Shodan API error; try again later`                                                    |


---

**Tool name:** `shodan_dns_reverse`

**Description (as seen by the LLM):**

> Looks up hostnames for IP addresses using Shodan's DNS database. Up to 100 IPs per call; public IPs only.
>
> Use to attribute suspicious IPs (CDN, cloud provider, VPN exit node, hosting company) or pivot from an IP to related domain infrastructure.
>
> Only indexed PTR data is returned — absence of results does not prove no hostname exists.

**Ask the agent:**

- "What hostname does `8.8.8.8` belong to?"
- "Reverse DNS lookup on `8.8.8.8` and `1.1.1.1`."
- "What domains are associated with `45.33.32.156`?"

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


| Parameter | Type   | Required | Default | Description                                                                   |
| --------- | ------ | -------- | ------- | ----------------------------------------------------------------------------- |
| `ips`     | string | **Yes**  | —       | Comma-separated public IPv4/IPv6 addresses (e.g. `8.8.8.8,1.1.1.1`). Max 100. |


**Error responses** are returned as MCP tool errors with human-readable messages:


| Condition                | Message                                                                    |
| ------------------------ | -------------------------------------------------------------------------- |
| Missing or empty IP list | `missing required parameter: ips` or `ips must contain at least one entry` |
| Too many IPs             | `ips must not exceed 100 entries`                                          |
| Invalid/private IP       | `invalid IP "<ip>": <validation message>`                                  |
| Authentication failure   | `Shodan authentication failed; check your API key`                         |
| Rate limit exceeded      | `Shodan rate limit exceeded; wait 60 seconds and retry`                    |
| Query timeout            | `Shodan query timed out; try again`                                        |
| Shodan API error         | `Shodan API error; try again later`                                        |


---

**Tool name:** `shodan_ip_query_bulk`

**Description (as seen by the LLM):**

> Bulk Shodan host queries for comma/newline-separated public IPs.
>
> Use for rapid triage across multiple addresses when you need quick status, port exposure, and CVE counts in one pass.
>
> Format guidance: use format=markdown for analyst-facing summaries and format=json when chaining outputs into other tools.
>
> For deep host-level analysis after triage, follow up with shodan_ip_query on high-risk IPs.

**Ask the agent:**

- "Run a bulk Shodan profile for these IPs: `8.8.8.8,1.1.1.1,9.9.9.9`."
- "Bulk query this list in markdown and include CVE counts."
- "Triage all public IPs from this incident scope: `8.8.8.8,1.1.1.1,9.9.9.9`."

**Example parameters:**

```json
{
  "ips": "8.8.8.8,1.1.1.1,9.9.9.9",
  "format": "markdown",
  "history": false,
  "minify": false,
  "clear_cache": false,
  "max_workers": 4
}
```

**Example output (excerpt):**

```
## Shodan Bulk Query

| IP | Status | Ports | CVEs |
|----|--------|-------|------|
| 8.8.8.8 | ok | 53,443 | 0 |
| 1.1.1.1 | ok | 53,80,443 | 0 |
| 9.9.9.9 | ok | 53 | 0 |
```

**Parameters:**


| Parameter     | Type    | Required | Default  | Description                                                      |
| ------------- | ------- | -------- | -------- | ---------------------------------------------------------------- |
| `ips`         | string  | **Yes**  | —        | Comma- or newline-separated public IPv4/IPv6 addresses (max 100) |
| `format`      | string  | No       | `pretty` | Output format: `pretty`, `markdown`, or `json`                   |
| `history`     | boolean | No       | `false`  | Include historical banner data                                   |
| `minify`      | boolean | No       | `false`  | Omit banner payloads                                             |
| `tier`        | string  | No       | `free`   | Deprecated compatibility field; bulk pacing uses server startup tier |
| `clear_cache` | boolean | No       | `false`  | Evict each IP from cache before querying                         |
| `max_workers` | number  | No       | `4`      | Concurrent workers (bounded to 1..10)                            |

`max_workers` controls concurrency for validation/formatting throughput, but does not bypass client pacing. With free-tier startup pacing, requests are serialized to approximately 1 request/second process-wide.


**Error responses** are returned as MCP tool errors with human-readable messages:


| Condition                        | Message                                                                    |
| -------------------------------- | -------------------------------------------------------------------------- |
| Missing or empty IP list         | `missing required parameter: ips` or `ips must contain at least one entry` |
| Too many IPs                     | `ips must not exceed 100 entries`                                          |
| Invalid or private IP (per-host) | Appears inline in each output row; does not abort the whole batch          |


---

**Tool name:** `shodan_cve_lookup`

**Description (as seen by the LLM):**

> Lookup a CVE across Shodan host and exploit datasets, returning host count and exploit availability.

**Ask the agent:**

- "Check `CVE-2021-44228` exposure and exploit availability."
- "Lookup `CVE-2023-34362` as JSON."
- "Is there a public exploit for `CVE-2024-3400`? How many hosts are affected?"

**Example parameters:**

```json
{
  "cve": "CVE-2021-44228",
  "format": "pretty"
}
```

**Example output:**

```text
CVE CVE-2021-44228
Affected hosts: 24837
Exploit available: true
Exploit entries: 15
CVSS: 10.0
```

**Parameters:**


| Parameter | Type   | Required | Default  | Description                                    |
| --------- | ------ | -------- | -------- | ---------------------------------------------- |
| `cve`     | string | **Yes**  | —        | CVE identifier (e.g. `CVE-2021-44228`)         |
| `format`  | string | No       | `pretty` | Output format: `pretty`, `markdown`, or `json` |


**Error responses** are returned as MCP tool errors with human-readable messages:


| Condition               | Message                                                                 |
| ----------------------- | ----------------------------------------------------------------------- |
| Missing CVE identifier  | `missing required parameter: cve`                                       |
| CVE not found in Shodan | `No results found for that query; the search returned no indexed hosts` |
| Authentication failure  | `Shodan authentication failed; check your API key`                      |
| Rate limit exceeded     | `Shodan rate limit exceeded; wait 60 seconds and retry`                 |
| Query timeout           | `Shodan query timed out; try again`                                     |
| Shodan API error        | `Shodan API error; try again later`                                     |


---

**Tool name:** `shodan_alert_create`

**Description (as seen by the LLM):**

> Create a Shodan network monitor alert for one or more IP/CIDR targets.

**Ask the agent:**

- "Create a Shodan alert named `engagement-monitor` watching `8.8.8.0/24`."
- "Start monitoring `8.8.8.8` and `1.1.1.1` for new open services."
- "Set up a 7-day alert for the client's public IP range — it expires after 604800 seconds."

**Example parameters:**

```json
{
  "name": "engagement-monitor",
  "targets": "8.8.8.0/24",
  "expires": 0
}
```

**Example output:**

```text
Created alert engagement-monitor (a1b2c3d4) for 1 target(s)
```

**Parameters:**


| Parameter | Type   | Required | Default | Description                                               |
| --------- | ------ | -------- | ------- | --------------------------------------------------------- |
| `name`    | string | **Yes**  | —       | Human-readable alert name                                 |
| `targets` | string | **Yes**  | —       | Comma/newline-separated IPs or CIDRs to monitor (max 100) |
| `expires` | number | No       | `0`     | Expiration in seconds (`0` means no expiry)               |


**Error responses** are returned as MCP tool errors with human-readable messages:


| Condition                | Message                                                                            |
| ------------------------ | ---------------------------------------------------------------------------------- |
| Missing alert name       | `missing required parameter: name`                                                 |
| Missing or empty targets | `missing required parameter: targets` or `targets must contain at least one entry` |
| Too many targets         | `targets must not exceed 100 entries`                                              |
| Authentication failure   | `Shodan authentication failed; check your API key`                                 |
| Rate limit exceeded      | `Shodan rate limit exceeded; wait 60 seconds and retry`                            |
| Query timeout            | `Shodan query timed out; try again`                                                |
| Shodan API error         | `Shodan API error; try again later`                                                |


---

**Tool name:** `shodan_alert_list`

**Description (as seen by the LLM):**

> List configured Shodan network monitor alerts.

**Ask the agent:**

- "Show all my active Shodan monitor alerts."
- "List my alerts as a markdown table."
- "What alerts do I currently have configured, and what are their IDs?"

**Example parameters:**

```json
{
  "format": "pretty"
}
```

**Example output:**

```text
SHODAN ALERTS (2)
- engagement-monitor (a1b2c3d4) targets=1 expires=0
- client-recon (e5f6g7h8) targets=5 expires=0
```

**Parameters:**


| Parameter | Type   | Required | Default  | Description                                    |
| --------- | ------ | -------- | -------- | ---------------------------------------------- |
| `format`  | string | No       | `pretty` | Output format: `pretty`, `markdown`, or `json` |


**Error responses** are returned as MCP tool errors with human-readable messages:


| Condition              | Message                                                 |
| ---------------------- | ------------------------------------------------------- |
| Authentication failure | `Shodan authentication failed; check your API key`      |
| Rate limit exceeded    | `Shodan rate limit exceeded; wait 60 seconds and retry` |
| Query timeout          | `Shodan query timed out; try again`                     |
| Shodan API error       | `Shodan API error; try again later`                     |


---

**Tool name:** `shodan_alert_delete`

**Description (as seen by the LLM):**

> Delete a Shodan network monitor alert by ID.

**Ask the agent:**

- "Delete the Shodan alert with ID `a1b2c3d4`."
- "Remove the `engagement-monitor` alert — get its ID from `shodan_alert_list` first, then delete it."
- "Clean up all alerts from last week's engagement."

**Example parameters:**

```json
{
  "id": "a1b2c3d4"
}
```

**Example output:**

```text
Alert deleted
```

**Parameters:**


| Parameter | Type   | Required | Default | Description        |
| --------- | ------ | -------- | ------- | ------------------ |
| `id`      | string | **Yes**  | —       | Alert ID to delete |


**Error responses** are returned as MCP tool errors with human-readable messages:


| Condition              | Message                                                 |
| ---------------------- | ------------------------------------------------------- |
| Missing alert ID       | `missing required parameter: id`                        |
| Authentication failure | `Shodan authentication failed; check your API key`      |
| Rate limit exceeded    | `Shodan rate limit exceeded; wait 60 seconds and retry` |
| Query timeout          | `Shodan query timed out; try again`                     |
| Shodan API error       | `Shodan API error; try again later`                     |


---

**Tool name:** `shodan_report`

**Description (as seen by the LLM):**

> Generate an exposure report for multiple public IPs.

**Ask the agent:**

- "Generate an exposure report for `8.8.8.8`, `1.1.1.1`, and `9.9.9.9`."
- "Give me a markdown summary of CVE exposure and top ports across this IP list."
- "Report on all public-facing IPs from this engagement scope."

**Example parameters:**

```json
{
  "ips": "8.8.8.8\n1.1.1.1\n9.9.9.9",
  "format": "markdown"
}
```

**Example output (excerpt):**

```markdown
## Shodan Exposure Report

- Total IPs: 3
- Successful queries: 3
- Cache hits: 0
- Errors: 0
- Total CVEs observed: 0

### Top Ports

- 53: 3 host(s)
- 443: 2 host(s)
- 80: 1 host(s)

### Host Details

- `8.8.8.8`: org=Google LLC ports=53,443 cves=0
- `1.1.1.1`: org=APNIC and Cloudflare DNS Resolver project ports=53,80,443 cves=0
- `9.9.9.9`: org=QUAD9 ports=53 cves=0
```

**Parameters:**


| Parameter | Type   | Required | Default    | Description                                                  |
| --------- | ------ | -------- | ---------- | ------------------------------------------------------------ |
| `ips`     | string | **Yes**  | —          | Comma/newline-separated public IPv4/IPv6 addresses (max 100) |
| `format`  | string | No       | `markdown` | Output format: `markdown` or `json`                          |


**Error responses** are returned as MCP tool errors with human-readable messages:


| Condition                        | Message                                                                     |
| -------------------------------- | --------------------------------------------------------------------------- |
| Missing or empty IP list         | `missing required parameter: ips` or `ips must contain at least one entry`  |
| Too many IPs                     | `ips must not exceed 100 entries`                                           |
| Invalid format                  | `invalid parameter value: format must be markdown or json`                  |
| Invalid or private IP (per-host) | Appears inline in the Host Details section; does not abort the whole report |


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
 Last Seen    : 2026-02-17 (recent)

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

### Stable JSON Contract

For machine consumers, treat JSON mode as the contract surface:

- **Stable intent:** top-level host intelligence fields (`IP`, `Ports`, `Services`, `Vulnerabilities`, location/attribution fields).
- **Potentially variable:** presentation-oriented text in `pretty`/`markdown` formats and section ordering in human-readable outputs.
- **Forward compatibility:** new JSON fields may be added in future releases; downstream parsers should ignore unknown fields.

### Markdown

Markdown output is designed for direct rendering in chat surfaces and reports.

```markdown
## Shodan Host Intelligence — 8.8.8.8

**Organization:** Google LLC | **ISP:** Google LLC | **ASN:** AS15169
**Country:** United States | **City:** Mountain View
**OS:** (unknown) | **Last Seen:** 2026-02-17 (recent)
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


| Range                                               | RFC      | Reason      |
| --------------------------------------------------- | -------- | ----------- |
| `127.0.0.0/8`, `::1`                                | —        | Loopback    |
| `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`     | RFC 1918 | Private     |
| `224.0.0.0/4`                                       | —        | Multicast   |
| `0.0.0.0`, `::`                                     | —        | Unspecified |
| `169.254.0.0/16`, `fe80::/10`                       | —        | Link-local  |
| `100.64.0.0/10`                                     | RFC 6598 | CGNAT       |
| `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24` | RFC 5737 | TEST-NET    |
| `2001:db8::/32`                                     | RFC 3849 | Documentation-only |
| `240.0.0.0/4`                                       | RFC 1112 | Reserved    |


IPv4-mapped IPv6 addresses (e.g., `::ffff:192.168.1.1`) are correctly resolved to their IPv4 form before validation — the private range check catches them.

---

## Caching

Results are cached locally to reduce redundant API calls and support offline re-analysis.

- **Location:** `~/.shodan_cache.json` (configurable via `CACHE_PATH`)
- **TTL:** 24 hours from query time
- **Capacity:** 100 entries. When full, the oldest entry by query time is evicted.
- **Writes:** Atomic — results are written to a temp file and renamed to prevent corruption on crash.
- **Force refresh:** Pass `clear_cache=true` (MCP) to evict and re-query.

The cache is loaded into memory at startup. Expired entries are discarded during load. If the cache file is corrupt or unreadable, shogunhound starts cleanly with an empty cache and logs a warning to stderr.

---

## Audit Logging

Single-IP queries (`shodan_ip_query`) log one entry per request. Batch tools (`shodan_ip_query_bulk`, `shodan_report`) emit one summary log entry per batch:

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

```json
{
  "time": "2026-02-20T20:15:39Z",
  "level": "INFO",
  "msg": "batch_query",
  "operation": "bulk",
  "format": "markdown",
  "input_count": 8,
  "successes": 7,
  "cache_hits": 3,
  "errors": 1,
  "duration_ms": 2314,
  "success": true,
  "error": ""
}
```

- **Location:** `~/shodan_queries.log` (configurable via `LOG_PATH`)
- **Format:** JSON lines, one record per single query or batch summary event
- **Permissions:** The log file should be `chmod 600`. See [Security](#security).

The log is intentionally not anonymized. In an investigation context, knowing exactly what was queried and when is the point of an audit log.
The log is in JSON lines format (one JSON object per line, no surrounding array). Standard `jq` works directly on the file.

### Log Rotation (Recommended)

For long-running deployments, rotate logs to avoid unbounded growth:

```conf
/home/your-user/shodan_queries.log {
  weekly
  rotate 8
  compress
  missingok
  notifempty
  create 0600 your-user your-user
}
```

Install this as a `logrotate` rule adapted to your username and host policy.

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

### Threat Model and Security Considerations

Trust boundaries:

- **MCP client and local host:** trusted execution environment for the shogunhound subprocess.
- **Shodan API over HTTPS:** external dependency; responses are treated as untrusted input and mapped to internal models.
- **Cache and audit log files:** local sensitive artifacts that may contain investigation context.

Design choices:

- IP input validation blocks private/special-range queries before any API call.
- No shell execution path is used for user-supplied IP or hostname input.
- `SHODAN_API_KEY` is read from environment only and not persisted by the server.

Operational guidance:

- Keep `~/shodan_queries.log` and cache files restricted (`chmod 600`) and treat them as case data.
- Prefer full-disk encryption or encrypted home directories on shared analyst infrastructure.
- Review and rotate logs per engagement retention requirements.

---

## Known Limitations

**Bulk query is summary-first.**
`shodan_ip_query_bulk` optimizes for breadth and quick triage. For deep per-host analysis, follow up with `shodan_ip_query` on specific IPs.

**`shodan_ip_query` requires IP addresses.**
The `ip` parameter only accepts IPv4 or IPv6 addresses — not hostnames. Use `shodan_dns_resolve` to resolve a hostname to an IP first, then query it.

---

## Exit Codes

| Code | Meaning |
| ---- | ------- |
| 0 | Clean exit (server stopped normally) |
| 1 | Startup failure (missing API key, bad config, log file unwritable) |

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

All tests are hermetic — no live Shodan API calls are made. The Shodan client tests use `net/http/httptest` to mock API responses. Example output:

```
ok  github.com/nethoundsh/shogunhound/internal/cache
ok  github.com/nethoundsh/shogunhound/internal/formatter
ok  github.com/nethoundsh/shogunhound/internal/handler
ok  github.com/nethoundsh/shogunhound/internal/shodan
ok  github.com/nethoundsh/shogunhound/internal/validator
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
[ ] shodan_ip_query_bulk ips="8.8.8.8,1.1.1.1" format=markdown → table output with per-IP status
[ ] shodan_cve_lookup cve="CVE-2021-44228"       → host count + exploit availability
[ ] shodan_report ips="8.8.8.8,1.1.1.1"          → markdown summary + host detail lines
[ ] shodan_alert_create name="test" targets="8.8.8.8" → alert created (monitor-enabled plan)
[ ] shodan_alert_list format=pretty              → includes created alert
[ ] shodan_alert_delete id="<alert-id>"          → alert removed
[ ] shodan_count query="invalid::query::"        → graceful error, not panic
[ ] Kill network mid-query             → timeout error within 4 seconds
[ ] Corrupt cache file, restart        → starts cleanly, cache rebuilt from scratch
```

---

## Project Structure

```
shogunhound/
├── .github/
│   └── workflows/
│       ├── ci.yml               # Test, vet, govulncheck on push/PR
│       └── release.yml          # Release gates + Linux binaries + GHCR Docker push on tag
├── .cursor/
│   └── AGENTS.md                # Internal implementation guidance for dev agents
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
│       ├── handler.go           # ToolHandler type + constructor/lifecycle
│       ├── handler_ip.go        # IP query, count, search, CVE handlers
│       ├── handler_dns.go       # DNS resolve/reverse handlers
│       ├── handler_alerts.go    # Alert create/list/delete handlers
│       ├── handler_bulk.go      # Bulk query/report handlers + aggregation
│       ├── handler_helpers.go   # Shared parsing, logging, and error helpers
│       └── handler_test.go
├── deploy/
│   └── shogunhound.service      # systemd unit (for future HTTP/SSE deployment)
├── Dockerfile                   # Multi-stage distroless container build
├── Makefile                     # Local build/test/lint/release-check helpers
├── CHANGELOG.md                 # Release history and notable changes
├── CONTRIBUTING.md              # Contributor setup and contribution workflow
├── SECURITY.md                  # Vulnerability reporting and disclosure policy
├── docs/
│   └── DESIGN.md                # Full technical design document
├── go.mod
└── go.sum
```

---

## Contributing

Contributions are welcome. Please open an issue before submitting a pull request for non-trivial changes.

For contributor setup and local quality checks, see [`CONTRIBUTING.md`](CONTRIBUTING.md).

**Areas actively looking for contributions:**

- Additional handler integration tests for remaining tool paths (`shodan_alert_`*, `shodan_cve_lookup`, `shodan_report`)
- IPv6 end-to-end testing against the live Shodan API
- Performance benchmarks for bulk query throughput under free vs paid tier rate limits

See `docs/DESIGN.md` for full architectural context. Internal developer-agent guidance lives in `.cursor/AGENTS.md`.

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