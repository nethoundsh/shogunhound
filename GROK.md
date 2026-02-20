### Overview of shogunhound

shogunhound is an open-source tool developed by nethoundsh (under the nethound.sh toolchain) that acts as a bridge between AI agents (via MCP-compatible clients like Cursor or Claude Code) and the Shodan API. Shodan is a search engine for internet-connected devices, providing intelligence on hosts, ports, services, vulnerabilities (CVEs), and more. This tool allows security analysts to perform reconnaissance, CVE checks, DNS lookups, and other Shodan queries directly from within conversational AI interfaces, without leaving their workflow. It's particularly tailored for tasks like ransomware recovery, penetration testing recon, threat intelligence, vulnerability management, and incident response.

The project is built in Go, runs as a subprocess on a Linux VPS (over SSH), and emphasizes security, ethics, and efficiency. It's licensed under MIT and appears to be in an early stage (no releases published yet, based on the provided README). The README is comprehensive, serving as both documentation and a marketing pitch for security professionals using AI-assisted workflows.

Key highlights:
- **Integration**: Works seamlessly with MCP clients (e.g., Cursor over Remote SSH or Claude Code) for stdio-based communication.
- **API Access**: Wraps Shodan's host intelligence, search, DNS, CVE, and alert endpoints into focused tools.
- **Deployment**: No daemon or open ports required; runs ephemeral via subprocess.
- **Ethical Focus**: Validates inputs to prevent querying private IPs, logs all actions for audits, and reminds users of Shodan's Terms of Service.

I'll break down the review into categories: features, installation/setup, usage, strengths, weaknesses/limitations, security considerations, development aspects, and recommendations.

### Features

shogunhound provides a suite of MCP tools that expose Shodan functionality. Each tool is well-documented in the README with descriptions, parameters, examples, and error handling. Here's a summary:

- **Core Recon Tools**:
  - `shodan_ip_query`: Detailed profile for a single IP (ports, services, banners, org, geo, CVEs). Supports formats like pretty, markdown, JSON.
  - `shodan_ip_query_bulk`: Batch queries for up to 100 IPs, with concurrency control.
  - `shodan_search`: Full Shodan search with pagination (paid tier recommended for large queries).
  - `shodan_count`: Quick count of matching hosts (no credits used, great for scoping).

- **DNS Tools**:
  - `shodan_dns_resolve`: Hostnames to IPs (up to 100).
  - `shodan_dns_reverse`: IPs to hostnames (up to 100, public IPs only).

- **Vulnerability Tools**:
  - `shodan_cve_lookup`: Host count, exploit availability, CVSS for a CVE.

- **Monitoring Tools** (plan-dependent):
  - `shodan_alert_create`, `shodan_alert_list`, `shodan_alert_delete`: Manage Shodan Monitor alerts for IPs/CIDRs.

- **Reporting**:
  - `shodan_report`: Aggregated exposure report across multiple IPs (e.g., top ports, CVE counts).

Additional features include:
- **Caching**: Local JSON cache (~24-hour TTL, 100-entry limit) to reduce API calls and enable offline reuse.
- **Logging**: Structured JSON audit logs for every query (including cache hits/misses).
- **Output Formats**: Pretty (plain text), Markdown (tables for chat), JSON (for chaining).
- **Rate Limiting**: Configurable via `SHODAN_TIER` (free or paid) to respect Shodan's limits.
- **Validation**: Strict IP checks to block private/reserved ranges, preventing misuse.

Use cases are practical and security-oriented, with examples like profiling attacker IPs or checking CVEs during incidents.

### Installation and Setup

The installation is straightforward for Go developers or Linux admins:
- Clone the repo, build with `go build`, move to `/usr/local/bin`.
- Requires Go 1.25+, a Shodan API key (free tier ok), and Linux (Ubuntu/Debian recommended).
- Configuration via environment variables (e.g., `SHODAN_API_KEY` in `~/.bashrc`).
- No dependencies beyond standard Go modules.

For MCP integration:
- Add to Cursor's `.cursor/mcp.json` or Claude Code via CLI/project config.
- Troubleshooting table covers common issues like path errors or invalid keys.

This seems user-friendly, but assumes familiarity with SSH, VPS setup, and MCP clients. New users might need a quickstart script.

### Usage

Primary workflow: Connect to VPS via SSH in Cursor/Claude Code, configure MCP, then query via natural language (e.g., "What ports are open on 8.8.8.8?"). The AI agent invokes tools automatically.

- **Pros**: Seamless for AI-driven security work. Tools are granular, allowing chaining (e.g., resolve DNS then query IP).
- **Examples**: Well-provided, with parameter JSON and output excerpts.
- **Limitations**: Stdio-only MVP; HTTP/SSE deployment is "future-facing" (service file included but experimental).
- **Ethical Reminders**: Each tool description includes TOS links and ethical notes.

In practice, this could speed up OSINT workflows, but relies on the AI agent's tool-calling accuracy.

### Strengths

- **Security-First Design**: Input validation, no network exposure, atomic caching, and audit logging make it robust for sensitive work. API key is never persisted or logged.
- **Efficiency**: Caching and bulk tools reduce costs (Shodan credits). Concurrency in bulk queries (up to 10 workers) is thoughtful.
- **Documentation**: Excellent README—detailed, structured, with tables, examples, and checklists. Covers everything from ethics to dev testing.
- **Modularity**: Clean project structure (internal packages for validator, cache, etc.). Go-based for performance and portability.
- **Ethical Emphasis**: Prevents private IP queries, logs for accountability, and focuses on defensive use cases.
- **Integration Fit**: Perfect for AI agents in security; bridges a gap between conversational tools and Shodan.
- **Open-Source Toolchain Fit**: Part of nethound.sh, suggesting synergy with other OSINT tools.

Overall, it's a niche but valuable tool for secops teams using AI (e.g., in Cursor for remote work).

### Weaknesses and Limitations

- **Scope Restrictions**: Free Shodan tier limits (1 req/s) make some tools (e.g., `shodan_search`) impractical without paid access. Bulk tools are throttled.
- **Dependencies**: Relies on Shodan (external API risks like downtime) and MCP clients (e.g., Cursor-specific quirks).
- **No Releases**: No tagged releases or binaries, so users must build from source. This could deter non-dev users.
- **IPv6 Support**: Mentioned but needs end-to-end testing (per contrib notes).
- **Error Handling**: Comprehensive, but timeouts (4s) might be too aggressive for slow networks.
- **Scalability**: Cache limit (100 entries) and max IPs (100) are reasonable but could be configurable.
- **Testing**: Good unit tests, but manual checklist highlights gaps (e.g., more handler tests, IPv6).
- **Future Features**: HTTP/SSE is teased but not ready, limiting non-MCP use.
- **Accessibility**: Assumes Linux VPS and SSH; no Docker/container support yet (though contrib welcome).
- **Potential Misuse**: Despite validations, bad actors could query public IPs unethically—README's ethics section is good but not enforceable.

Known limitations (e.g., IP-only queries, summary-first bulk) are transparently noted.

### Security Considerations

This is a strong area:
- **No Exposed Surface**: Stdio over SSH means no ports to scan/attack.
- **Input Sanitization**: `net.ParseIP` prevents injection; range checks block privates.
- **Data Handling**: Cache/logs are local and permission-protected (recommend `chmod 600`).
- **Key Management**: Env vars only; no disk storage.
- **Auditing**: JSON logs enable analysis (e.g., via jq examples).
- **Risks**: Logs contain queried IPs—treat as sensitive. Cache could leak if VPS compromised.

Recommendations: Add optional log encryption or rotation. For engagements, run locally to avoid shared VPS risks.

### Development Aspects

- **Build/Test**: Simple `go build/test`. Hermetic tests (no live API) are a plus.
- **Structure**: Modular and clean; easy to extend.
- **Contributing**: Welcoming, with specific areas (tests, IPv6, Docker).
- **Versioning**: Embeds Git tag in binary—good practice.
- **Docs**: DESIGN.md and AGENTS.md provide deeper context.

As an open-source project, it's well-set up for growth.

### Recommendations for Improvement

1. **Packaging**: Add pre-built binaries, Docker image, or GitHub Actions for releases/GHCR to ease adoption.
2. **Config Enhancements**: Make cache TTL/size and log path more flexible (e.g., via CLI flags).
3. **Expansion**: Implement HTTP/SSE soon for broader compatibility (e.g., web-based agents).
4. **Testing**: Complete contrib areas (more tests, IPv6 validation).
5. **User Onboarding**: Add a quickstart script or demo video for Cursor setup.
6. **Monitoring**: Integrate basic metrics (e.g., cache hit rate) into logs or a tool.
7. **Community**: Since no releases, promote on security forums (e.g., Reddit r/netsec) to build users.
8. **Edge Cases**: Handle Shodan API changes (e.g., via client wrapper updates).
9. **Accessibility**: Consider Windows/macOS support for local dev, even if VPS is Linux-focused.

### Conclusion

shogunhound is a solid, purpose-built tool that effectively integrates Shodan into AI-driven security workflows. Its strengths in security, documentation, and efficiency outweigh the limitations, making it ideal for analysts in incident response or OSINT. For a MVP, it's impressively polished—ethical, performant, and extensible. If you're in cybersecurity and use tools like Cursor, it's worth trying (build it and test with a free Shodan key). With releases and container support, it could gain wider adoption. Overall rating: 8.5/10—great for its niche, with room to grow. If you have specific aspects (e.g., code snippets or live demo), I can dive deeper!