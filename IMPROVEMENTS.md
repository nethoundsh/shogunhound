This is a question I can answer directly from my thorough review of the codebase — no browsing needed.
Here are the features worth considering, grouped by value and effort:

High Value, Relatively Straightforward
Shodan Alerts / Monitor integration — Shodan's API lets you create and manage network monitors that notify you when new hosts appear on a set of IPs or CIDRs. Tools like shodan_alert_create, shodan_alert_list, and shodan_alert_delete would let an agent set up persistent monitoring during an engagement directly from a conversation. This fits the incident response use case well.
Bulk IP query tool — The README acknowledges "No batch queries" as a known limitation. A shodan_ip_query_bulk tool that accepts a comma-separated list of IPs (or a newline-separated block) and fans out concurrent queries (respecting the rate limiter) would meaningfully speed up directory sweeps. The worker pool pattern you already have in hashchecker is directly applicable here.
CVE lookup / exploit check — Shodan's API includes /shodan/exploit/search which searches known exploits. A shodan_cve_lookup tool that takes a CVE ID and returns affected host count, exploit availability, and CVSS score would be high-value in the vulnerability management and IR use cases you describe.
Export / report generation — A shodan_report tool that runs multiple queries, collects results, and emits a structured Markdown or JSON report. This would be especially useful for the compliance/audit use case. The formatter package is already well-positioned for this.

Medium Value, Meaningful Work
Shodan InternetDB integration — InternetDB (internetdb.shodan.io) is a free, no-auth-required API that returns ports, tags, CPEs, and CVEs for a given IP in under 100ms. Adding a shodan_internetdb_query tool (or using InternetDB as a fast pre-check before the full Shodan API call) would let the tool work without an API key for basic lookups. This lowers the barrier to entry significantly.
ASN / organization exposure scan — A shodan_org_exposure tool that takes an org name or ASN, runs shodan_count and shodan_search, groups results by service type, and returns a structured exposure summary. This is essentially a codified version of the recon prompt workflow, but as a discrete tool the LLM can call in a single step.
Facet analysis — Shodan's /shodan/host/search/facets endpoint returns aggregate breakdowns (e.g. top countries, top ports, top orgs) for a query without returning individual hosts. A shodan_facets tool would let an agent quickly characterize the landscape of a query without paging through results.
Log rotation / log management — Right now the audit log grows forever and requires manual management. A --max-log-size or --log-rotate-days option (or just a shodan_log_summary tool that reads and summarizes the log) would help in long-running deployments.

Architectural Improvements Worth Framing as Features
HTTP/SSE transport mode — You already have the deploy/shogunhound.service systemd unit. Adding an --transport http flag that runs as an SSE server (rather than stdio subprocess) would let multiple clients connect simultaneously and enable remote deployments that don't require SSH. This is a larger feature but the mcp-go library already supports SSE.
Per-tool rate limiting with a token bucket — Right now the rate limiter is a fixed sleep after each QueryHost call. A proper token bucket shared across all concurrent tool calls (using golang.org/x/time/rate, which you're already using in hashchecker) would be more correct and would handle the case where multiple tools are running simultaneously as the library/agent ecosystem grows.
Configurable cache TTL per tool — The 24-hour TTL is hardcoded. Banners for a known-bad IP may change faster than that during an active incident. An environment variable or per-call cache_ttl parameter would give analysts more control.

Smaller Quality-of-Life Additions
--version flag — The version string is embedded at build time but there's no way to check it without reading the binary header. A simple -version flag (like hashchecker has) would be useful for verifying deployments.
shodan_dns_resolve → shodan_ip_query chaining prompt — A built-in prompt that takes a hostname, resolves it, then immediately queries Shodan would be a common workflow worth automating.
Shodan scan credits check — A shodan_account_info tool that returns your API plan, scan credits remaining, and query credits remaining. Useful at the start of an engagement to know what you're working with.

What I'd Prioritize
If I were sequencing these, I'd tackle them in this order: InternetDB integration first (zero barrier to entry, free PR value), then bulk IP query (addresses the biggest current limitation), then CVE lookup (adds depth to the IR use case), then HTTP/SSE transport (unlocks new deployment models). The others are polish and expansion once the core is solid.