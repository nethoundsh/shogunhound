package main

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/nethoundsh/shogunhound/internal/cache"
	"github.com/nethoundsh/shogunhound/internal/handler"
	"github.com/nethoundsh/shogunhound/internal/shodan"
)

var version = "vdev"

type runtimeConfig struct {
	cachePath string
	logPath   string
	apiKey    string
	tier      string
}

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "--version", "-version":
			fmt.Println(version)
			return
		case "--help", "-h", "help":
			printHelp()
			return
		}
	}

	cfg := loadRuntimeConfig()
	if cfg.apiKey == "" {
		fmt.Fprintln(os.Stderr, "SHODAN_API_KEY not set; cannot query Shodan")
		os.Exit(1)
	}
	_, _, h, err := initComponents(cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "shogunhound %s | cache: %s | log: %s | tier: %s\n", version, cfg.cachePath, cfg.logPath, cfg.tier)
	defer func() {
		if err := h.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "failed to close handler log file: %v\n", err)
		}
	}()

	mcpServer := server.NewMCPServer("shogunhound", version)
	mcpServer.AddTool(mcpTool(), h.HandleShodanIPQuery)
	mcpServer.AddTool(countTool(), h.HandleShodanCount)
	mcpServer.AddTool(searchTool(), h.HandleShodanSearch)
	mcpServer.AddTool(dnsResolveTool(), h.HandleShodanDNSResolve)
	mcpServer.AddTool(dnsReverseTool(), h.HandleShodanDNSReverse)
	mcpServer.AddTool(alertCreateTool(), h.HandleShodanAlertCreate)
	mcpServer.AddTool(alertListTool(), h.HandleShodanAlertList)
	mcpServer.AddTool(alertDeleteTool(), h.HandleShodanAlertDelete)
	mcpServer.AddTool(cveLookupTool(), h.HandleShodanCVELookup)
	mcpServer.AddTool(ipBulkTool(), h.HandleShodanIPQueryBulk)
	mcpServer.AddTool(reportTool(), h.HandleShodanReport)
	mcpServer.AddPrompt(
		mcp.NewPrompt("investigate_ip",
			mcp.WithPromptDescription("Step-by-step Shodan investigation workflow for a single public IP."),
			mcp.WithArgument("ip",
				mcp.ArgumentDescription("The public IPv4 or IPv6 address to investigate"),
				mcp.RequiredArgument(),
			),
		),
		func(ctx context.Context, req mcp.GetPromptRequest) (*mcp.GetPromptResult, error) {
			ip := req.Params.Arguments["ip"]
			return mcp.NewGetPromptResult(
				"Shodan IP investigation workflow",
				[]mcp.PromptMessage{
					{
						Role: mcp.RoleUser,
						Content: mcp.NewTextContent(fmt.Sprintf(`Investigate the IP address %s using the available Shodan tools. Follow this workflow:

1. Call shodan_ip_query with ip=%s and format=markdown.
2. Summarize the findings: organization, country, ASN, open ports, and services.
3. If CVEs are listed, flag them explicitly with severity context.
4. Check the Tags field. If tags include 'honeypot', note that this host is likely a decoy and should not be treated as a real target.
   If tags include 'tor' or 'scanner', note the likely infrastructure type. If tags include 'cloud', confirm provider context with organization/ASN.
5. Note any services that are unusual or high-risk (RDP, Telnet, exposed databases, admin panels).
6. If banners are present, extract any version strings or software identifiers.
7. Call shodan_dns_reverse with ips=%s to check for associated hostnames.
8. Provide a one-paragraph threat assessment: is this a known cloud provider, a suspicious host, or something worth escalating?

Be concise and actionable. Flag anything that warrants immediate follow-up.`, ip, ip, ip)),
					},
				},
			), nil
		},
	)
	mcpServer.AddPrompt(
		mcp.NewPrompt("recon",
			mcp.WithPromptDescription("Reconnaissance workflow: assess Shodan exposure for a query."),
			mcp.WithArgument("query",
				mcp.ArgumentDescription("Shodan search query (e.g. 'org:\"Acme Corp\"', 'asn:AS15169 port:22')"),
				mcp.RequiredArgument(),
			),
		),
		func(ctx context.Context, req mcp.GetPromptRequest) (*mcp.GetPromptResult, error) {
			query := req.Params.Arguments["query"]
			return mcp.NewGetPromptResult(
				"Shodan recon workflow",
				[]mcp.PromptMessage{
					{
						Role: mcp.RoleUser,
						Content: mcp.NewTextContent(fmt.Sprintf(`Run a Shodan reconnaissance assessment for the query: %s

Follow this workflow:

1. Call shodan_count with query="%s" to assess the scope.
2. If the count is under 500, call shodan_search with the same query and format=markdown.
   If the count is over 500, suggest 2-3 ways to refine the query before searching.
3. From the search results, identify:
   - The most common organizations and countries
   - Ports and services that appear frequently
   - Any hosts that stand out (unusual services, known-vulnerable versions)
4. Select the 3 hosts most worth investigating further. Prioritize hosts that:
   - Have CVEs listed (if visible in results)
   - Are running high-risk services (RDP, Telnet, exposed databases on 3306/5432/27017/6379)
   - Have unusual port combinations suggesting misconfiguration
   - Are NOT tagged as honeypot or scanner
   Call shodan_ip_query on each to get full details.
5. Summarize the overall exposure: what is publicly visible, what is notable,
   and what should be investigated further or remediated.`, query, query)),
					},
				},
			), nil
		},
	)
	if err := server.ServeStdio(mcpServer); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func printHelp() {
	fmt.Printf(`shogunhound %s
MCP stdio server for Shodan host intelligence.

Usage:
  shogunhound            Start MCP server over stdio
  shogunhound --help     Show this help
  shogunhound --version  Show version

Environment:
  SHODAN_API_KEY   Required; Shodan API key
  SHODAN_TIER      Optional; "free" (default) or "paid"
  CACHE_PATH       Optional; default "~/.shodan_cache.json"
  LOG_PATH         Optional; default "~/shodan_queries.log"
`, version)
}

func loadRuntimeConfig() runtimeConfig {
	tier := "free"
	if strings.EqualFold(os.Getenv("SHODAN_TIER"), "paid") {
		tier = "paid"
	}
	return runtimeConfig{
		cachePath: envOrDefault("CACHE_PATH", "~/.shodan_cache.json"),
		logPath:   envOrDefault("LOG_PATH", "~/shodan_queries.log"),
		apiKey:    os.Getenv("SHODAN_API_KEY"),
		tier:      tier,
	}
}

func initComponents(cfg runtimeConfig) (*cache.Cache, *shodan.ShodanClient, *handler.ToolHandler, error) {
	c, err := cache.New(cfg.cachePath)
	if err != nil {
		return nil, nil, nil, err
	}

	client := shodan.NewClient(cfg.apiKey, cfg.tier)
	h, err := handler.New(c, client, cfg.logPath)
	if err != nil {
		return nil, nil, nil, err
	}

	return c, client, h, nil
}

func mcpTool() mcp.Tool {
	return mcp.NewTool("shodan_ip_query",
		mcp.WithDescription("Queries Shodan for a single public IP: open ports, running services, banner data, "+
			"organization, geolocation, and CVEs. Use this first when investigating a specific IP.\n\n"+
			"Format guidance: use format=markdown for chat responses, format=json when chaining with other tools or scripts, format=pretty for plain-text summaries.\n\n"+
			"After receiving results: flag any CVEs as high-priority findings. Note unexpected services (admin panels, databases, RDP, Telnet). "+
			"Highlight the organization and ASN for attribution. If the result contains no services, the host may be unindexed — note this and suggest the user verify the IP is public and reachable.\n\n"+
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
}

func countTool() mcp.Tool {
	return mcp.NewTool("shodan_count",
		mcp.WithDescription("Returns the number of Shodan-indexed hosts matching a search query — no result details and no query credits consumed.\n\n"+
			"Use before shodan_search to gauge scope and avoid unexpectedly large result sets. "+
			"If the count exceeds ~500, suggest refining the query with additional filters "+
			"(country:XX, org:\"name\", port:N, version:\"x.y\") before searching.\n\n"+
			"Supports all Shodan search filters. Free tier compatible.\n"+
			"For ethical, authorized use only."),
		mcp.WithString("query",
			mcp.Required(),
			mcp.Description("Shodan search query (e.g. 'port:22 country:DE', 'vuln:CVE-2021-44228', 'asn:AS15169 nginx')")),
		mcp.WithReadOnlyHintAnnotation(true),
	)
}

func searchTool() mcp.Tool {
	return mcp.NewTool("shodan_search",
		mcp.WithDescription("Searches Shodan and returns matching hosts with IP, organization, country, and open ports. "+
			"Use after shodan_count to confirm the result set is manageable. 100 results per page.\n\n"+
			"Format guidance: format=markdown produces a table suitable for chat; format=json is best for downstream processing.\n\n"+
			"After receiving results: look for repeated organizations, geographic clustering, and shared service versions. "+
			"Flag hosts running unexpected or known-vulnerable services, then call shodan_ip_query for deeper host-level analysis.\n\n"+
			"Requires a paid Shodan API key for most filtered queries.\n"+
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

func dnsResolveTool() mcp.Tool {
	return mcp.NewTool("shodan_dns_resolve",
		mcp.WithDescription("Resolves hostnames to IP addresses using Shodan's DNS database. Up to 100 hostnames per call.\n\n"+
			"Use when given a domain instead of an IP: resolve first, then call shodan_ip_query on the result. "+
			"Also useful for bulk resolution from threat intel feeds.\n\n"+
			"If a hostname is not found in Shodan's database, try live DNS as a fallback."),
		mcp.WithString("hostnames",
			mcp.Required(),
			mcp.Description("Comma-separated list of hostnames to resolve (e.g. 'google.com,cloudflare.com')")),
		mcp.WithReadOnlyHintAnnotation(true),
	)
}

func dnsReverseTool() mcp.Tool {
	return mcp.NewTool("shodan_dns_reverse",
		mcp.WithDescription("Looks up hostnames for IP addresses using Shodan's DNS database. "+
			"Up to 100 IPs per call; public IPs only.\n\n"+
			"Use to attribute suspicious IPs (CDN, cloud provider, VPN exit node, hosting company) or pivot from an IP to related domain infrastructure.\n\n"+
			"Only indexed PTR data is returned — absence of results does not prove no hostname exists."),
		mcp.WithString("ips",
			mcp.Required(),
			mcp.Description("Comma-separated list of public IPv4 or IPv6 addresses (e.g. '8.8.8.8,1.1.1.1')")),
		mcp.WithReadOnlyHintAnnotation(true),
	)
}

func alertCreateTool() mcp.Tool {
	return mcp.NewTool("shodan_alert_create",
		mcp.WithDescription("Create a Shodan network monitor alert for one or more IP/CIDR targets."),
		mcp.WithString("name",
			mcp.Required(),
			mcp.Description("Human-readable alert name")),
		mcp.WithString("targets",
			mcp.Required(),
			mcp.Description("Comma- or newline-separated public IPs/CIDRs to monitor")),
		mcp.WithNumber("expires",
			mcp.Description("Optional expiration (seconds, 0 means no expiry)")),
		mcp.WithReadOnlyHintAnnotation(false),
	)
}

func alertListTool() mcp.Tool {
	return mcp.NewTool("shodan_alert_list",
		mcp.WithDescription("List configured Shodan network monitor alerts."),
		mcp.WithString("format",
			mcp.Description("Output format: pretty, markdown, or json (default: pretty)")),
		mcp.WithReadOnlyHintAnnotation(true),
	)
}

func alertDeleteTool() mcp.Tool {
	return mcp.NewTool("shodan_alert_delete",
		mcp.WithDescription("Delete a Shodan network monitor alert by ID."),
		mcp.WithString("id",
			mcp.Required(),
			mcp.Description("Alert ID to delete")),
		mcp.WithReadOnlyHintAnnotation(false),
	)
}

func cveLookupTool() mcp.Tool {
	return mcp.NewTool("shodan_cve_lookup",
		mcp.WithDescription("Lookup a CVE across Shodan host and exploit datasets, returning host count and exploit availability."),
		mcp.WithString("cve",
			mcp.Required(),
			mcp.Description("CVE identifier (e.g. CVE-2021-44228)")),
		mcp.WithString("format",
			mcp.Description("Output format: pretty, markdown, or json (default: pretty)")),
		mcp.WithReadOnlyHintAnnotation(true),
	)
}

func ipBulkTool() mcp.Tool {
	return mcp.NewTool("shodan_ip_query_bulk",
		mcp.WithDescription("Bulk Shodan host queries for comma/newline-separated public IPs.\n\n"+
			"Use for rapid triage across multiple addresses when you need quick status, port exposure, and CVE counts in one pass.\n\n"+
			"Format guidance: use format=markdown for analyst-facing summaries and format=json when chaining outputs into other tools.\n\n"+
			"For deep host-level analysis after triage, follow up with shodan_ip_query on high-risk IPs."),
		mcp.WithString("ips",
			mcp.Required(),
			mcp.Description("Comma- or newline-separated public IPv4/IPv6 addresses")),
		mcp.WithString("format",
			mcp.Description("Output format: pretty, markdown, or json (default: pretty)")),
		mcp.WithBoolean("history",
			mcp.Description("Include historical banner data")),
		mcp.WithBoolean("minify",
			mcp.Description("Omit banner payloads")),
		mcp.WithString("tier",
			mcp.Description("Rate limit tier: free or paid")),
		mcp.WithBoolean("clear_cache",
			mcp.Description("Evict each IP from cache before querying")),
		mcp.WithNumber("max_workers",
			mcp.Description("Concurrent workers (1-10, default 4)")),
		mcp.WithReadOnlyHintAnnotation(true),
	)
}

func reportTool() mcp.Tool {
	return mcp.NewTool("shodan_report",
		mcp.WithDescription("Generate an exposure report for multiple public IPs."),
		mcp.WithString("ips",
			mcp.Required(),
			mcp.Description("Comma- or newline-separated public IPv4/IPv6 addresses")),
		mcp.WithString("format",
			mcp.Description("Output format: markdown or json (default: markdown)")),
		mcp.WithReadOnlyHintAnnotation(true),
	)
}

func envOrDefault(key, def string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return def
}
