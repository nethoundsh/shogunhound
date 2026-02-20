package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/nethoundsh/shogunhound/internal/cache"
	"github.com/nethoundsh/shogunhound/internal/formatter"
	"github.com/nethoundsh/shogunhound/internal/shodan"
	"github.com/nethoundsh/shogunhound/internal/validator"
)

type ToolHandler struct {
	cache   *cache.Cache
	shodan  *shodan.ShodanClient
	logger  *slog.Logger
	logFile *os.File
}

func New(cache *cache.Cache, client *shodan.ShodanClient, logPath string) (*ToolHandler, error) {
	resolvedLogPath, err := resolvePath(logPath)
	if err != nil {
		return nil, err
	}

	logFile, err := os.OpenFile(resolvedLogPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}

	return &ToolHandler{
		cache:   cache,
		shodan:  client,
		logger:  slog.New(slog.NewJSONHandler(logFile, nil)),
		logFile: logFile,
	}, nil
}

func (h *ToolHandler) Close() error {
	if h == nil || h.logFile == nil {
		return nil
	}
	return h.logFile.Close()
}

func (h *ToolHandler) HandleShodanIPQuery(
	ctx context.Context,
	req mcp.CallToolRequest,
) (*mcp.CallToolResult, error) {
	ip, ok := req.GetArguments()["ip"].(string)
	if !ok || strings.TrimSpace(ip) == "" {
		return mcp.NewToolResultError("missing required parameter: ip"), nil
	}

	format, err := optionalString(req.GetArguments(), "format", "pretty")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	history, err := optionalBool(req.GetArguments(), "history", false)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	minify, err := optionalBool(req.GetArguments(), "minify", false)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	tier, err := optionalString(req.GetArguments(), "tier", "free")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	clearCache, err := optionalBool(req.GetArguments(), "clear_cache", false)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	if err := validator.ValidateIP(ip); err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	if clearCache {
		h.cache.Evict(ip)
	}

	result, queriedAt, hit := h.cache.Get(ip)
	if hit {
		h.logQuery(ip, format, true, 0, true, "")
		output := formatter.Format(result, format)
		if format != "json" {
			cacheNote := fmt.Sprintf("[cached · fetched %s — pass clear_cache=true to refresh]", queriedAt.Format("2006-01-02"))
			if format == "markdown" {
				output = fmt.Sprintf("> %s\n\n%s", cacheNote, output)
			} else {
				output = cacheNote + "\n\n" + output
			}
		}
		return mcp.NewToolResultText(output), nil
	}

	start := time.Now()
	result, err = h.shodan.QueryHostWithTier(ctx, ip, history, minify, tier)
	duration := time.Since(start)
	if err != nil {
		h.logQuery(ip, format, false, duration, false, err.Error())
		return mcp.NewToolResultError(humanizeError(ip, err)), nil
	}

	h.cache.Set(ip, result)
	h.logQuery(ip, format, false, duration, true, "")

	return mcp.NewToolResultText(formatter.Format(result, format)), nil
}

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
		h.logger.Error("count_failed", "query", query, "error", err.Error())
		return mcp.NewToolResultError(humanizeSearchError(err)), nil
	}
	h.logger.Info("count", "query", query, "count", count, "success", true, "error", "")

	return mcp.NewToolResultText(fmt.Sprintf("%d hosts match: %s", count, query)), nil
}

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
	switch p := req.GetArguments()["page"].(type) {
	case float64:
		if p >= 1 {
			page = int(p)
		}
	case int:
		if p >= 1 {
			page = p
		}
	}

	result, err := h.shodan.Search(ctx, query, page)
	if err != nil {
		h.logger.Error("search_failed", "query", query, "format", format, "error", err.Error())
		return mcp.NewToolResultError(humanizeSearchError(err)), nil
	}
	h.logger.Info("search", "query", query, "format", format, "success", true, "error", "")

	return mcp.NewToolResultText(formatter.FormatSearchResult(result, format)), nil
}

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
		h.logger.Error("dns_resolve_failed", "hostnames", hostnames, "error", err.Error())
		return mcp.NewToolResultError(humanizeSearchError(err)), nil
	}
	h.logger.Info("dns_resolve", "hostnames", hostnames, "success", true, "error", "")

	var b strings.Builder
	for _, hostname := range hostnames {
		if ip, ok := result[hostname]; ok && ip != "" {
			fmt.Fprintf(&b, "%s -> %s\n", hostname, ip)
		} else {
			fmt.Fprintf(&b, "%s -> (not found)\n", hostname)
		}
	}

	return mcp.NewToolResultText(strings.TrimSpace(b.String())), nil
}

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

	for _, ip := range ips {
		if err := validator.ValidateIP(ip); err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("invalid IP %q: %s", ip, err.Error())), nil
		}
	}

	result, err := h.shodan.DNSReverse(ctx, ips)
	if err != nil {
		h.logger.Error("dns_reverse_failed", "ips", ips, "error", err.Error())
		return mcp.NewToolResultError(humanizeSearchError(err)), nil
	}
	h.logger.Info("dns_reverse", "ips", ips, "success", true, "error", "")

	var b strings.Builder
	for _, ip := range ips {
		if hostnames, ok := result[ip]; ok && len(hostnames) > 0 {
			fmt.Fprintf(&b, "%s -> %s\n", ip, strings.Join(hostnames, ", "))
		} else {
			fmt.Fprintf(&b, "%s -> (none)\n", ip)
		}
	}

	return mcp.NewToolResultText(strings.TrimSpace(b.String())), nil
}

func (h *ToolHandler) HandleShodanAlertCreate(
	ctx context.Context,
	req mcp.CallToolRequest,
) (*mcp.CallToolResult, error) {
	name, ok := req.GetArguments()["name"].(string)
	if !ok || strings.TrimSpace(name) == "" {
		return mcp.NewToolResultError("missing required parameter: name"), nil
	}
	rawTargets, ok := req.GetArguments()["targets"].(string)
	if !ok || strings.TrimSpace(rawTargets) == "" {
		return mcp.NewToolResultError("missing required parameter: targets"), nil
	}

	targets := splitCSVOrLines(rawTargets)
	if len(targets) == 0 {
		return mcp.NewToolResultError("targets must contain at least one entry"), nil
	}
	if len(targets) > 100 {
		return mcp.NewToolResultError("targets must not exceed 100 entries"), nil
	}

	expires := 0
	switch v := req.GetArguments()["expires"].(type) {
	case float64:
		expires = int(v)
	case int:
		expires = v
	}

	alert, err := h.shodan.CreateAlert(ctx, strings.TrimSpace(name), targets, expires)
	if err != nil {
		h.logger.Error("alert_create_failed", "name", name, "targets", targets, "error", err.Error())
		return mcp.NewToolResultError(humanizeSearchError(err)), nil
	}
	h.logger.Info("alert_create", "name", name, "targets", targets, "alert_id", alert.ID, "success", true, "error", "")

	return mcp.NewToolResultText(fmt.Sprintf("Created alert %s (%s) for %d target(s)", alert.Name, alert.ID, len(alert.IPs))), nil
}

func (h *ToolHandler) HandleShodanAlertList(
	ctx context.Context,
	req mcp.CallToolRequest,
) (*mcp.CallToolResult, error) {
	format, err := optionalString(req.GetArguments(), "format", "pretty")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	alerts, err := h.shodan.ListAlerts(ctx)
	if err != nil {
		h.logger.Error("alert_list_failed", "error", err.Error())
		return mcp.NewToolResultError(humanizeSearchError(err)), nil
	}
	h.logger.Info("alert_list", "format", format, "count", len(alerts), "success", true, "error", "")

	switch format {
	case "json":
		out, jerr := json.MarshalIndent(alerts, "", " ")
		if jerr != nil {
			return mcp.NewToolResultError("failed to encode alerts"), nil
		}
		return mcp.NewToolResultText(string(out)), nil
	case "markdown":
		var b strings.Builder
		fmt.Fprintf(&b, "## Shodan Alerts\n\n")
		if len(alerts) == 0 {
			fmt.Fprintf(&b, "No alerts configured.\n")
			return mcp.NewToolResultText(b.String()), nil
		}
		fmt.Fprintf(&b, "| ID | Name | Targets | Expires |\n")
		fmt.Fprintf(&b, "|----|------|---------|---------|\n")
		for _, a := range alerts {
			if a == nil {
				continue
			}
			fmt.Fprintf(&b, "| %s | %s | %d | %d |\n", a.ID, a.Name, len(a.IPs), a.Expires)
		}
		return mcp.NewToolResultText(b.String()), nil
	default:
		var b strings.Builder
		if len(alerts) == 0 {
			return mcp.NewToolResultText("No alerts configured."), nil
		}
		fmt.Fprintf(&b, "SHODAN ALERTS (%d)\n", len(alerts))
		for _, a := range alerts {
			if a == nil {
				continue
			}
			fmt.Fprintf(&b, "- %s (%s) targets=%d expires=%d\n", a.Name, a.ID, len(a.IPs), a.Expires)
		}
		return mcp.NewToolResultText(strings.TrimSpace(b.String())), nil
	}
}

func (h *ToolHandler) HandleShodanAlertDelete(
	ctx context.Context,
	req mcp.CallToolRequest,
) (*mcp.CallToolResult, error) {
	id, ok := req.GetArguments()["id"].(string)
	if !ok || strings.TrimSpace(id) == "" {
		return mcp.NewToolResultError("missing required parameter: id"), nil
	}

	if err := h.shodan.DeleteAlert(ctx, strings.TrimSpace(id)); err != nil {
		h.logger.Error("alert_delete_failed", "id", id, "error", err.Error())
		return mcp.NewToolResultError(humanizeSearchError(err)), nil
	}
	h.logger.Info("alert_delete", "id", strings.TrimSpace(id), "success", true, "error", "")
	return mcp.NewToolResultText("Alert deleted"), nil
}

func (h *ToolHandler) HandleShodanCVELookup(
	ctx context.Context,
	req mcp.CallToolRequest,
) (*mcp.CallToolResult, error) {
	cve, ok := req.GetArguments()["cve"].(string)
	if !ok || strings.TrimSpace(cve) == "" {
		return mcp.NewToolResultError("missing required parameter: cve"), nil
	}

	result, err := h.shodan.CVELookup(ctx, cve)
	if err != nil {
		h.logger.Error("cve_lookup_failed", "cve", cve, "error", err.Error())
		return mcp.NewToolResultError(humanizeSearchError(err)), nil
	}

	format, err := optionalString(req.GetArguments(), "format", "pretty")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	switch format {
	case "json":
		out, jerr := json.MarshalIndent(result, "", " ")
		if jerr != nil {
			return mcp.NewToolResultError("failed to encode result"), nil
		}
		return mcp.NewToolResultText(string(out)), nil
	case "markdown":
		cvss := "(unknown)"
		if result.CVSS != nil {
			cvss = fmt.Sprintf("%.1f", *result.CVSS)
		}
		return mcp.NewToolResultText(fmt.Sprintf("## CVE Lookup — %s\n\n- Affected hosts: %d\n- Exploit availability: %t\n- Exploit entries: %d\n- CVSS: %s",
			result.CVE, result.AffectedHostCount, result.ExploitAvailable, result.ExploitCount, cvss)), nil
	default:
		cvss := "(unknown)"
		if result.CVSS != nil {
			cvss = fmt.Sprintf("%.1f", *result.CVSS)
		}
		return mcp.NewToolResultText(fmt.Sprintf(
			"CVE %s\nAffected hosts: %d\nExploit available: %t\nExploit entries: %d\nCVSS: %s",
			result.CVE,
			result.AffectedHostCount,
			result.ExploitAvailable,
			result.ExploitCount,
			cvss,
		)), nil
	}
}

func (h *ToolHandler) HandleShodanIPQueryBulk(
	ctx context.Context,
	req mcp.CallToolRequest,
) (*mcp.CallToolResult, error) {
	raw, ok := req.GetArguments()["ips"].(string)
	if !ok || strings.TrimSpace(raw) == "" {
		return mcp.NewToolResultError("missing required parameter: ips"), nil
	}
	ips := splitCSVOrLines(raw)
	if len(ips) == 0 {
		return mcp.NewToolResultError("ips must contain at least one entry"), nil
	}
	if len(ips) > 100 {
		return mcp.NewToolResultError("ips must not exceed 100 entries"), nil
	}

	format, err := optionalString(req.GetArguments(), "format", "pretty")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	history, err := optionalBool(req.GetArguments(), "history", false)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	minify, err := optionalBool(req.GetArguments(), "minify", false)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	tier, err := optionalString(req.GetArguments(), "tier", "free")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	clearCache, err := optionalBool(req.GetArguments(), "clear_cache", false)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	maxWorkers := 4
	switch v := req.GetArguments()["max_workers"].(type) {
	case float64:
		maxWorkers = int(v)
	case int:
		maxWorkers = v
	}
	if maxWorkers < 1 {
		maxWorkers = 1
	}
	if maxWorkers > 10 {
		maxWorkers = 10
	}

	start := time.Now()
	items := h.bulkLookup(ctx, ips, history, minify, clearCache, tier, maxWorkers)
	duration := time.Since(start)
	h.logBatchQuery("bulk", format, len(ips), summarizeBulk(items), duration, true, "")
	return mcp.NewToolResultText(formatBulkOutput(items, format)), nil
}

func (h *ToolHandler) HandleShodanReport(
	ctx context.Context,
	req mcp.CallToolRequest,
) (*mcp.CallToolResult, error) {
	raw, ok := req.GetArguments()["ips"].(string)
	if !ok || strings.TrimSpace(raw) == "" {
		return mcp.NewToolResultError("missing required parameter: ips"), nil
	}
	ips := splitCSVOrLines(raw)
	if len(ips) == 0 {
		return mcp.NewToolResultError("ips must contain at least one entry"), nil
	}
	if len(ips) > 100 {
		return mcp.NewToolResultError("ips must not exceed 100 entries"), nil
	}

	format, err := optionalString(req.GetArguments(), "format", "markdown")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	if format != "markdown" && format != "json" {
		return mcp.NewToolResultError("invalid parameter value: format must be markdown or json"), nil
	}

	start := time.Now()
	items := h.bulkLookup(ctx, ips, false, false, false, h.shodan.DefaultTier(), 4)
	duration := time.Since(start)
	h.logBatchQuery("report", format, len(ips), summarizeBulk(items), duration, true, "")
	return mcp.NewToolResultText(formatReportOutput(items, format)), nil
}

type bulkResultItem struct {
	IP     string                   `json:"ip"`
	Cached bool                     `json:"cached"`
	Error  string                   `json:"error,omitempty"`
	Result *shodan.ShodanHostResult `json:"result,omitempty"`
}

func (h *ToolHandler) bulkLookup(
	ctx context.Context,
	ips []string,
	history bool,
	minify bool,
	clearCache bool,
	tier string,
	maxWorkers int,
) []*bulkResultItem {
	items := make([]*bulkResultItem, len(ips))
	type job struct {
		index int
		ip    string
	}
	jobs := make(chan job)
	var wg sync.WaitGroup

	worker := func() {
		defer wg.Done()
		for j := range jobs {
			items[j.index] = h.querySingleIP(ctx, j.ip, history, minify, clearCache, tier)
		}
	}

	for i := 0; i < maxWorkers; i++ {
		wg.Add(1)
		go worker()
	}
	for idx, ip := range ips {
		jobs <- job{index: idx, ip: ip}
	}
	close(jobs)
	wg.Wait()
	return items
}

func (h *ToolHandler) querySingleIP(ctx context.Context, ip string, history, minify, clearCache bool, tier string) *bulkResultItem {
	if err := validator.ValidateIP(ip); err != nil {
		return &bulkResultItem{IP: ip, Error: err.Error()}
	}
	if clearCache {
		h.cache.Evict(ip)
	}

	result, _, hit := h.cache.Get(ip)
	if hit {
		return &bulkResultItem{IP: ip, Result: result, Cached: true}
	}
	result, err := h.shodan.QueryHostWithTier(ctx, ip, history, minify, tier)
	if err != nil {
		return &bulkResultItem{IP: ip, Error: humanizeError(ip, err)}
	}
	h.cache.Set(ip, result)
	return &bulkResultItem{IP: ip, Result: result}
}

type bulkSummary struct {
	successes int
	cacheHits int
	errors    int
}

func summarizeBulk(items []*bulkResultItem) bulkSummary {
	summary := bulkSummary{}
	for _, item := range items {
		if item == nil {
			continue
		}
		if item.Error != "" {
			summary.errors++
			continue
		}
		summary.successes++
		if item.Cached {
			summary.cacheHits++
		}
	}
	return summary
}

func splitCSVOrLines(s string) []string {
	normalized := strings.ReplaceAll(s, "\r\n", "\n")
	normalized = strings.ReplaceAll(normalized, "\r", "\n")
	normalized = strings.ReplaceAll(normalized, "\n", ",")
	return splitAndTrim(normalized)
}

func formatBulkOutput(items []*bulkResultItem, format string) string {
	switch format {
	case "json":
		out, err := json.MarshalIndent(items, "", " ")
		if err != nil {
			return "[]"
		}
		return string(out)
	case "markdown":
		var b strings.Builder
		fmt.Fprintf(&b, "## Shodan Bulk Query\n\n")
		fmt.Fprintf(&b, "| IP | Status | Ports | CVEs |\n")
		fmt.Fprintf(&b, "|----|--------|-------|------|\n")
		for _, item := range items {
			if item == nil {
				continue
			}
			if item.Error != "" {
				fmt.Fprintf(&b, "| %s | error | — | — |\n", item.IP)
				continue
			}
			ports := "(none)"
			cves := "0"
			if item.Result != nil {
				ports = joinIntCSV(item.Result.Ports)
				cves = strconv.Itoa(len(item.Result.Vulnerabilities))
			}
			status := "ok"
			if item.Cached {
				status = "cached"
			}
			fmt.Fprintf(&b, "| %s | %s | %s | %s |\n", item.IP, status, ports, cves)
		}
		return b.String()
	default:
		var b strings.Builder
		for _, item := range items {
			if item == nil {
				continue
			}
			if item.Error != "" {
				fmt.Fprintf(&b, "%s -> error: %s\n", item.IP, item.Error)
				continue
			}
			status := "ok"
			if item.Cached {
				status = "cached"
			}
			ports := "(none)"
			if item.Result != nil {
				ports = joinIntCSV(item.Result.Ports)
			}
			fmt.Fprintf(&b, "%s -> %s ports=%s\n", item.IP, status, ports)
		}
		return strings.TrimSpace(b.String())
	}
}

func formatReportOutput(items []*bulkResultItem, format string) string {
	total := len(items)
	success := 0
	cached := 0
	errorCount := 0
	totalCVEs := 0
	serviceFrequency := map[int]int{}
	for _, item := range items {
		if item == nil {
			continue
		}
		if item.Error != "" {
			errorCount++
			continue
		}
		success++
		if item.Cached {
			cached++
		}
		if item.Result != nil {
			totalCVEs += len(item.Result.Vulnerabilities)
			for _, p := range item.Result.Ports {
				serviceFrequency[p]++
			}
		}
	}

	type report struct {
		TotalIPs      int               `json:"total_ips"`
		Successful    int               `json:"successful"`
		Cached        int               `json:"cached"`
		Errors        int               `json:"errors"`
		TotalCVEs     int               `json:"total_cves"`
		PortFrequency map[int]int       `json:"port_frequency"`
		Items         []*bulkResultItem `json:"items"`
	}
	if format == "json" {
		out, err := json.MarshalIndent(report{
			TotalIPs:      total,
			Successful:    success,
			Cached:        cached,
			Errors:        errorCount,
			TotalCVEs:     totalCVEs,
			PortFrequency: serviceFrequency,
			Items:         items,
		}, "", " ")
		if err != nil {
			return "{}"
		}
		return string(out)
	}

	var b strings.Builder
	fmt.Fprintf(&b, "## Shodan Exposure Report\n\n")
	fmt.Fprintf(&b, "- Total IPs: %d\n", total)
	fmt.Fprintf(&b, "- Successful queries: %d\n", success)
	fmt.Fprintf(&b, "- Cache hits: %d\n", cached)
	fmt.Fprintf(&b, "- Errors: %d\n", errorCount)
	fmt.Fprintf(&b, "- Total CVEs observed: %d\n\n", totalCVEs)

	type pf struct {
		port  int
		count int
	}
	ports := make([]pf, 0, len(serviceFrequency))
	for port, count := range serviceFrequency {
		ports = append(ports, pf{port: port, count: count})
	}
	sort.Slice(ports, func(i, j int) bool { return ports[i].count > ports[j].count })
	if len(ports) > 0 {
		fmt.Fprintf(&b, "### Top Ports\n\n")
		for _, p := range ports {
			fmt.Fprintf(&b, "- %d: %d host(s)\n", p.port, p.count)
		}
		fmt.Fprintf(&b, "\n")
	}

	fmt.Fprintf(&b, "### Host Details\n\n")
	for _, item := range items {
		if item == nil {
			continue
		}
		if item.Error != "" {
			fmt.Fprintf(&b, "- `%s`: error: %s\n", item.IP, item.Error)
			continue
		}
		org := "(unknown)"
		portsText := "(none)"
		cves := 0
		if item.Result != nil {
			org = valueOr(item.Result.Organization, "(unknown)")
			portsText = joinIntCSV(item.Result.Ports)
			cves = len(item.Result.Vulnerabilities)
		}
		fmt.Fprintf(&b, "- `%s`: org=%s ports=%s cves=%d\n", item.IP, org, portsText, cves)
	}
	return b.String()
}

func joinIntCSV(values []int) string {
	if len(values) == 0 {
		return "(none)"
	}
	out := make([]string, 0, len(values))
	for _, v := range values {
		out = append(out, strconv.Itoa(v))
	}
	return strings.Join(out, ",")
}

func valueOr(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}

func (h *ToolHandler) logQuery(ip, format string, cacheHit bool, duration time.Duration, success bool, errMsg string) {
	if h.logger == nil {
		return
	}

	h.logger.Info("query",
		"ip", ip,
		"format", format,
		"cache_hit", cacheHit,
		"duration_ms", duration.Milliseconds(),
		"success", success,
		"error", errMsg,
	)
}

func (h *ToolHandler) logBatchQuery(op, format string, inputCount int, summary bulkSummary, duration time.Duration, success bool, errMsg string) {
	if h.logger == nil {
		return
	}

	h.logger.Info("batch_query",
		"operation", op,
		"format", format,
		"input_count", inputCount,
		"successes", summary.successes,
		"cache_hits", summary.cacheHits,
		"errors", summary.errors,
		"duration_ms", duration.Milliseconds(),
		"success", success,
		"error", errMsg,
	)
}

func humanizeError(ip string, err error) string {
	switch {
	case errors.Is(err, shodan.ErrUnauthorized):
		return "Shodan authentication failed; check your API key"
	case errors.Is(err, shodan.ErrRateLimited):
		return "Shodan rate limit exceeded; wait 60 seconds and retry"
	case errors.Is(err, shodan.ErrNotFound):
		return fmt.Sprintf("No Shodan data found for %s; host may not be indexed", ip)
	case errors.Is(err, context.DeadlineExceeded):
		return "Shodan query timed out after 4 seconds; try again"
	default:
		return "Shodan API error; try again later"
	}
}

func humanizeSearchError(err error) string {
	switch {
	case errors.Is(err, shodan.ErrUnauthorized):
		return "Shodan authentication failed; check your API key"
	case errors.Is(err, shodan.ErrRateLimited):
		return "Shodan rate limit exceeded; wait 60 seconds and retry"
	case errors.Is(err, shodan.ErrNotFound):
		return "No results found for that query; the search returned no indexed hosts"
	case errors.Is(err, context.DeadlineExceeded):
		return "Shodan query timed out; try again"
	default:
		return "Shodan API error; try again later"
	}
}

func optionalString(args map[string]any, key, def string) (string, error) {
	v, ok := args[key]
	if !ok {
		return def, nil
	}
	str, ok := v.(string)
	if !ok {
		return "", fmt.Errorf("invalid parameter type: %s", key)
	}
	if strings.TrimSpace(str) == "" {
		return def, nil
	}
	return str, nil
}

func optionalBool(args map[string]any, key string, def bool) (bool, error) {
	v, ok := args[key]
	if !ok {
		return def, nil
	}
	b, ok := v.(bool)
	if !ok {
		return false, fmt.Errorf("invalid parameter type: %s", key)
	}
	return b, nil
}

func resolvePath(path string) (string, error) {
	if path == "" {
		return "", fmt.Errorf("path cannot be empty")
	}

	if path == "~" || strings.HasPrefix(path, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		if path == "~" {
			return home, nil
		}
		return filepath.Join(home, strings.TrimPrefix(path, "~/")), nil
	}

	return path, nil
}

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
