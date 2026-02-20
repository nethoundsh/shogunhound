package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/nethoundsh/shogunhound/internal/shodan"
	"github.com/nethoundsh/shogunhound/internal/validator"
)

func (h *ToolHandler) HandleShodanIPQueryBulk(
	ctx context.Context,
	req mcp.CallToolRequest,
) (*mcp.CallToolResult, error) {
	raw, err := requireString(req.GetArguments(), "ips")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
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
	// Backward-compatible no-op: bulk pacing now follows server startup tier.
	if _, err := optionalString(req.GetArguments(), "tier", "free"); err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	clearCache, err := optionalBool(req.GetArguments(), "clear_cache", false)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	maxWorkers, err := optionalIntBounded(req.GetArguments(), "max_workers", 4, 1, 10)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	start := time.Now()
	items := h.bulkLookup(ctx, ips, history, minify, clearCache, maxWorkers)
	duration := time.Since(start)
	h.logBatchQuery("bulk", format, len(ips), summarizeBulk(items), duration, true, "")
	return mcp.NewToolResultText(formatBulkOutput(items, format)), nil
}

func (h *ToolHandler) HandleShodanReport(
	ctx context.Context,
	req mcp.CallToolRequest,
) (*mcp.CallToolResult, error) {
	raw, err := requireString(req.GetArguments(), "ips")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	ips := splitCSVOrLines(raw)
	if len(ips) == 0 {
		return mcp.NewToolResultError("ips must contain at least one entry"), nil
	}
	if len(ips) > 100 {
		return mcp.NewToolResultError("ips must not exceed 100 entries"), nil
	}

	format, err := optionalEnum(req.GetArguments(), "format", "markdown", "markdown", "json")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	start := time.Now()
	items := h.bulkLookup(ctx, ips, false, false, false, 4)
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
			items[j.index] = h.querySingleIP(ctx, j.ip, history, minify, clearCache)
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

func (h *ToolHandler) querySingleIP(ctx context.Context, ip string, history, minify, clearCache bool) *bulkResultItem {
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
	result, err := h.shodan.QueryHost(ctx, ip, history, minify)
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
	sort.Slice(ports, func(i, j int) bool {
		if ports[i].count != ports[j].count {
			return ports[i].count > ports[j].count
		}
		return ports[i].port < ports[j].port
	})
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
			fmt.Fprintf(&b, "- `%s`: error: %s\n", item.IP, escapeMD(item.Error))
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
		fmt.Fprintf(&b, "- `%s`: org=%s ports=%s cves=%d\n", item.IP, escapeMD(org), portsText, cves)
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
