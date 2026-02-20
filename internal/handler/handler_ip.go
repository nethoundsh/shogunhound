package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/nethoundsh/shogunhound/internal/formatter"
	"github.com/nethoundsh/shogunhound/internal/validator"
)

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
