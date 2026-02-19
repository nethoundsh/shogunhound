package handler

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/nethoundsh/shogunhound/internal/cache"
	"github.com/nethoundsh/shogunhound/internal/formatter"
	"github.com/nethoundsh/shogunhound/internal/shodan"
	"github.com/nethoundsh/shogunhound/internal/validator"
)

type ToolHandler struct {
	cache  *cache.Cache
	shodan *shodan.ShodanClient
	logger *slog.Logger
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
		cache:  cache,
		shodan: client,
		logger: slog.New(slog.NewJSONHandler(logFile, nil)),
	}, nil
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

	h.shodan.SetTier(tier)

	if clearCache {
		h.cache.Evict(ip)
	}

	result, queriedAt, hit := h.cache.Get(ip)
	if hit {
		h.logQuery(ip, format, true, 0, true, "")
		output := formatter.Format(result, format)
		if format != "json" {
			cacheNote := fmt.Sprintf("[cached · fetched %s — pass clear_cache=true to refresh]", queriedAt.Format("2006-01-02"))
			output = cacheNote + "\n\n" + output
		}
		return mcp.NewToolResultText(output), nil
	}

	start := time.Now()
	result, err = h.shodan.QueryHost(ctx, ip, history, minify)
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
		return mcp.NewToolResultError(humanizeSearchError(err)), nil
	}

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
		if h.logger != nil {
			h.logger.Info("search", "query", query, "format", format, "success", false, "error", err.Error())
		}
		return mcp.NewToolResultError(humanizeSearchError(err)), nil
	}

	if h.logger != nil {
		h.logger.Info("search", "query", query, "format", format, "success", true, "error", "")
	}

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
		return mcp.NewToolResultError(humanizeSearchError(err)), nil
	}

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
		return mcp.NewToolResultError(humanizeSearchError(err)), nil
	}

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
		return fmt.Sprintf("Shodan API error (%s); check your query and try again", err.Error())
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
		return fmt.Sprintf("Shodan API error (%s); check your query and try again", err.Error())
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
