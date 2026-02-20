package handler

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/nethoundsh/shogunhound/internal/shodan"
)

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
