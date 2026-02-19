package handler

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/nethoundsh/shogunhound/internal/cache"
	"github.com/nethoundsh/shogunhound/internal/shodan"
)

func TestOptionalString(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		args    map[string]any
		def     string
		want    string
		wantErr bool
	}{
		{name: "missing uses default", args: map[string]any{}, def: "pretty", want: "pretty"},
		{name: "present string", args: map[string]any{"format": "json"}, def: "pretty", want: "json"},
		{name: "wrong type", args: map[string]any{"format": true}, def: "pretty", wantErr: true},
		{name: "blank uses default", args: map[string]any{"format": "   "}, def: "pretty", want: "pretty"},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			got, err := optionalString(tc.args, "format", tc.def)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("optionalString() error = %v", err)
			}
			if got != tc.want {
				t.Fatalf("optionalString() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestOptionalBool(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		args    map[string]any
		def     bool
		want    bool
		wantErr bool
	}{
		{name: "missing uses default true", args: map[string]any{}, def: true, want: true},
		{name: "present true", args: map[string]any{"history": true}, def: false, want: true},
		{name: "present false", args: map[string]any{"history": false}, def: true, want: false},
		{name: "wrong type", args: map[string]any{"history": "true"}, def: false, wantErr: true},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			got, err := optionalBool(tc.args, "history", tc.def)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("optionalBool() error = %v", err)
			}
			if got != tc.want {
				t.Fatalf("optionalBool() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestResolvePath(t *testing.T) {
	t.Parallel()

	if _, err := resolvePath(""); err == nil {
		t.Fatalf("resolvePath(\"\") expected error")
	}

	home, err := resolvePath("~")
	if err != nil || home == "" {
		t.Fatalf("resolvePath(\"~\") = (%q, %v), expected home path", home, err)
	}

	expanded, err := resolvePath("~/foo")
	if err != nil {
		t.Fatalf("resolvePath(\"~/foo\") error = %v", err)
	}
	if !strings.HasPrefix(expanded, home) {
		t.Fatalf("resolvePath(\"~/foo\") = %q, expected prefix %q", expanded, home)
	}

	abs := "/tmp/shogunhound.log"
	got, err := resolvePath(abs)
	if err != nil {
		t.Fatalf("resolvePath(abs) error = %v", err)
	}
	if got != abs {
		t.Fatalf("resolvePath(abs) = %q, want %q", got, abs)
	}
}

func TestHumanizeErrorAndSearchError(t *testing.T) {
	t.Parallel()

	ip := "8.8.8.8"
	raw := "upstream raw details"

	if got := humanizeError(ip, shodan.ErrUnauthorized); got != "Shodan authentication failed; check your API key" {
		t.Fatalf("unexpected unauthorized message: %q", got)
	}
	if got := humanizeError(ip, shodan.ErrRateLimited); got != "Shodan rate limit exceeded; wait 60 seconds and retry" {
		t.Fatalf("unexpected rate-limit message: %q", got)
	}
	if got := humanizeError(ip, shodan.ErrNotFound); got != "No Shodan data found for 8.8.8.8; host may not be indexed" {
		t.Fatalf("unexpected not-found message: %q", got)
	}
	if got := humanizeError(ip, context.DeadlineExceeded); got != "Shodan query timed out after 4 seconds; try again" {
		t.Fatalf("unexpected timeout message: %q", got)
	}
	if got := humanizeError(ip, context.Canceled); got != "Shodan API error; try again later" {
		t.Fatalf("unexpected default message: %q", got)
	}
	if got := humanizeError(ip, errors.New(raw)); strings.Contains(got, raw) {
		t.Fatalf("default message leaked raw error: %q", got)
	}

	if got := humanizeSearchError(shodan.ErrUnauthorized); got != "Shodan authentication failed; check your API key" {
		t.Fatalf("unexpected search unauthorized message: %q", got)
	}
	if got := humanizeSearchError(shodan.ErrRateLimited); got != "Shodan rate limit exceeded; wait 60 seconds and retry" {
		t.Fatalf("unexpected search rate-limit message: %q", got)
	}
	if got := humanizeSearchError(shodan.ErrNotFound); got != "No results found for that query; the search returned no indexed hosts" {
		t.Fatalf("unexpected search not-found message: %q", got)
	}
	if got := humanizeSearchError(context.DeadlineExceeded); got != "Shodan query timed out; try again" {
		t.Fatalf("unexpected search timeout message: %q", got)
	}
	if got := humanizeSearchError(errors.New(raw)); strings.Contains(got, raw) {
		t.Fatalf("search default message leaked raw error: %q", got)
	}
}

func TestSplitCSVOrLinesHandlesCRLF(t *testing.T) {
	t.Parallel()

	got := splitCSVOrLines("8.8.8.8\r\n1.1.1.1\r\n9.9.9.9")
	if len(got) != 3 {
		t.Fatalf("unexpected item count: got %d (%v)", len(got), got)
	}
	if got[0] != "8.8.8.8" || got[1] != "1.1.1.1" || got[2] != "9.9.9.9" {
		t.Fatalf("unexpected normalized values: %v", got)
	}
}

func TestHandleShodanIPQueryMissingIP(t *testing.T) {
	t.Parallel()

	h := newTestHandler(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "should not call upstream", http.StatusInternalServerError)
	}))
	defer func() { _ = h.Close() }()

	req := mcp.CallToolRequest{
		Params: mcp.CallToolParams{
			Name:      "shodan_ip_query",
			Arguments: map[string]any{},
		},
	}

	result, err := h.HandleShodanIPQuery(context.Background(), req)
	if err != nil {
		t.Fatalf("HandleShodanIPQuery() error = %v", err)
	}
	if !result.IsError {
		t.Fatalf("expected tool error result")
	}
	if got := extractText(result); got != "missing required parameter: ip" {
		t.Fatalf("unexpected error text: %q", got)
	}
}

func TestHandleShodanIPQueryInvalidIP(t *testing.T) {
	t.Parallel()

	h := newTestHandler(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "should not call upstream", http.StatusInternalServerError)
	}))
	defer func() { _ = h.Close() }()

	req := mcp.CallToolRequest{
		Params: mcp.CallToolParams{
			Name:      "shodan_ip_query",
			Arguments: map[string]any{"ip": "not-an-ip"},
		},
	}

	result, err := h.HandleShodanIPQuery(context.Background(), req)
	if err != nil {
		t.Fatalf("HandleShodanIPQuery() error = %v", err)
	}
	if !result.IsError {
		t.Fatalf("expected tool error result")
	}
	if got := extractText(result); !strings.Contains(got, "invalid IP address: not-an-ip") {
		t.Fatalf("unexpected error text: %q", got)
	}
}

func TestHandleShodanIPQueryCacheHit(t *testing.T) {
	t.Parallel()

	callCount := 0
	h := newTestHandlerWithCache(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		http.Error(w, "unexpected upstream call", http.StatusInternalServerError)
	}))
	defer func() { _ = h.Close() }()

	h.cache.Set("8.8.8.8", &shodan.ShodanHostResult{IP: "8.8.8.8", Organization: "Google LLC"})

	req := mcp.CallToolRequest{
		Params: mcp.CallToolParams{
			Name:      "shodan_ip_query",
			Arguments: map[string]any{"ip": "8.8.8.8", "format": "markdown"},
		},
	}

	result, err := h.HandleShodanIPQuery(context.Background(), req)
	if err != nil {
		t.Fatalf("HandleShodanIPQuery() error = %v", err)
	}
	if result.IsError {
		t.Fatalf("expected non-error result, got %q", extractText(result))
	}
	out := extractText(result)
	if !strings.Contains(out, "> [cached · fetched") {
		t.Fatalf("expected cache note in output, got: %q", out)
	}
	if callCount != 0 {
		t.Fatalf("unexpected upstream calls: %d", callCount)
	}
}

func TestHandleShodanIPQueryCacheMissSuccessSetsCache(t *testing.T) {
	t.Parallel()

	h := newTestHandlerWithCache(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"ip_str":"8.8.8.8",
			"org":"Google LLC",
			"country_name":"United States",
			"ports":[53],
			"hostnames":["dns.google"],
			"data":[{"port":53,"transport":"udp","data":"ok","_shodan":{"module":"dns-udp"}}]
		}`))
	}))
	defer func() { _ = h.Close() }()

	req := mcp.CallToolRequest{
		Params: mcp.CallToolParams{
			Name: "shodan_ip_query",
			Arguments: map[string]any{
				"ip":     "8.8.8.8",
				"format": "json",
				"tier":   "paid",
			},
		},
	}

	result, err := h.HandleShodanIPQuery(context.Background(), req)
	if err != nil {
		t.Fatalf("HandleShodanIPQuery() error = %v", err)
	}
	if result.IsError {
		t.Fatalf("expected non-error result, got %q", extractText(result))
	}
	if got := extractText(result); !strings.Contains(got, `"IP": "8.8.8.8"`) {
		t.Fatalf("unexpected json output: %q", got)
	}

	cached, queriedAt, ok := h.cache.Get("8.8.8.8")
	if !ok || cached == nil || cached.IP != "8.8.8.8" || queriedAt.IsZero() {
		t.Fatalf("expected cached result, got (%+v, %v, %v)", cached, queriedAt, ok)
	}
}

func TestHandleShodanIPQueryNotFoundHumanized(t *testing.T) {
	t.Parallel()

	h := newTestHandler(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "404 no information available for that ip", http.StatusNotFound)
	}))
	defer func() { _ = h.Close() }()

	req := mcp.CallToolRequest{
		Params: mcp.CallToolParams{
			Name: "shodan_ip_query",
			Arguments: map[string]any{
				"ip":   "8.8.8.8",
				"tier": "paid",
			},
		},
	}

	result, err := h.HandleShodanIPQuery(context.Background(), req)
	if err != nil {
		t.Fatalf("HandleShodanIPQuery() error = %v", err)
	}
	if !result.IsError {
		t.Fatalf("expected error result")
	}
	if got := extractText(result); got != "No Shodan data found for 8.8.8.8; host may not be indexed" {
		t.Fatalf("unexpected error text: %q", got)
	}
}

func newTestHandler(t *testing.T, upstream http.Handler) *ToolHandler {
	t.Helper()
	return newTestHandlerWithCache(t, upstream)
}

func newTestHandlerWithCache(t *testing.T, upstream http.Handler) *ToolHandler {
	t.Helper()

	server := httptest.NewServer(upstream)
	t.Cleanup(server.Close)

	cachePath := filepath.Join(t.TempDir(), "cache.json")
	c, err := cache.New(cachePath)
	if err != nil {
		t.Fatalf("cache.New() error = %v", err)
	}

	client := shodan.NewClient("test-key", "paid")
	client.SetBaseURL(server.URL)

	logPath := filepath.Join(t.TempDir(), "queries.log")
	h, err := New(c, client, logPath)
	if err != nil {
		t.Fatalf("handler.New() error = %v", err)
	}
	return h
}

func extractText(result *mcp.CallToolResult) string {
	if result == nil || len(result.Content) == 0 {
		return ""
	}
	text, ok := result.Content[0].(mcp.TextContent)
	if !ok {
		return ""
	}
	return text.Text
}
