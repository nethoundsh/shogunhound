package shodan

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestQueryHostSuccess(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/shodan/host/8.8.8.8" {
			http.Error(w, "unexpected path", http.StatusBadRequest)
			return
		}

		if got := r.URL.Query().Get("history"); got != "true" {
			http.Error(w, "missing history=true", http.StatusBadRequest)
			return
		}

		if got := r.URL.Query().Get("key"); got != "test-key" {
			http.Error(w, "missing key", http.StatusBadRequest)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"ip_str":"8.8.8.8",
			"org":"Google LLC",
			"isp":"Google LLC",
			"asn":"AS15169",
			"country_name":"United States",
			"city":"Mountain View",
			"os":"Linux",
			"ports":[53,443],
			"hostnames":["dns.google"],
			"tags":["cdn","self-signed"],
			"vulns":["CVE-2024-0002","CVE-2021-44228"],
			"last_update":"2026-02-17T00:00:00Z",
			"data":[
				{
					"port":53,
					"transport":"udp",
					"product":"dns",
					"version":"1.2.3",
					"data":"recursion available",
					"cpe":["cpe:/a:example:dns:1.2.3"],
					"_shodan":{"module":"dns-udp"}
				}
			]
		}`))
	}))
	defer server.Close()

	client := NewClient("test-key", "paid")
	client.client.BaseURL = server.URL

	result, err := client.QueryHost(context.Background(), "8.8.8.8", true, false)
	if err != nil {
		t.Fatalf("QueryHost() error = %v", err)
	}

	if result.IP != "8.8.8.8" || result.Organization != "Google LLC" || result.ISP != "Google LLC" {
		t.Fatalf("unexpected identity mapping: %+v", result)
	}

	if len(result.Vulnerabilities) != 2 || result.Vulnerabilities[0] != "CVE-2021-44228" {
		t.Fatalf("unexpected vulnerabilities mapping: %+v", result.Vulnerabilities)
	}

	if len(result.Services) != 1 {
		t.Fatalf("expected 1 service, got %d", len(result.Services))
	}
	if len(result.Tags) != 2 || result.Tags[0] != "cdn" || result.Tags[1] != "self-signed" {
		t.Fatalf("unexpected tags mapping: %+v", result.Tags)
	}

	svc := result.Services[0]
	if svc.Module != "dns-udp" || svc.Banner != "recursion available" || svc.Transport != "udp" {
		t.Fatalf("unexpected service mapping: %+v", svc)
	}
}

func TestQueryHostUnauthorized(t *testing.T) {
	t.Parallel()

	client := newTestClientWithStatus(t, http.StatusUnauthorized)
	_, err := client.QueryHost(context.Background(), "8.8.8.8", false, false)
	if !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("error = %v, want ErrUnauthorized", err)
	}
}

func TestQueryHostRateLimited(t *testing.T) {
	t.Parallel()

	client := newTestClientWithStatus(t, http.StatusTooManyRequests)
	_, err := client.QueryHost(context.Background(), "8.8.8.8", false, false)
	if !errors.Is(err, ErrRateLimited) {
		t.Fatalf("error = %v, want ErrRateLimited", err)
	}
}

func TestQueryHostNotFound(t *testing.T) {
	t.Parallel()

	client := newTestClientWithStatus(t, http.StatusNotFound)
	_, err := client.QueryHost(context.Background(), "8.8.8.8", false, false)
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("error = %v, want ErrNotFound", err)
	}
}

func TestQueryHostTimeout(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(5 * time.Second)
		_, _ = w.Write([]byte(`{"ip_str":"8.8.8.8"}`))
	}))
	defer server.Close()

	client := NewClient("test-key", "paid")
	client.client.BaseURL = server.URL

	_, err := client.QueryHost(context.Background(), "8.8.8.8", false, false)
	if err == nil {
		t.Fatalf("expected timeout error, got nil")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("error = %T %v, want context.DeadlineExceeded", err, err)
	}
}

func TestQueryHostMalformedJSON(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("{invalid"))
	}))
	defer server.Close()

	client := NewClient("test-key", "paid")
	client.client.BaseURL = server.URL

	_, err := client.QueryHost(context.Background(), "8.8.8.8", false, false)
	if err == nil {
		t.Fatalf("expected decode error, got nil")
	}
}

func TestQueryHostRespectsContextDuringRateLimitSleep(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{
			"ip_str":"8.8.8.8",
			"ports":[53],
			"hostnames":[]
		}`))
	}))
	defer server.Close()

	client := NewClient("test-key", "free")
	client.client.BaseURL = server.URL

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, err := client.QueryHost(ctx, "8.8.8.8", false, false)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatalf("expected context cancellation during sleep")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("error = %v, want context.DeadlineExceeded", err)
	}
	if elapsed > 300*time.Millisecond {
		t.Fatalf("query took too long; sleep did not respect context: %v", elapsed)
	}
}

func TestCountSuccess(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.Path, "count") {
			http.Error(w, "wrong path", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"total": 42}`))
	}))
	defer server.Close()

	client := NewClient("test-key", "free")
	client.client.BaseURL = server.URL

	count, err := client.Count(context.Background(), "nginx")
	if err != nil {
		t.Fatalf("Count() error = %v", err)
	}
	if count != 42 {
		t.Fatalf("Count() = %d, want 42", count)
	}
}

func TestCountUnauthorized(t *testing.T) {
	t.Parallel()

	client := newTestClientWithStatus(t, http.StatusUnauthorized)
	_, err := client.Count(context.Background(), "nginx")
	if !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("error = %v, want ErrUnauthorized", err)
	}
}

func TestSearchSuccess(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/shodan/host/search" {
			http.Error(w, "wrong path", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"total": 1,
			"matches": [{
				"ip_str": "1.2.3.4",
				"org": "Acme Corp",
				"country_name": "United States",
				"city": "Austin",
				"port": 443,
				"transport": "tcp",
				"product": "nginx",
				"version": "1.25.0",
				"hostnames": ["app.acme.test"],
				"data": "HTTP/1.1 200 OK",
				"_shodan": {"module": "https"}
			}]
		}`))
	}))
	defer server.Close()

	client := NewClient("test-key", "free")
	client.client.BaseURL = server.URL

	result, err := client.Search(context.Background(), "port:443", 1)
	if err != nil {
		t.Fatalf("Search() error = %v", err)
	}
	if result.Total != 1 || len(result.Matches) != 1 {
		t.Fatalf("unexpected search result shape: %+v", result)
	}
	if result.Matches[0].IP != "1.2.3.4" || result.Matches[0].Services[0].Module != "https" {
		t.Fatalf("unexpected mapped match: %+v", result.Matches[0])
	}
}

func TestDNSResolveSuccess(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/dns/resolve" {
			http.Error(w, "wrong path", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"google.com":"8.8.8.8"}`))
	}))
	defer server.Close()

	client := NewClient("test-key", "free")
	client.client.BaseURL = server.URL

	result, err := client.DNSResolve(context.Background(), []string{"google.com"})
	if err != nil {
		t.Fatalf("DNSResolve() error = %v", err)
	}
	if result["google.com"] != "8.8.8.8" {
		t.Fatalf("unexpected DNS resolve result: %+v", result)
	}
}

func TestDNSReverseSuccess(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/dns/reverse" {
			http.Error(w, "wrong path", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"8.8.8.8":["dns.google"]}`))
	}))
	defer server.Close()

	client := NewClient("test-key", "free")
	client.client.BaseURL = server.URL

	result, err := client.DNSReverse(context.Background(), []string{"8.8.8.8"})
	if err != nil {
		t.Fatalf("DNSReverse() error = %v", err)
	}
	if len(result["8.8.8.8"]) != 1 || result["8.8.8.8"][0] != "dns.google" {
		t.Fatalf("unexpected DNS reverse result: %+v", result)
	}
}

func TestDNSReverseInvalidIP(t *testing.T) {
	t.Parallel()

	client := NewClient("test-key", "free")
	_, err := client.DNSReverse(context.Background(), []string{"not-an-ip"})
	if err == nil || !strings.Contains(err.Error(), "invalid IP address") {
		t.Fatalf("expected invalid ip error, got: %v", err)
	}
}

func newTestClientWithStatus(t *testing.T, status int) *ShodanClient {
	t.Helper()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, fmt.Sprintf("status %d", status), status)
	}))
	t.Cleanup(server.Close)

	client := NewClient("test-key", "paid")
	client.client.BaseURL = server.URL
	return client
}
