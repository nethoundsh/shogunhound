package shodan

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sort"
	"strings"
	"time"

	goshodan "github.com/ns3777k/go-shodan/v4/shodan"
)

var (
	ErrRateLimited  = errors.New("rate limited")
	ErrNotFound     = errors.New("not found")
	ErrUnauthorized = errors.New("unauthorized")
)

type ShodanClient struct {
	client *goshodan.Client
	tier   string // "free" or "paid"
}

type SearchResult struct {
	Total   int
	Matches []*ShodanHostResult
}

func NewClient(apiKey, tier string) *ShodanClient {
	return &ShodanClient{
		client: goshodan.NewClient(http.DefaultClient, apiKey),
		tier:   normalizeTier(tier),
	}
}

func (c *ShodanClient) SetTier(tier string) {
	c.tier = normalizeTier(tier)
}

func (c *ShodanClient) QueryHost(ctx context.Context, ip string, history, minify bool) (*ShodanHostResult, error) {
	ctx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()

	options := &goshodan.HostServicesOptions{
		History: history,
		Minify:  minify,
	}
	req, err := c.client.NewRequest(http.MethodGet, "/shodan/host/"+ip, options, nil)
	if err != nil {
		return nil, err
	}

	var host hostResponse
	if err := c.client.Do(ctx, req, &host); err != nil {
		return nil, mapAPIError(err)
	}

	result := mapHostToResult(&host.Host, host.Tags, minify)

	// Enforce rate limit after a successful fetch. The sleep is context-aware
	// so a canceled context exits immediately. Note: this sleep shares the
	// same 4-second timeout context as the HTTP call; if the response arrived
	// near deadline, sleep can return DeadlineExceeded after a valid fetch.
	// Callers should treat DeadlineExceeded from QueryHost as uncertain.
	if err := sleepWithContext(ctx, rateLimitDelay(c.tier)); err != nil {
		return nil, err
	}

	return result, nil
}

func (c *ShodanClient) Count(ctx context.Context, query string) (int, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	result, err := c.client.GetHostsCountForQuery(ctx, &goshodan.HostQueryOptions{Query: query})
	if err != nil {
		return 0, mapAPIError(err)
	}

	return result.Total, nil
}

func (c *ShodanClient) Search(ctx context.Context, query string, page int) (*SearchResult, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	if page < 1 {
		page = 1
	}

	result, err := c.client.GetHostsForQuery(ctx, &goshodan.HostQueryOptions{
		Query: query,
		Page:  page,
	})
	if err != nil {
		return nil, mapAPIError(err)
	}

	search := &SearchResult{Total: result.Total}
	for _, match := range result.Matches {
		if match == nil {
			continue
		}
		search.Matches = append(search.Matches, mapHostDataToResult(match))
	}

	return search, nil
}

func (c *ShodanClient) DNSResolve(ctx context.Context, hostnames []string) (map[string]string, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	result, err := c.client.GetDNSResolve(ctx, hostnames)
	if err != nil {
		return nil, mapAPIError(err)
	}

	out := make(map[string]string, len(result))
	for hostname, ip := range result {
		if ip == nil {
			out[hostname] = ""
			continue
		}
		out[hostname] = ip.String()
	}

	return out, nil
}

func (c *ShodanClient) DNSReverse(ctx context.Context, ips []string) (map[string][]string, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	netIPs := make([]net.IP, 0, len(ips))
	for _, ipStr := range ips {
		parsed := net.ParseIP(ipStr)
		if parsed == nil {
			return nil, fmt.Errorf("invalid IP address: %s", ipStr)
		}
		netIPs = append(netIPs, parsed)
	}

	result, err := c.client.GetDNSReverse(ctx, netIPs)
	if err != nil {
		return nil, mapAPIError(err)
	}

	out := make(map[string][]string, len(result))
	for ip, hostnames := range result {
		if hostnames == nil {
			out[ip] = nil
			continue
		}
		out[ip] = append([]string(nil), (*hostnames)...)
	}

	return out, nil
}

// hostResponse extends goshodan.Host to capture the tags field, which is
// present in Shodan's API response but absent from the upstream Host struct.
type hostResponse struct {
	goshodan.Host
	Tags []string `json:"tags"`
}

func mapHostToResult(host *goshodan.Host, tags []string, minify bool) *ShodanHostResult {
	result := &ShodanHostResult{
		Organization: host.Organization,
		ISP:          host.ISP,
		ASN:          host.ASN,
		Country:      host.Country,
		City:         host.City,
		OS:           host.OS,
		Ports:        append([]int(nil), host.Ports...),
		Hostnames:    append([]string(nil), host.Hostnames...),
		Tags:         append([]string(nil), tags...),
	}

	if host.IP != nil {
		result.IP = host.IP.String()
	}

	result.Vulnerabilities = append([]string(nil), host.Vulnerabilities...)
	sort.Strings(result.Vulnerabilities)

	for _, data := range host.Data {
		if data == nil {
			continue
		}

		var banner string
		if !minify {
			banner = data.Data
			if banner == "" {
				banner = data.Banner
			}
		}

		version := ""
		if v := data.Version.String(); v != "" {
			version = v
		}

		result.Services = append(result.Services, ServiceRecord{
			Port:      data.Port,
			Transport: data.Transport,
			Module:    moduleFromShodanData(data.ShodanData),
			Product:   data.Product,
			Version:   version,
			Banner:    banner,
			CPE:       append([]string(nil), data.CPE...),
		})
	}

	if host.LastUpdate != "" {
		if ts, err := time.Parse(time.RFC3339, host.LastUpdate); err == nil {
			result.LastSeen = ts
		} else if ts, err := time.Parse(time.RFC3339Nano, host.LastUpdate); err == nil {
			result.LastSeen = ts
		}
	}

	return result
}

func mapHostDataToResult(data *goshodan.HostData) *ShodanHostResult {
	r := &ShodanHostResult{
		Organization: data.Organization,
		ISP:          data.ISP,
		ASN:          data.ASN,
		OS:           data.OS,
		Hostnames:    append([]string(nil), data.Hostnames...),
		Ports:        []int{data.Port},
	}

	if data.IP != nil {
		r.IP = data.IP.String()
	}

	if data.Location != nil {
		r.Country = data.Location.Country
		r.City = data.Location.City
	}

	banner := data.Data
	if banner == "" {
		banner = data.Banner
	}

	version := ""
	if v := data.Version.String(); v != "" {
		version = v
	}

	r.Services = []ServiceRecord{{
		Port:      data.Port,
		Transport: data.Transport,
		Module:    moduleFromShodanData(data.ShodanData),
		Product:   data.Product,
		Version:   version,
		Banner:    banner,
		CPE:       append([]string(nil), data.CPE...),
	}}

	return r
}

func moduleFromShodanData(data map[string]interface{}) string {
	if data == nil {
		return ""
	}

	raw, ok := data["module"]
	if !ok {
		return ""
	}

	module, ok := raw.(string)
	if !ok {
		return ""
	}

	return strings.TrimSpace(module)
}

func normalizeTier(tier string) string {
	if strings.EqualFold(tier, "paid") {
		return "paid"
	}
	return "free"
}

func rateLimitDelay(tier string) time.Duration {
	if normalizeTier(tier) == "paid" {
		return 100 * time.Millisecond
	}
	return 1000 * time.Millisecond
}

func sleepWithContext(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func mapAPIError(err error) error {
	// mapAPIError normalizes errors from go-shodan into sentinel values.
	// The library does not expose HTTP status codes directly, so we match
	// on the error message text. This is brittle against upstream changes.
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return err
	}

	msg := strings.ToLower(strings.TrimSpace(err.Error()))

	switch {
	case strings.Contains(msg, "401"), strings.Contains(msg, "invalid api key"), strings.Contains(msg, "unauthorized"):
		return ErrUnauthorized
	case strings.Contains(msg, "429"), strings.Contains(msg, "rate limit"):
		return ErrRateLimited
	case strings.Contains(msg, "404"), strings.Contains(msg, "no information available for that ip"):
		return ErrNotFound
	default:
		return fmt.Errorf("shodan API error: %w", err)
	}
}
