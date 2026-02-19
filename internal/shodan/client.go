package shodan

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
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
	mu     sync.RWMutex
}

type SearchResult struct {
	Total   int
	Matches []*ShodanHostResult
}

type Alert struct {
	ID      string
	Name    string
	Created string
	Expires int
	IPs     []string
}

type CVELookupResult struct {
	CVE               string
	AffectedHostCount int
	ExploitCount      int
	ExploitAvailable  bool
	CVSS              *float64
}

func NewClient(apiKey, tier string) *ShodanClient {
	return &ShodanClient{
		client: goshodan.NewClient(http.DefaultClient, apiKey),
		tier:   normalizeTier(tier),
	}
}

func (c *ShodanClient) SetBaseURL(baseURL string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.client.BaseURL = baseURL
}

func (c *ShodanClient) SetExploitBaseURL(baseURL string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.client.ExploitBaseURL = baseURL
}

func (c *ShodanClient) QueryHost(ctx context.Context, ip string, history, minify bool) (*ShodanHostResult, error) {
	return c.QueryHostWithTier(ctx, ip, history, minify, c.currentTier())
}

func (c *ShodanClient) QueryHostWithTier(
	ctx context.Context,
	ip string,
	history, minify bool,
	tier string,
) (*ShodanHostResult, error) {
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

	delay := rateLimitDelay(tier)
	sleepCtx, sleepCancel := context.WithTimeout(context.Background(), delay+200*time.Millisecond)
	defer sleepCancel()
	if err := sleepWithContext(sleepCtx, delay); err != nil {
		// A sleep interruption (e.g., process shutdown) does not invalidate the fetched result.
		return result, nil
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

func (c *ShodanClient) CreateAlert(ctx context.Context, name string, ipOrCIDRs []string, expires int) (*Alert, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	created, err := c.client.CreateAlert(ctx, name, ipOrCIDRs, expires)
	if err != nil {
		return nil, mapAPIError(err)
	}
	return mapAlert(created), nil
}

func (c *ShodanClient) ListAlerts(ctx context.Context) ([]*Alert, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	alerts, err := c.client.GetAlerts(ctx)
	if err != nil {
		return nil, mapAPIError(err)
	}

	out := make([]*Alert, 0, len(alerts))
	for _, a := range alerts {
		if a == nil {
			continue
		}
		out = append(out, mapAlert(a))
	}
	return out, nil
}

func (c *ShodanClient) DeleteAlert(ctx context.Context, id string) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	ok, err := c.client.DeleteAlert(ctx, id)
	if err != nil {
		return mapAPIError(err)
	}
	if !ok {
		return fmt.Errorf("shodan API error: delete alert failed")
	}
	return nil
}

func (c *ShodanClient) CVELookup(ctx context.Context, cve string) (*CVELookupResult, error) {
	cve = strings.ToUpper(strings.TrimSpace(cve))
	if cve == "" {
		return nil, fmt.Errorf("invalid CVE")
	}

	hostCount, err := c.Count(ctx, "vuln:"+cve)
	if err != nil {
		return nil, err
	}

	search, err := c.searchExploitsWithCVSS(ctx, cve)
	if err != nil {
		return nil, err
	}

	var maxCVSS *float64
	for _, m := range search.Matches {
		if m == nil || m.CVSS == nil {
			continue
		}
		if maxCVSS == nil || *m.CVSS > *maxCVSS {
			v := *m.CVSS
			maxCVSS = &v
		}
	}

	return &CVELookupResult{
		CVE:               cve,
		AffectedHostCount: hostCount,
		ExploitCount:      search.Total,
		ExploitAvailable:  search.Total > 0,
		CVSS:              maxCVSS,
	}, nil
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

func (c *ShodanClient) currentTier() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.tier
}

func mapAlert(in *goshodan.Alert) *Alert {
	out := &Alert{
		ID:      in.ID,
		Name:    in.Name,
		Created: in.Created,
		Expires: in.Expires,
	}
	if in.Filters != nil {
		out.IPs = append([]string(nil), in.Filters.IP...)
	}
	return out
}

type exploitSearchWithCVSS struct {
	Matches []*exploitMatchWithCVSS `json:"matches"`
	Total   int                     `json:"total"`
}

type exploitMatchWithCVSS struct {
	RawCVSS interface{} `json:"cvss"`
	CVSS    *float64    `json:"-"`
}

func (c *ShodanClient) searchExploitsWithCVSS(ctx context.Context, query string) (*exploitSearchWithCVSS, error) {
	// Bound exploit lookup latency while preserving any tighter parent deadline.
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	options := &goshodan.ExploitSearchOptions{Query: query, Page: 1}
	req, err := c.client.NewExploitRequest(http.MethodGet, "/search", options, nil)
	if err != nil {
		return nil, err
	}

	var found exploitSearchWithCVSS
	if err := c.client.Do(ctx, req, &found); err != nil {
		return nil, mapAPIError(err)
	}

	for _, m := range found.Matches {
		if m == nil {
			continue
		}
		switch v := m.RawCVSS.(type) {
		case float64:
			val := v
			m.CVSS = &val
		case string:
			parsed, perr := strconv.ParseFloat(strings.TrimSpace(v), 64)
			if perr == nil {
				m.CVSS = &parsed
			} else {
				m.CVSS = nil
			}
		default:
			m.CVSS = nil
		}
	}

	return &found, nil
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
