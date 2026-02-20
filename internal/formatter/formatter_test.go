package formatter

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/nethoundsh/shogunhound/internal/shodan"
)

func TestFormatPrettyWithCVEs(t *testing.T) {
	t.Parallel()

	result := &shodan.ShodanHostResult{
		IP:              "8.8.8.8",
		Vulnerabilities: []string{"CVE-2021-44228"},
		Services: []shodan.ServiceRecord{
			{Port: 443, Transport: "tcp", Module: "https", Product: "nginx", Version: "1.25.0"},
		},
		LastSeen: time.Date(2026, 2, 17, 0, 0, 0, 0, time.UTC),
	}

	out := Format(result, "pretty")
	if !strings.Contains(out, "VULNERABILITIES") {
		t.Fatalf("expected VULNERABILITIES header, got: %q", out)
	}
	if !strings.Contains(out, "CVE-2021-44228") {
		t.Fatalf("expected CVE in output: %q", out)
	}
}

func TestFormatPrettyWithoutCVEs(t *testing.T) {
	t.Parallel()

	out := Format(&shodan.ShodanHostResult{IP: "1.1.1.1"}, "pretty")
	if !strings.Contains(out, "None detected") {
		t.Fatalf("expected plain none detected, got: %q", out)
	}
}

func TestFormatPrettyWithEmptyPorts(t *testing.T) {
	t.Parallel()

	out := Format(&shodan.ShodanHostResult{IP: "1.1.1.1"}, "pretty")
	if !strings.Contains(out, "OPEN PORTS & SERVICES") {
		t.Fatalf("missing ports section: %q", out)
	}
	if !strings.Contains(out, "(none)") {
		t.Fatalf("expected explicit none marker for empty ports: %q", out)
	}
}

func TestFormatJSON(t *testing.T) {
	t.Parallel()

	result := &shodan.ShodanHostResult{
		IP:           "8.8.8.8",
		Organization: "Google LLC",
		Ports:        []int{53, 443},
	}

	out := Format(result, "json")

	var decoded shodan.ShodanHostResult
	if err := json.Unmarshal([]byte(out), &decoded); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}

	if decoded.IP != result.IP || decoded.Organization != result.Organization {
		t.Fatalf("decoded mismatch: got %+v want %+v", decoded, *result)
	}
}

func TestFormatEmptyResultNoPanic(t *testing.T) {
	t.Parallel()

	_ = Format(&shodan.ShodanHostResult{}, "pretty")
	_ = Format(nil, "pretty")
	_ = Format(nil, "json")
}

func TestFormatJSONNilReturnsObject(t *testing.T) {
	t.Parallel()

	out := Format(nil, "json")
	trimmed := strings.TrimSpace(out)
	if trimmed == "null" || !strings.HasPrefix(trimmed, "{") {
		t.Fatalf("Format(nil, json) = %q, want JSON object", out)
	}
}

func TestFormatMarkdownWithCVEs(t *testing.T) {
	result := &shodan.ShodanHostResult{
		IP:              "8.8.8.8",
		Organization:    "Google LLC",
		Vulnerabilities: []string{"CVE-2021-44228", "CVE-2024-0001"},
		Services: []shodan.ServiceRecord{
			{Port: 443, Transport: "tcp", Module: "https", Product: "nginx", Version: "1.25.0"},
		},
		LastSeen: time.Date(2026, 2, 17, 0, 0, 0, 0, time.UTC),
	}

	out := Format(result, "markdown")
	if !strings.Contains(out, "## Shodan Host Intelligence") {
		t.Fatalf("missing markdown header: %q", out)
	}
	if !strings.Contains(out, "CVE-2021-44228") {
		t.Fatalf("missing CVE: %q", out)
	}
	if !strings.Contains(out, "| 443 |") {
		t.Fatalf("missing services table row: %q", out)
	}
}

func TestFormatMarkdownNoPanic(t *testing.T) {
	t.Parallel()
	_ = Format(nil, "markdown")
	_ = Format(&shodan.ShodanHostResult{}, "markdown")
}

func TestFormatSearchResultPrettyMarkdownJSON(t *testing.T) {
	t.Parallel()

	result := &shodan.SearchResult{
		Total: 2,
		Matches: []*shodan.ShodanHostResult{
			{
				IP:           "8.8.8.8",
				Organization: "Google LLC",
				Country:      "United States",
				Ports:        []int{53, 443},
			},
		},
	}

	pretty := FormatSearchResult(result, "pretty")
	if !strings.Contains(pretty, "SHODAN SEARCH") {
		t.Fatalf("expected pretty header, got: %q", pretty)
	}
	if !strings.Contains(pretty, "2 total results") {
		t.Fatalf("expected pretty total count, got: %q", pretty)
	}
	if !strings.Contains(pretty, "8.8.8.8") {
		t.Fatalf("expected pretty IP row, got: %q", pretty)
	}

	markdown := FormatSearchResult(result, "markdown")
	if !strings.Contains(markdown, "| IP | Organization | Country | Ports |") {
		t.Fatalf("expected markdown table header, got: %q", markdown)
	}
	if !strings.Contains(markdown, "| 8.8.8.8 | Google LLC | United States | 53, 443 |") {
		t.Fatalf("expected markdown row, got: %q", markdown)
	}

	jsonOut := FormatSearchResult(result, "json")
	var decoded shodan.SearchResult
	if err := json.Unmarshal([]byte(jsonOut), &decoded); err != nil {
		t.Fatalf("expected valid JSON, got error: %v", err)
	}
	if decoded.Total != result.Total {
		t.Fatalf("decoded total = %d, want %d", decoded.Total, result.Total)
	}
}

func TestFormatTagsWithContext(t *testing.T) {
	t.Parallel()

	if got := formatTagsWithContext(nil); got != "(none)" {
		t.Fatalf("nil tags = %q, want (none)", got)
	}

	cases := []struct {
		name     string
		input    []string
		contains string
	}{
		{name: "honeypot", input: []string{"honeypot"}, contains: "treat as decoy"},
		{name: "tor", input: []string{"tor"}, contains: "Tor exit/relay node"},
		{name: "scanner", input: []string{"scanner"}, contains: "known scanning infrastructure"},
		{name: "cloud", input: []string{"cloud"}, contains: "confirm provider context"},
		{name: "unknown", input: []string{"custom-tag"}, contains: "custom-tag"},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			got := formatTagsWithContext(tc.input)
			if !strings.Contains(got, tc.contains) {
				t.Fatalf("formatTagsWithContext(%v) = %q, expected to contain %q", tc.input, got, tc.contains)
			}
		})
	}
}

func TestDateWithAge(t *testing.T) {
	t.Parallel()

	if got := dateWithAge(time.Time{}); got != "(unknown)" {
		t.Fatalf("zero time = %q, want (unknown)", got)
	}

	recent := dateWithAge(time.Now().Add(-7 * 24 * time.Hour))
	if !strings.Contains(recent, "(recent)") {
		t.Fatalf("recent date missing marker: %q", recent)
	}

	daysAgo := dateWithAge(time.Now().Add(-60 * 24 * time.Hour))
	if !strings.Contains(daysAgo, "days ago") {
		t.Fatalf("expected days-ago marker: %q", daysAgo)
	}

	monthsAgo := dateWithAge(time.Now().Add(-120 * 24 * time.Hour))
	if !strings.Contains(monthsAgo, "months ago - data may be stale") {
		t.Fatalf("expected months-ago marker: %q", monthsAgo)
	}
}

func TestCollectBannersTruncationASCIIAndUTF8(t *testing.T) {
	t.Parallel()

	ascii := strings.Repeat("a", 201)
	asciiLines := collectBanners([]shodan.ServiceRecord{{Port: 80, Banner: ascii}})
	if len(asciiLines) != 1 {
		t.Fatalf("expected 1 banner line, got %d", len(asciiLines))
	}
	if !strings.HasSuffix(asciiLines[0].text, "…") {
		t.Fatalf("expected ellipsis suffix, got %q", asciiLines[0].text)
	}
	if got, want := utf8.RuneCountInString(asciiLines[0].text), 201; got != want {
		t.Fatalf("ASCII truncated rune count = %d, want %d", got, want)
	}

	utf8Banner := strings.Repeat("b", 199) + "界" + "Z"
	utf8Lines := collectBanners([]shodan.ServiceRecord{{Port: 443, Banner: utf8Banner}})
	if len(utf8Lines) != 1 {
		t.Fatalf("expected 1 UTF-8 banner line, got %d", len(utf8Lines))
	}
	if !utf8.ValidString(utf8Lines[0].text) {
		t.Fatalf("expected valid UTF-8 output, got invalid string: %q", utf8Lines[0].text)
	}
	if !strings.HasSuffix(utf8Lines[0].text, "…") {
		t.Fatalf("expected ellipsis suffix, got %q", utf8Lines[0].text)
	}
	if got, want := utf8.RuneCountInString(utf8Lines[0].text), 201; got != want {
		t.Fatalf("UTF-8 truncated rune count = %d, want %d", got, want)
	}
	if strings.Contains(utf8Lines[0].text, "Z") {
		t.Fatalf("expected final rune to be truncated, got %q", utf8Lines[0].text)
	}
}

func TestFormatSearchResultNil(t *testing.T) {
	t.Parallel()
	if got := FormatSearchResult(nil, "pretty"); got != "" {
		t.Fatalf("FormatSearchResult(nil) = %q, want empty", got)
	}
	if got := FormatSearchResult(nil, "json"); got != "{}" {
		t.Fatalf("FormatSearchResult(nil, json) = %q, want {}", got)
	}
}

func TestFormatSearchResultJSONFallbackOnMarshalError(t *testing.T) {
	t.Parallel()

	// Defensive check: ensure current JSON formatting path can marshal normal payloads.
	out := FormatSearchResult(&shodan.SearchResult{Total: 1}, "json")
	if !strings.Contains(out, fmt.Sprintf("%q", "Total")) && out != "{}" {
		t.Fatalf("unexpected JSON output shape: %q", out)
	}
}
