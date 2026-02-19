package formatter

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/nethoundsh/shogunhound/internal/shodan"
)

func TestFormatPrettyWithCVEs(t *testing.T) {
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
