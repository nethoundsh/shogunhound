package formatter

import (
	"encoding/json"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/nethoundsh/shogunhound/internal/shodan"
)

const headerLine = "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

func Format(result *shodan.ShodanHostResult, format string) string {
	if result == nil {
		result = &shodan.ShodanHostResult{}
	}

	switch format {
	case "json":
		out, err := json.MarshalIndent(result, "", " ")
		if err != nil {
			return "{}"
		}
		return string(out)
	case "markdown":
		return formatMarkdown(result)
	}

	var b strings.Builder

	fmt.Fprintf(&b, "%s\n", headerLine)
	fmt.Fprintf(&b, " SHODAN HOST INTELLIGENCE — %s\n", valueOr(result.IP, "(unknown)"))
	fmt.Fprintf(&b, "%s\n\n", headerLine)

	fmt.Fprintf(&b, "IDENTITY\n")
	fmt.Fprintf(&b, " %-12s : %s\n", "Organization", valueOr(result.Organization, "(unknown)"))
	fmt.Fprintf(&b, " %-12s : %s\n", "ISP", valueOr(result.ISP, "(unknown)"))
	fmt.Fprintf(&b, " %-12s : %s\n", "ASN", valueOr(result.ASN, "(unknown)"))
	fmt.Fprintf(&b, " %-12s : %s\n", "OS", valueOr(result.OS, "(unknown)"))
	fmt.Fprintf(&b, " %-12s : %s\n", "Hostnames", joinOr(result.Hostnames, "(none)"))
	fmt.Fprintf(&b, " %-12s : %s\n", "Tags", formatTagsWithContext(result.Tags))
	fmt.Fprintf(&b, " %-12s : %s\n\n", "Last Seen", dateWithAge(result.LastSeen))

	fmt.Fprintf(&b, "LOCATION\n")
	fmt.Fprintf(&b, " %-7s : %s\n", "Country", valueOr(result.Country, "(unknown)"))
	fmt.Fprintf(&b, " %-7s : %s\n\n", "City", valueOr(result.City, "(unknown)"))

	if len(result.Vulnerabilities) > 0 {
		fmt.Fprintf(&b, "VULNERABILITIES\n")
		for _, cve := range result.Vulnerabilities {
			fmt.Fprintf(&b, " %s\n", cve)
		}
	} else {
		fmt.Fprintf(&b, "VULNERABILITIES\n")
		fmt.Fprintf(&b, " None detected\n")
	}
	fmt.Fprintf(&b, "\n")

	fmt.Fprintf(&b, "OPEN PORTS & SERVICES\n")
	if len(result.Services) == 0 {
		fmt.Fprintf(&b, " (none)\n")
	} else {
		for _, service := range result.Services {
			portProto := fmt.Sprintf("%d/%s", service.Port, valueOr(service.Transport, "tcp"))
			fmt.Fprintf(&b, " %-9s %-8s", portProto, strings.TrimSpace(service.Module))
			if productVersion := strings.TrimSpace(service.Product + " " + service.Version); productVersion != "" {
				fmt.Fprintf(&b, " — %s", productVersion)
			}
			if len(service.CPE) > 0 {
				fmt.Fprintf(&b, " [%s]", strings.Join(service.CPE, ", "))
			}
			fmt.Fprintf(&b, "\n")
		}
	}

	banners := collectBanners(result.Services)
	if len(banners) > 0 {
		fmt.Fprintf(&b, "\nBANNERS\n")
		for _, banner := range banners {
			fmt.Fprintf(&b, " Port %d: %s\n", banner.port, banner.text)
		}
	}

	return b.String()
}

func FormatSearchResult(result *shodan.SearchResult, format string) string {
	if result == nil {
		if format == "json" {
			return "{}"
		}
		return ""
	}

	switch format {
	case "json":
		out, err := json.MarshalIndent(result, "", " ")
		if err != nil {
			return "{}"
		}
		return string(out)
	case "markdown":
		return formatSearchResultMarkdown(result)
	default:
		return formatSearchResultPretty(result)
	}
}

type bannerLine struct {
	port int
	text string
}

func collectBanners(services []shodan.ServiceRecord) []bannerLine {
	lines := make([]bannerLine, 0, len(services))
	for _, service := range services {
		text := strings.TrimSpace(service.Banner)
		if text == "" {
			continue
		}
		if len([]rune(text)) > 200 {
			text = truncateRunes(text, 200) + "…"
		}
		lines = append(lines, bannerLine{
			port: service.Port,
			text: text,
		})
	}
	return lines
}

func truncateRunes(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n])
}

func valueOr(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}

func joinOr(values []string, fallback string) string {
	if len(values) == 0 {
		return fallback
	}
	return strings.Join(values, ", ")
}

func formatTagsWithContext(tags []string) string {
	if len(tags) == 0 {
		return "(none)"
	}

	annotated := make([]string, 0, len(tags))
	for _, tag := range tags {
		switch strings.ToLower(strings.TrimSpace(tag)) {
		case "honeypot":
			annotated = append(annotated, "honeypot (treat as decoy - not a real target)")
		case "tor":
			annotated = append(annotated, "tor (Tor exit/relay node)")
		case "scanner":
			annotated = append(annotated, "scanner (known scanning infrastructure)")
		case "cloud":
			annotated = append(annotated, "cloud (confirm provider context via organization/ASN)")
		default:
			annotated = append(annotated, tag)
		}
	}

	return strings.Join(annotated, ", ")
}

func formatMarkdown(result *shodan.ShodanHostResult) string {
	var b strings.Builder

	fmt.Fprintf(&b, "## Shodan Host Intelligence — %s\n\n", valueOr(result.IP, "(unknown)"))
	fmt.Fprintf(&b, "**Organization:** %s | **ISP:** %s | **ASN:** %s\n", valueOr(result.Organization, "(unknown)"), valueOr(result.ISP, "(unknown)"), valueOr(result.ASN, "(unknown)"))
	fmt.Fprintf(&b, "**Country:** %s | **City:** %s\n", valueOr(result.Country, "(unknown)"), valueOr(result.City, "(unknown)"))
	fmt.Fprintf(&b, "**OS:** %s | **Last Seen:** %s\n", valueOr(result.OS, "(unknown)"), dateWithAge(result.LastSeen))
	fmt.Fprintf(&b, "**Hostnames:** %s\n", joinOr(result.Hostnames, "(none)"))
	fmt.Fprintf(&b, "**Tags:** %s\n\n", formatTagsWithContext(result.Tags))

	fmt.Fprintf(&b, "### Vulnerabilities\n\n")
	if len(result.Vulnerabilities) == 0 {
		fmt.Fprintf(&b, "None detected.\n\n")
	} else {
		for _, cve := range result.Vulnerabilities {
			fmt.Fprintf(&b, "- %s\n", cve)
		}
		fmt.Fprintf(&b, "\n")
	}

	fmt.Fprintf(&b, "### Open Ports & Services\n\n")
	if len(result.Services) == 0 {
		fmt.Fprintf(&b, "None indexed.\n")
	} else {
		fmt.Fprintf(&b, "| Port | Transport | Module | Product/Version |\n")
		fmt.Fprintf(&b, "|------|-----------|--------|-----------------|\n")
		for _, service := range result.Services {
			productVersion := strings.TrimSpace(service.Product + " " + service.Version)
			if productVersion == "" {
				productVersion = "—"
			}
			if len(service.CPE) > 0 {
				productVersion += " [" + strings.Join(service.CPE, ", ") + "]"
			}
			fmt.Fprintf(&b, "| %d | %s | %s | %s |\n", service.Port, valueOr(service.Transport, "tcp"), valueOr(strings.TrimSpace(service.Module), "—"), productVersion)
		}
	}

	banners := collectBanners(result.Services)
	if len(banners) > 0 {
		fmt.Fprintf(&b, "\n\n### Banners\n\n")
		for i, banner := range banners {
			if i > 0 {
				fmt.Fprintf(&b, "\n")
			}
			fmt.Fprintf(&b, "**Port %d:** %s\n", banner.port, banner.text)
		}
	}

	return b.String()
}

func formatSearchResultPretty(result *shodan.SearchResult) string {
	var b strings.Builder

	fmt.Fprintf(&b, "%s\n", headerLine)
	fmt.Fprintf(&b, " SHODAN SEARCH — %d total results\n", result.Total)
	fmt.Fprintf(&b, "%s\n\n", headerLine)

	for _, match := range result.Matches {
		if match == nil {
			continue
		}
		fmt.Fprintf(&b, " %-16s  %-30s  %-16s  ports: %s\n",
			valueOr(match.IP, "(unknown)"),
			valueOr(match.Organization, "(unknown)"),
			valueOr(match.Country, "(unknown)"),
			joinPorts(match.Ports),
		)
	}

	return b.String()
}

func formatSearchResultMarkdown(result *shodan.SearchResult) string {
	var b strings.Builder

	fmt.Fprintf(&b, "## Shodan Search Results — %d total\n\n", result.Total)
	fmt.Fprintf(&b, "| IP | Organization | Country | Ports |\n")
	fmt.Fprintf(&b, "|----|--------------|---------|-------|\n")
	for _, match := range result.Matches {
		if match == nil {
			continue
		}
		fmt.Fprintf(&b, "| %s | %s | %s | %s |\n",
			valueOr(match.IP, "(unknown)"),
			valueOr(match.Organization, "(unknown)"),
			valueOr(match.Country, "(unknown)"),
			joinPorts(match.Ports),
		)
	}

	return b.String()
}

func joinPorts(ports []int) string {
	if len(ports) == 0 {
		return "(none)"
	}

	out := make([]string, 0, len(ports))
	for _, p := range ports {
		out = append(out, strconv.Itoa(p))
	}
	return strings.Join(out, ", ")
}

func dateWithAge(ts time.Time) string {
	if ts.IsZero() {
		return "(unknown)"
	}

	days := int(time.Since(ts).Hours() / 24)
	switch {
	case days < 14:
		return ts.Format("2006-01-02") + " (recent)"
	case days < 90:
		return fmt.Sprintf("%s (%d days ago)", ts.Format("2006-01-02"), days)
	default:
		months := max(1, int(math.Round(float64(days)/30.44)))
		return fmt.Sprintf("%s (%d months ago - data may be stale)", ts.Format("2006-01-02"), months)
	}
}
