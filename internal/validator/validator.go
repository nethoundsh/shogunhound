package validator

import (
	"fmt"
	"net"
)

var rejectedCIDRs []*net.IPNet

func init() {
	cidrs := []string{
		"100.64.0.0/10",   // CGNAT RFC 6598
		"192.0.2.0/24",    // TEST-NET-1 RFC 5737
		"198.51.100.0/24", // TEST-NET-2 RFC 5737
		"203.0.113.0/24",  // TEST-NET-3 RFC 5737
		"2001:db8::/32",   // Documentation prefix RFC 3849
		"240.0.0.0/4",     // Reserved RFC 1112
	}

	rejectedCIDRs = make([]*net.IPNet, 0, len(cidrs))
	for _, cidr := range cidrs {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			// CIDRs are compile-time constants. A parse failure is a programming
			// error, not a runtime condition, so panic is appropriate.
			panic(fmt.Sprintf("failed to parse CIDR %q: %v", cidr, err))
		}
		rejectedCIDRs = append(rejectedCIDRs, network)
	}
}

func ValidateIP(ip string) error {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return fmt.Errorf("invalid IP address: %s", ip)
	}

	if ipv4 := parsed.To4(); ipv4 != nil {
		parsed = ipv4
	}

	if parsed.IsLoopback() {
		return nonPublicError(ip)
	}

	if parsed.IsPrivate() {
		return nonPublicError(ip)
	}

	if parsed.IsMulticast() {
		return nonPublicError(ip)
	}

	if parsed.IsUnspecified() {
		return nonPublicError(ip)
	}

	if parsed.IsLinkLocalUnicast() {
		return nonPublicError(ip)
	}

	for _, network := range rejectedCIDRs {
		if network.Contains(parsed) {
			return nonPublicError(ip)
		}
	}

	return nil
}

func nonPublicError(ip string) error {
	return fmt.Errorf("IP %s is not a public address and cannot be queried", ip)
}
