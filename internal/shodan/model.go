package shodan

import "time"

type ServiceRecord struct {
	Port      int
	Transport string // "tcp" or "udp"
	Module    string // e.g. "dns-udp", "ssh"
	Product   string // e.g. "OpenSSH"
	Version   string
	Banner    string // raw banner; empty when minify=true
	CPE       []string
}

type ShodanHostResult struct {
	IP              string
	Organization    string
	ISP             string
	ASN             string
	Country         string
	City            string
	OS              string // OS fingerprint; empty string if not detected
	Ports           []int
	Hostnames       []string
	Tags            []string
	Vulnerabilities []string // CVE IDs, e.g. "CVE-2021-44228"; sorted
	Services        []ServiceRecord
	LastSeen        time.Time
}
