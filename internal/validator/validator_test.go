package validator

import "testing"

func TestValidateIP(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{name: "public ipv4 google", input: "8.8.8.8", wantErr: false},
		{name: "public ipv4 cloudflare", input: "1.1.1.1", wantErr: false},
		{name: "public ipv6 google", input: "2001:4860:4860::8888", wantErr: false},
		{name: "ipv6 documentation prefix rfc3849", input: "2001:db8::1", wantErr: true},
		{name: "loopback ipv4", input: "127.0.0.1", wantErr: true},
		{name: "loopback ipv6", input: "::1", wantErr: true},
		{name: "private 10/8", input: "10.0.0.1", wantErr: true},
		{name: "private 172.16/12 start", input: "172.16.0.1", wantErr: true},
		{name: "private 172.16/12 end", input: "172.31.255.255", wantErr: true},
		{name: "private 192.168/16", input: "192.168.1.1", wantErr: true},
		{name: "multicast", input: "224.0.0.1", wantErr: true},
		{name: "unspecified ipv4", input: "0.0.0.0", wantErr: true},
		{name: "unspecified ipv6", input: "::", wantErr: true},
		{name: "link local ipv4", input: "169.254.1.1", wantErr: true},
		{name: "link local ipv6", input: "fe80::1", wantErr: true},
		{name: "cgnat start", input: "100.64.0.1", wantErr: true},
		{name: "cgnat end", input: "100.127.255.255", wantErr: true},
		{name: "test net 1", input: "192.0.2.1", wantErr: true},
		{name: "test net 2", input: "198.51.100.1", wantErr: true},
		{name: "test net 3", input: "203.0.113.1", wantErr: true},
		{name: "reserved 240/4", input: "240.0.0.1", wantErr: true},
		{name: "empty string", input: "", wantErr: true},
		{name: "not an ip", input: "not-an-ip", wantErr: true},
		{name: "domain", input: "google.com", wantErr: true},
		{name: "ipv4 mapped private", input: "::ffff:192.168.1.1", wantErr: true},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := ValidateIP(tt.input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ValidateIP(%q) error = %v, wantErr=%v", tt.input, err, tt.wantErr)
			}
		})
	}
}
