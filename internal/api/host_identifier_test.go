package api

import "testing"

// TestValidHostIdentifier exercises the strict IP/CIDR/hostname rule.
func TestValidHostIdentifier(t *testing.T) {
	cases := []struct {
		name       string
		identifier string
		want       bool
	}{
		{"ip", "10.0.0.1", true},
		{"cidr", "10.0.0.0/24", true},
		{"hostname", "dc01.corp.local", true},
		{"ipv6", "fe80::1", true},
		{"rejects space", "web server", false},
		{"rejects url", "https://example.com/a?b=1", false},
		{"rejects empty", "", false},
		{"rejects newline", "10.0.0.1\n10.0.0.2", false},
		{"rejects tab", "a\tb", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := validHostIdentifier(tc.identifier); got != tc.want {
				t.Errorf("validHostIdentifier(%q) = %v, want %v", tc.identifier, got, tc.want)
			}
		})
	}
}
