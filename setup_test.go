package ldap

import (
	"testing"

	"github.com/caddyserver/caddy"
)

// TestSetup tests the various things that should be parsed by setup.
// Make sure you also test for parse errors.
func TestSetup(t *testing.T) {
	tests := []struct {
		body          string
		expectedError bool
	}{
		{`ldap`, true},
		{`ldap :`, true},
		{`ldap {
    ldap_url ldap://example.com
    base_dn ou=ae-dir
    filter (objectClass=aeNwDevice)
    sasl
    attributes {
        fqdn aeFqdn
        ip4 ipHostNumber
    }
}`, false},
	}
	for i, test := range tests {
		c := caddy.NewTestController("dns", test.body)
		if _, err := ParseStanza(c); (err == nil) == test.expectedError {
			t.Fatalf("Unexpected errors in test %d: %v\n%s", i, err, test.body)
		}
	}
}
