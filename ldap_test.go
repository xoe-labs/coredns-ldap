package ldap

import (
	"bytes"
	"context"
	"testing"

	"github.com/coredns/coredns/plugin/pkg/dnstest"
	"github.com/coredns/coredns/plugin/test"

	"github.com/miekg/dns"
)

func TestLdap(t *testing.T) {
	// Create a new Ldap Plugin. Use the test.ErrorHandler as the next plugin.
	x := Ldap{Next: test.ErrorHandler()}

	// Setup a new output buffer that is *not* standard output, so we can check if
	// ldap is really being printed.
	b := &bytes.Buffer{}
	out = b

	ctx := context.TODO()
	r := new(dns.Msg)
	r.SetQuestion("ldap.org.", dns.TypeA)
	// Create a new Recorder that captures the result, this isn't actually used in this test
	// as it just serves as something that implements the dns.ResponseWriter interface.
	rec := dnstest.NewRecorder(&test.ResponseWriter{})

	// Call our plugin directly, and check the result.
	x.ServeDNS(ctx, rec, r)
	if a := b.String(); a != "ldap\n" {
		t.Errorf("Failed to print '%s', got %s", ldap, a)
	}
}
