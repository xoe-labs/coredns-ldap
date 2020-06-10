package ldap_test

import (
	"context"
	"testing"

	"github.com/coredns/coredns/plugin/file"
	"github.com/coredns/coredns/plugin/pkg/dnstest"
	"github.com/coredns/coredns/plugin/pkg/fall"
	"github.com/coredns/coredns/plugin/test"

	"github.com/miekg/dns"

	. "github.com/xoe-labs/ldap/v0"
)

// nolint: gochecknoglobals
var ldapTestCases = []test.Case{
	{
		// Simple case
		Qname: "a.example.org.", Qtype: dns.TypeA,
		Answer: []dns.RR{
			test.A("a.example.org." + defaultA),
		},
	},
}

// Create a new Ldap Plugin. Use the test.ErrorHandler as the next plugin.
func newTestLdap() *Ldap {
	ldap := New([]string{"example.org.", "www.example.org.", "example.org.", "sample.example.org."})
	ldap.Zones.Z = newTestLdapZones()
	ldap.Fall = fall.Zero
	ldap.Next = test.ErrorHandler()

	return ldap
}

func newTestLdapZones() map[string]*file.Zone {
	Zone := file.NewZone("example.org.", "")
	if err := Zone.Insert(SOA("example.org.")); err != nil {
		panic("omg")
	}

	for _, rr := range []string{
		"example.org. " + defaultA,
		"a.example.org. " + defaultA,
	} {
		r, _ := dns.NewRR(rr)
		if err := Zone.Insert(r); err != nil {
			panic("omg")
		}
	}

	zones := make(map[string]*file.Zone)
	zones["example.org."] = Zone

	return zones
}

func TestServeDNS(t *testing.T) {
	ldap := newTestLdap()

	for i, tc := range ldapTestCases {
		req := tc.Msg()
		rec := dnstest.NewRecorder(&test.ResponseWriter{})

		_, err := ldap.ServeDNS(context.Background(), rec, req)
		if err != nil {
			t.Errorf("Expected no error, got %v", err)
			continue
		}

		resp := rec.Msg
		if resp == nil {
			t.Fatalf("Test %d, got nil message and no error for %q", i, req.Question[0].Name)
		}

		if err := test.SortAndCheck(resp, tc); err != nil {
			t.Error(err)
		}
	}
}

const defaultA = " 3600 IN A 1.2.3.4"
