// Package ldap is a CoreDNS plugin that resolves A, AAAA y PTR RR from a ldap backend.
//
// It serves as a backend connector for autoritative zone data.
// Ldap is often used for bare metal inventories. This use is the main use case
// for this plugin. Other use cases might eventually be supported.
// fqdn and ip4 / ip6 information is mapped from it's repsective ldap schema and
// served as DNS records over coredns. Mapping is configurable. To reduce load
// on the backend, a configurable cache is bundled.
package ldap

import (
	"errors"
	"net"
	"sync"
	"time"

	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/plugin/file"
	"github.com/coredns/coredns/plugin/pkg/fall"
	"github.com/coredns/coredns/plugin/pkg/upstream"

	"github.com/miekg/dns"
	"gopkg.in/ldap.v3"
)

type ldapRecord struct {
	fqdn string
	ip   net.IP
}

func (r *ldapRecord) A() (A *dns.A) {
	return &dns.A{Hdr: dns.RR_Header{Name: r.fqdn, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 0}, A: r.ip}
}

// Ldap is an ldap plugin to serve zone entries from a ldap backend.
type Ldap struct {
	Next     plugin.Handler
	Fall     fall.F
	Upstream *upstream.Upstream
	Client   ldap.Client
	Zones    file.Zones

	searchRequest *ldap.SearchRequest
	ldapURL       string
	pagingLimit   uint32
	syncInterval  time.Duration
	username      string
	password      string
	sasl          bool
	fqdnAttr      string
	ip4Attr       string
	zMu           sync.RWMutex
	ttl           time.Duration
}

// New returns an initialized Ldap with defaults.
func New(zoneNames []string) *Ldap {
	l := new(Ldap)
	l.Zones.Names = zoneNames
	l.pagingLimit = 0
	// SearchRequest defaults
	l.searchRequest = new(ldap.SearchRequest)
	l.searchRequest.DerefAliases = ldap.NeverDerefAliases // TODO: Reason
	l.searchRequest.Scope = ldap.ScopeWholeSubtree        // search whole subtree
	l.searchRequest.SizeLimit = 500                       // TODO: Reason
	l.searchRequest.TimeLimit = 500                       // TODO: Reason
	l.searchRequest.TypesOnly = false                     // TODO: Reason
	return l
}

var (
	errNoItems        = errors.New("no items found")
	errNsNotExposed   = errors.New("namespace is not exposed")
	errInvalidRequest = errors.New("invalid query name")
)

// InitClient initializes a Ldap client.
func (l *Ldap) InitClient() (err error) {
	l.Client, err = ldap.DialURL(l.ldapURL)
	if err != nil {
		log.Fatal(err)
		return err
	}
	defer l.Client.Close()
	return nil
}


// SOA returns a syntetic SOA record for a zone.
func SOA(zone string) (dns.RR) {
	ttl := uint32(300)
	header := dns.RR_Header{Name: zone, Rrtype: dns.TypeSOA, Ttl: ttl, Class: dns.ClassINET}

	Mbox := hostmaster + "."
	Ns := "ns.dns."
	if zone[0] != '.' {
		Mbox += zone
		Ns += zone
	}

	return &dns.SOA{Hdr: header,
		Mbox:    Mbox,
		Ns:      Ns,
		Serial:  12345,
		Refresh: 7200,
		Retry:   1800,
		Expire:  86400,
		Minttl:  ttl,
	}
}
const hostmaster = "hostmaster"
