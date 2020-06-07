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
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"strings"

	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/plugin/etcd/msg"
	"github.com/coredns/coredns/plugin/pkg/fall"
	"github.com/coredns/coredns/request"

	"github.com/miekg/dns"
	"gopkg.in/ldap.v3"
)

// Ldap is an ldap plugin to serve zone entries from a ldap backend.
type Ldap struct {
	Next   plugin.Handler
	Fall   fall.F
	Zones  []string
	Client *ldap.Client
	clientConfig map[string]
}

// New returns an initialized Ldap with defaults.
func New(zones []string) *Ldap {
	k := new(Ldap)
	k.Zones = zones
	return k
}

var (
	errNoItems        = errors.New("no items found")
	errNsNotExposed   = errors.New("namespace is not exposed")
	errInvalidRequest = errors.New("invalid query name")
)

// InitClient initializes a Ldap client.
func (l *Ldap) InitClient() (err error) {
	l.Client, err = ldap.Dial("tcp", fmt.Sprintf("%s:%d", "ldap.example.com", 389))
	if err != nil {
		log.Fatal(err)
	}
	defer l.Client.Close()

	// Reconnect with TLS
	err = l.Client.StartTLS(&tls.Config{InsecureSkipVerify: true})
	if err != nil {
		log.Fatal(err)
	}
}

// Services implements the ServiceBackend interface.
func (l *Ldap) Services(ctx context.Context, state request.Request, exact bool, opt plugin.Options) (services []msg.Service, err error) {
	services, err = l.Records(ctx, state, exact)
	if err != nil {
		return
	}

	services = msg.Group(services)
	return
}

// Reverse implements the ServiceBackend interface.
func (l *Ldap) Reverse(ctx context.Context, state request.Request, exact bool, opt plugin.Options) (services []msg.Service, err error) {
	return l.Services(ctx, state, exact, opt)
}

// Lookup implements the ServiceBackend interface.
func (l *Ldap) Lookup(ctx context.Context, state request.Request, name string, typ uint16) (*dns.Msg, error) {
	return l.Upstream.Lookup(ctx, state, name, typ)
}

// IsNameError implements the ServiceBackend interface.
func (l *Ldap) IsNameError(err error) bool {
	return err == errNoItems || err == errNsNotExposed || err == errInvalidRequest
}

// Records looks up records in ldap. If exact is true, it will lookup just this
// name. This is used when find matches when completing SRV lookups for instance.
func (l *Ldap) Records(ctx context.Context, state request.Request, exact bool) ([]msg.Service, error) {
	name := state.Name()

	path, star := msg.PathWithWildcard(name, l.PathPrefix)
	r, err := l.get(ctx, path, !exact)
	if err != nil {
		return nil, err
	}
	segments := strings.Split(msg.Path(name, l.PathPrefix), "/")
	return l.loopNodes(r.Kvs, segments, star, state.QType())
}
