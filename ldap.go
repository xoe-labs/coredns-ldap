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
	"errors"
	"fmt"
	"net"
	"io"
	"os"

	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/plugin/metrics"
	"github.com/coredns/coredns/plugin/pkg/fall"

	"github.com/miekg/dns"
	"gopkg.in/ldap.v2"
)

// Ldap is an ldap plugin to serve zone entries from a ldap backend.
type Ldap struct {
	Next plugin.Handler
	Fall       fall.F
	Zones      []string
	Client     *ldap.Client

}

var (
	errNoItems        = errors.New("no items found")
	errNsNotExposed   = errors.New("namespace is not exposed")
	errInvalidRequest = errors.New("invalid query name")
)

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