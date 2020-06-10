package ldap

import (
	"context"

	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/plugin/file"
	"github.com/coredns/coredns/request"

	"github.com/miekg/dns"
)

// ServeDNS implements the plugin.Handler interface.
func (l Ldap) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	// opt := plugin.Options{}
	state := request.Request{W: w, Req: r}

	zone := plugin.Zones(l.Zones.Names).Matches(state.Name())
	if zone == "" {
		return plugin.NextOrFailure(l.Name(), l.Next, ctx, w, r)
	}
	Zone, ok := l.Zones.Z[zone]
	if !ok || Zone == nil {
		return dns.RcodeServerFailure, nil
	}
	var result file.Result
	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true
	l.zMu.RLock()
	m.Answer, m.Ns, m.Extra, result = Zone.Lookup(ctx, state, state.Name())
	l.zMu.RUnlock()

	if len(m.Answer) == 0 && result != file.NoData && l.Fall.Through(state.Name()) {
		return plugin.NextOrFailure(l.Name(), l.Next, ctx, w, r)
	}

	switch result {
	case file.Success:
	case file.NoData:
	case file.NameError:
		m.Rcode = dns.RcodeNameError
	case file.Delegation:
		m.Authoritative = false
	case file.ServerFailure:
		return dns.RcodeServerFailure, nil
	}
	w.WriteMsg(m)
	return dns.RcodeSuccess, nil
}

// Name implements the Handler interface.
func (l Ldap) Name() string { return "ldap" }

