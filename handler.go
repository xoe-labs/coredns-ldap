package ldap

import (
	"context"

	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/plugin/file"
	"github.com/coredns/coredns/request"

	"github.com/miekg/dns"
)

// ServeDNS implements the plugin.Handler interface.
func (l *Ldap) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	// opt := plugin.Options{}
	state := request.Request{W: w, Req: r}

	var result file.Result

	zone := plugin.Zones(l.Zones.Names).Matches(state.Name())
	if zone == "" {
		return plugin.NextOrFailure(l.Name(), l.Next, ctx, w, r)
	}

	Zone, ok := l.Zones.Z[zone]
	if !ok || Zone == nil {
		return dns.RcodeServerFailure, nil
	}

	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true

	if r.Question[0].Qtype == dns.TypePTR {
		hdr := dns.RR_Header{Name: r.Question[0].Name, Ttl: 3600, Class: dns.ClassINET, Rrtype: dns.TypePTR}

		if ptr, found := l.Ptr[r.Question[0].Name]; found {
			l.zMu.RLock()
			m.Answer = []dns.RR{&dns.PTR{Hdr: hdr, Ptr: ptr}}
			l.zMu.RUnlock()
			result = file.Success
		} else {
			ptr := r.Question[0].Name
			l.zMu.RLock()
			m.Answer = []dns.RR{&dns.PTR{Hdr: hdr, Ptr: ptr}}
			l.zMu.RUnlock()
			result = file.Success
		}
	} else {
		l.zMu.RLock()
		m.Answer, m.Ns, m.Extra, result = Zone.Lookup(ctx, state, state.Name())
		l.zMu.RUnlock()
	}

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

	if err := w.WriteMsg(m); err != nil {
		return dns.RcodeServerFailure, nil
	}

	return dns.RcodeSuccess, nil
}

// Name implements the Handler interface.
func (l *Ldap) Name() string { return "ldap" }
