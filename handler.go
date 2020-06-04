package ldap

import (
	"context"

	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/request"

	"github.com/miekg/dns"
)

// ServeDNS implements the plugin.Handler interface.
func (l Ldap) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	opt := plugin.Options{}
	state := request.Request{W: w, Req: r}

	zone := plugin.Zones(l.Zones).Matches(state.Name())
	if zone == "" {
		return plugin.NextOrFailure(l.Name(), l.Next, ctx, w, r)
	}
	var (
		records []dns.RR
		extra   []dns.RR
		err     error
	)

	switch state.QType() {
	case dns.TypeA:
		records, err = plugin.A(ctx, l, zone, state, nil, opt)
	case dns.TypeAAAA:
		records, err = plugin.AAAA(ctx, l, zone, state, nil, opt)
	case dns.TypeTXT:
		records, err = plugin.TXT(ctx, l, zone, state, nil, opt)
	case dns.TypeCNAME:
		records, err = plugin.CNAME(ctx, l, zone, state, opt)
	case dns.TypePTR:
		records, err = plugin.PTR(ctx, l, zone, state, opt)
	case dns.TypeMX:
		records, extra, err = plugin.MX(ctx, l, zone, state, opt)
	case dns.TypeSRV:
		records, extra, err = plugin.SRV(ctx, l, zone, state, opt)
	case dns.TypeSOA:
		records, err = plugin.SOA(ctx, l, zone, state, opt)
	case dns.TypeNS:
		if state.Name() == zone {
			records, extra, err = plugin.NS(ctx, l, zone, state, opt)
			break
		}
		fallthrough
	default:
		// Do a fake A lookup, so we can distinguish between NODATA and NXDOMAIN
		_, err = plugin.A(ctx, l, zone, state, nil, opt)
	}

	if l.IsNameError(err) {
		if l.Fall.Through(state.Name()) {
			return plugin.NextOrFailure(l.Name(), l.Next, ctx, w, r)
		}
		// Make err nil when returning here, so we don't log spam for NXDOMAIN.
		return plugin.BackendError(ctx, &l, zone, dns.RcodeNameError, state, nil /* err */, opt)

	}
	if err != nil {
		return plugin.BackendError(ctx, &l, zone, dns.RcodeServerFailure, state, err, opt)
	}

	if len(records) == 0 {
		return plugin.BackendError(ctx, &l, zone, dns.RcodeSuccess, state, err, opt)
	}

	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true
	m.Answer = append(m.Answer, records...)
	m.Extra = append(m.Extra, extra...)

	w.WriteMsg(m)
	return dns.RcodeSuccess, nil
}

// Name implements the Handler interface.
func (l Ldap) Name() string { return "ldap" }
