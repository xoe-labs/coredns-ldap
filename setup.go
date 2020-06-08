package ldap

import (
	"strconv"
	"sync"

	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/plugin/metrics"
	clog "github.com/coredns/coredns/plugin/pkg/log"
	"github.com/coredns/coredns/plugin/pkg/upstream"

	"github.com/caddyserver/caddy"
)

const pluginName = "ldap"

// Define log to be a logger with the plugin name in it.
var log = clog.NewWithPlugin(pluginName)

// init registers this plugin.
func init() { plugin.Register(pluginName, setup) }

// setup is the function that gets called when the config parser see the token "ldap". Setup is responsible
// for parsing any extra options the ldap plugin may have. The first token this function sees is "ldap".
func setup(c *caddy.Controller) error {

	// parse corefile config
	l, err := ldapParse(c)
	if err != nil {
		return plugin.Error(pluginName, err)
	}

	err = l.InitClient()
	if err != nil {
		return plugin.Error(pluginName, err)
	}

	// add prometheus metrics on startup
	c.OnStartup(func() error {
		// add plugin-global metric once
		once.Do(func() {
			metrics.MustRegister(c, requestCount)
		})
		return nil
	})

	// Add the Plugin to CoreDNS, so Servers can use it in their plugin chain.
	dnsserver.GetConfig(c).AddPlugin(func(next plugin.Handler) plugin.Handler {
		l.Next = next
		return l
	})

	return nil
}

var once sync.Once

func ldapParse(c *caddy.Controller) (*Ldap, error) {
	var (
		ldap *Ldap
		err  error
	)

	i := 0
	for c.Next() {
		if i > 0 {
			return nil, plugin.ErrOnce
		}
		i++

		ldap, err = ParseStanza(c)
		if err != nil {
			return ldap, err
		}
	}
	return ldap, nil
}

// ParseStanza parses a ldap stanza
func ParseStanza(c *caddy.Controller) (*Ldap, error) {
	ldap := New([]string{""})
	zones := c.RemainingArgs()

	if len(zones) != 0 {
		ldap.Zones = zones
		for i := 0; i < len(ldap.Zones); i++ {
			ldap.Zones[i] = plugin.Host(ldap.Zones[i]).Normalize()
		}
	} else {
		ldap.Zones = make([]string, len(c.ServerBlockKeys))
		for i := 0; i < len(c.ServerBlockKeys); i++ {
			ldap.Zones[i] = plugin.Host(c.ServerBlockKeys[i]).Normalize()
		}
	}

	ldap.Upstream = upstream.New()

	for c.NextBlock() {
		switch c.Val() {
		// RFC 4516 URL
		case "ldap_url":
			c.NextArg()
			ldap.ldapURL = c.Val()
			continue
		case "paging_limit":
			c.NextArg()
			pagingLimit, err := strconv.Atoi(c.Val())
			if err != nil {
				return nil, c.ArgErr()
			}
			ldap.pagingLimit = pagingLimit
			continue
		case "search_request":
			for c.NextBlock() {
				switch c.Val() {
				case "base_dn":
					c.NextArg() // ou=ae-dir
					ldap.searchRequest.BaseDN = c.Val()
				case "filter":
					c.NextArg() // (objectClass=aeNwDevice)
					ldap.searchRequest.Filter = c.Val()
				case "attributes":
					ldap.searchRequest.Attributes = c.RemainingArgs() // aeFqdn ipHostNumber
				default:
					return nil, c.Errf("unknown search request property '%s'", c.Val())
				}
			}
			continue
		case "username":
			c.NextArg()
			ldap.username = c.Val()
		case "password":
			c.NextArg()
			ldap.password = c.Val()
		case "sasl":
			c.NextArg()
			ldap.sasl = true
		case "fallthrough":
			ldap.Fall.SetZonesFromArgs(c.RemainingArgs())
		default:
			return nil, c.Errf("unknown property '%s'", c.Val())
		}
	}
	// validate non-default ldap values ...
	if ldap.ldapURL == "" || &ldap.ldapURL == nil {
		return nil, c.ArgErr()
	}
	if ldap.searchRequest.BaseDN == "" {
		return nil, c.ArgErr()
	}
	if ldap.searchRequest.Filter == "" {
		return nil, c.ArgErr()
	}
	if len(ldap.searchRequest.Attributes) != 2 {
		return nil, c.ArgErr()
	}
	// if only one of password and username set
	if (&ldap.username == nil) != (&ldap.password == nil) {
		return nil, c.ArgErr()
	}
	// if both username/password and sasl are set
	if &ldap.username != nil && &ldap.sasl != nil {
		return nil, c.ArgErr()
	}
	// if neither username/password nor sasl are set
	if &ldap.username == nil && &ldap.sasl == nil {
		return nil, c.ArgErr()
	}

	return ldap, nil
}
