package ldap

import (
	"strconv"
	"sync"
	"time"

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
	zoneNames := c.RemainingArgs()
	if len(zoneNames) != 0 {
		for i := 0; i < len(zoneNames); i++ {
			zoneNames[i] = plugin.Host(zoneNames[i]).Normalize()
		}
	} else {
		zoneNames = make([]string, len(c.ServerBlockKeys))
		for i := 0; i < len(zoneNames); i++ {
			zoneNames[i] = plugin.Host(c.ServerBlockKeys[i]).Normalize()
		}
	}

	ldap := New(zoneNames)
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
			pagingLimit, err := strconv.ParseUint(c.Val(), 10, 0)
			if err != nil {
				return nil, c.ArgErr()
			}
			ldap.pagingLimit = uint32(pagingLimit)
			continue
		case "base_dn":
			c.NextArg() // ou=ae-dir
			ldap.searchRequest.BaseDN = c.Val()
			continue
		case "filter":
			c.NextArg() // (objectClass=aeNwDevice)
			ldap.searchRequest.Filter = c.Val()
			continue
		case "attributes":
			for c.NextBlock() {
				switch c.Val() {
				case "fqdn":
					c.NextArg() // aeFqdn
					ldap.searchRequest.Attributes = append(ldap.searchRequest.Attributes, c.Val())
					ldap.fqdnAttr = c.Val()
					continue
				case "ip4":
					c.NextArg() // ipHostNumber
					ldap.searchRequest.Attributes = append(ldap.searchRequest.Attributes, c.Val())
					ldap.ip4Attr = c.Val()
					continue
				default:
					return nil, c.Errf("unknown attributes property '%s'", c.Val())
				}
			}
			continue
		case "username":
			c.NextArg()
			ldap.username = c.Val()
			continue
		case "password":
			c.NextArg()
			ldap.password = c.Val()
			continue
		case "sasl":
			c.NextArg()
			ldap.sasl = true
			continue
		case "ttl":
			c.NextArg()
			ttl, err := time.ParseDuration(c.Val())
			if err != nil {
				return nil, c.ArgErr()
			}
			ldap.ttl = ttl
			continue
		case "sync_interval":
			c.NextArg()
			syncInterval, err := time.ParseDuration(c.Val())
			if err != nil {
				return nil, c.ArgErr()
			}
			ldap.syncInterval = syncInterval
			continue
		case "fallthrough":
			ldap.Fall.SetZonesFromArgs(c.RemainingArgs())
			continue
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
