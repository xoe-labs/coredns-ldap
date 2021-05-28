package ldap

import (
	"fmt"
	"strconv"
	"sync"
	"time"

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
	"github.com/prometheus/client_golang/prometheus"
	clog "github.com/coredns/coredns/plugin/pkg/log"
	"github.com/coredns/coredns/plugin/pkg/upstream"
)

const pluginName = "ldap"

// Define log to be a logger with the plugin name in it.
// nolint: gochecknoglobals
var log = clog.NewWithPlugin(pluginName)

// init registers this plugin.
// nolint: gochecknoinits
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
			prometheus.MustRegister(requestCount)
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

// nolint: gochecknoglobals
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

// ParseStanza parses a ldap stanza.
// nolint: funlen, gocognit, gocyclo
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
			if !c.NextArg() {
				return nil, c.ArgErr()
			}

			ldap.ldapURL = c.Val()
		case "paging_limit":
			if !c.NextArg() {
				return nil, c.ArgErr()
			}

			pagingLimit, err := strconv.ParseUint(c.Val(), 10, 0)
			if err != nil {
				return nil, c.Errf("paging_limit: %w", err)
			}

			ldap.pagingLimit = uint32(pagingLimit)
		case "base_dn":
			if !c.NextArg() {
				return nil, c.ArgErr()
			}

			ldap.SearchRequest.BaseDN = c.Val() // ou=ae-dir
		case "filter":
			if !c.NextArg() {
				return nil, c.ArgErr()
			}

			ldap.SearchRequest.Filter = c.Val() // (objectClass=aeNwDevice)
		case "attributes":
			c.Next()

			for c.NextBlock() {
				switch c.Val() {
				case "fqdn":
					if !c.NextArg() {
						return nil, c.ArgErr()
					}

					ldap.SearchRequest.Attributes = append(ldap.SearchRequest.Attributes, c.Val())
					ldap.FqdnAttr = c.Val() // aeFqdn
				case "ip4":
					if !c.NextArg() {
						return nil, c.ArgErr()
					}

					ldap.SearchRequest.Attributes = append(ldap.SearchRequest.Attributes, c.Val())
					ldap.Ip4Attr = c.Val() // ipHostNumber
				case "ip6":
					if !c.NextArg() {
						return nil, c.ArgErr()
					}

					ldap.SearchRequest.Attributes = append(ldap.SearchRequest.Attributes, c.Val())
					ldap.Ip6Attr = c.Val() // ipHostNumber
				default:
					return nil, c.Errf("unknown attributes property '%s'", c.Val())
				}
			}

			continue
		case "username":
			if !c.NextArg() {
				return nil, c.ArgErr()
			}

			ldap.username = c.Val()
		case "password":
			if !c.NextArg() {
				return nil, c.ArgErr()
			}

			ldap.password = c.Val()
		case "sasl":
			ldap.sasl = true
		case "ttl":
			if !c.NextArg() {
				return nil, c.ArgErr()
			}

			ttl, err := time.ParseDuration(c.Val())
			if err != nil {
				return nil, c.Errf("ttl: %w", err)
			}

			ldap.ttl = ttl
		case "sync_interval":
			if !c.NextArg() {
				return nil, c.ArgErr()
			}

			syncInterval, err := time.ParseDuration(c.Val())
			if err != nil {
				return nil, c.Errf("sync_interval: %w", err)
			}

			ldap.syncInterval = syncInterval
		case "fallthrough":
			ldap.Fall.SetZonesFromArgs(c.RemainingArgs())
		default:
			return nil, c.Errf("unknown property '%s'", c.Val())
		}
	}

	// validate non-default ldap values ...
	if ldap.ldapURL == "" {
		return nil, c.Err("ldap_url cannot be empty")
	}

	if ldap.SearchRequest.BaseDN == "" {
		return nil, c.Err("base_dn cannot be empty")
	}

	if ldap.SearchRequest.Filter == "" {
		return nil, c.Err("filter cannot be empty")
	}

	if ldap.FqdnAttr == "" {
		return nil, c.Err("fqdn attribute cannot be empty")
	}

	if ldap.Ip4Attr == "" {
		return nil, c.Err("ip4 attribute cannot be empty")
	}

	// if only one of password and username set
	if (ldap.username == "") != (ldap.password == "") {
		return nil, c.Err("if not using sasl, both, username and password must be set")
	}

	// if both username/password and sasl are set
	if ldap.username != "" && ldap.sasl {
		fmt.Printf("666 %#v\t%#v", ldap.username, ldap.sasl)
		return nil, c.Err("cannot use sasl and username based authentication at the same time")
	}

	// if neither username/password nor sasl are set
	if ldap.username == "" && !ldap.sasl {
		return nil, c.Err("authenticate either via username/password or sasl")
	}

	return ldap, nil
}
